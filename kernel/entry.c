#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h> 
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/file.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
#include "breakpoint.h"

// ==========================================================
//              COMPATIBILITY & HELPERS
// ==========================================================

// Принудительное объявление для старых ядер, где нет хедера
extern long probe_kernel_read(void *dst, const void *src, size_t size);

// Глобальные переменные (для совместимости с memory.c)
struct task_struct *task = NULL; 
struct task_struct *hide_pid_process_task = NULL;
int hide_process_pid = 0;
int hide_process_state = 0;

// ==========================================================
//              SNIFFER IMPLEMENTATION (VFS_READ)
// ==========================================================

struct read_ctx {
    struct file *file;
    char __user *buf;
    size_t count;
    char filename[64]; // Буфер для имени файла
};

static struct kretprobe sniffer_kretprobe;

// 1. ВХОД: Запоминаем параметры вызова vfs_read
static int sniffer_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_ctx *ctx = (struct read_ctx *)ri->data;
    
    // Аргументы vfs_read: X0=file, X1=buf, X2=count
    struct file *f = (struct file *)regs->regs[0];
    char *path_ptr;
    char tmp_path[128];

    // Опционально: фильтр по PID (раскомментировать, если спамит от системы)
    // if (current->tgid < 1000) return 1; 

    // Получаем имя файла из структуры file
    if (f && f->f_path.dentry) {
        path_ptr = d_path(&f->f_path, tmp_path, 128);
        if (!IS_ERR(path_ptr)) {
            // ФИЛЬТР: Ловим только файлы, похожие на сенсоры
            if (strstr(path_ptr, "event") || strstr(path_ptr, "iio") || strstr(path_ptr, "sensor")) {
                
                // Сохраняем данные для обработчика выхода
                strncpy(ctx->filename, path_ptr, 63);
                ctx->file = f;
                ctx->buf = (char __user *)regs->regs[1];
                ctx->count = (size_t)regs->regs[2];
                return 0; // Идем в sniffer_ret
            }
        }
    }
    return 1; // Пропускаем (не наш файл)
}

// 2. ВЫХОД: Читаем данные, которые ядро вернуло игре
static int sniffer_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_ctx *ctx = (struct read_ctx *)ri->data;
    ssize_t ret_len = regs_return_value(regs);
    
    char kbuf[32]; // Читаем первые 32 байта
    short *sdata;
    
    // Если данных мало, это не сенсор
    if (ret_len < 12) return 0;

    // Безопасное чтение памяти пользователя (без падения ядра)
    pagefault_disable();
    if (probe_kernel_read(kbuf, ctx->buf, 32) == 0) {
        sdata = (short*)kbuf;
        
        // ВЫВОД В DMESG
        // Формат: [Имя файла] [Длина] [Данные: short1 short2 short3 ...]
        // short1..3 - это обычно X, Y, Z
        printk(KERN_INFO "GYRO_SNIFF: File=[%s] Len=%ld Data: %d %d %d %d %d %d", 
               ctx->filename, ret_len, 
               sdata[0], sdata[1], sdata[2], 
               sdata[3], sdata[4], sdata[5]);
    }
    pagefault_enable();
    return 0;
}

int init_sniffer(void) {
    sniffer_kretprobe.kp.symbol_name = "vfs_read";
    sniffer_kretprobe.handler = sniffer_ret;
    sniffer_kretprobe.entry_handler = sniffer_entry;
    sniffer_kretprobe.data_size = sizeof(struct read_ctx);
    sniffer_kretprobe.maxactive = 64; // Больше очередь, чтобы не пропускать пакеты

    if (register_kretprobe(&sniffer_kretprobe) < 0) {
        printk(KERN_ERR "JiangNight: Failed to hook vfs_read");
        return -1;
    }
    printk(KERN_INFO "JiangNight: Sniffer Loaded. Watch dmesg!");
    return 0;
}

// ==========================================================
//                   DRIVER OPS (STANDARD)
// ==========================================================

static struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
} memdev;

static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

// Пустышка для IOCTL (аим выключен в режиме сниффера)
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    int ret = 0;

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) ret = -EFAULT;
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) ret = -EFAULT;
            break;

        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) ||
                copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) return -EFAULT;
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) return -EFAULT;
            break;
            
        case OP_GYRO_MOVE:
            // В режиме сниффера игнорируем команды аима
            break;

        default:
            ret = -EINVAL;
            break;
    }
    return ret;
}

int dispatch_open(struct inode *node, struct file *file) {
    file->private_data = &memdev;
    task = current; 
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    return 0;
}

struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static int __init driver_entry(void) {
    int ret;
    
    printk(KERN_INFO "JiangNight: Sniffer Initializing...");
    devicename = "mem_driver"; 

    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
    if (ret < 0) return ret;

    cdev_init(&memdev.cdev, &dispatch_functions);
    memdev.cdev.owner = THIS_MODULE;
    ret = cdev_add(&memdev.cdev, mem_tool_dev_t, 1);
    if (ret) {
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return ret;
    }

    mem_tool_class = class_create(THIS_MODULE, devicename);
    if (IS_ERR(mem_tool_class)) {
        cdev_del(&memdev.cdev);
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return PTR_ERR(mem_tool_class);
    }

    memdev.dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, devicename);
    if (IS_ERR(memdev.dev)) {
        class_destroy(mem_tool_class);
        cdev_del(&memdev.cdev);
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return PTR_ERR(memdev.dev);
    }
    
    // Запуск сниффера
    init_sniffer(); 

    return 0;
}

static void __exit driver_unload(void) {
    unregister_kretprobe(&sniffer_kretprobe);
    
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
    printk(KERN_INFO "JiangNight: Sniffer Unloaded.");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");
