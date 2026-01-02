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

// Подключаем ваши заголовки (убедитесь, что файлы лежат рядом)
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
#include "breakpoint.h"

// ==========================================================
//              MACROS & COMPATIBILITY (KERNEL 4.14 - 6.x)
// ==========================================================
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    #define probe_read(dst, src, size) copy_from_user_nofault(dst, src, size)
    #define probe_write(dst, src, size) copy_to_user_nofault(dst, src, size)
#else
    #define probe_read(dst, src, size) probe_kernel_read(dst, src, size)
    #define probe_write(dst, src, size) probe_kernel_write(dst, src, size)
#endif

// Глобальные переменные
struct task_struct *task = NULL; 
struct task_struct *hide_pid_process_task = NULL;
int hide_process_pid = 0;
int hide_process_state = 0;

// Переменные Аимбота
static int g_aim_x = 0;
static int g_aim_y = 0;
static int g_target_pid = 0; 

// ==========================================================
//              GYRO HOOK IMPLEMENTATION (PARADISE STYLE)
// ==========================================================

// Контекст для передачи адреса буфера от входа к выходу функции
struct gyro_context {
    char __user *user_buffer;
    size_t count;
};

static struct kretprobe gyro_kretprobe;

// 1. ВХОД: Запоминаем, куда игра просит положить данные
static int gyro_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gyro_context *ctx = (struct gyro_context *)ri->data;

    // Авто-захват PID: Если мы еще не знаем PID игры, и это не системный процесс
    if (g_target_pid == 0 && current->tgid > 1000) {
        // Можно раскомментировать для авто-детекта:
        // g_target_pid = current->tgid; 
    }

    // Если фильтр включен, игнорируем чужие процессы
    if (g_target_pid > 0 && current->tgid != g_target_pid) {
        return 1; // Пропустить (не наше приложение)
    }

    // ARM64 Calling Convention:
    // X0 = struct iio_buffer *
    // X1 = size_t count (или буфер, зависит от ядра)
    // В iio_buffer_read_outer(file, buf, count, ppos):
    // X1 = user_buf
    // X2 = count
    
    ctx->user_buffer = (char __user *)regs->regs[1]; // Аргумент 2: User Buffer
    ctx->count = (size_t)regs->regs[2];              // Аргумент 3: Count

    return 0;
}

// 2. ВЫХОД: Функция отработала, буфер полон. Меняем данные.
static int gyro_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gyro_context *ctx = (struct gyro_context *)ri->data;
    ssize_t ret_len = regs_return_value(regs); 
    
    // Объявления в начале (C90)
    char kbuf[128]; 
    short *sensors;
    size_t bytes_to_copy;

    // Если аим выключен или ошибка чтения - ничего не делаем
    if (g_aim_x == 0 && g_aim_y == 0) return 0;
    
    // Проверка валидности
    if (ret_len < 12) return 0; // Меньше 12 байт не может быть гироскопом (X,Y,Z по 2 байта + timestamp)

    // Защита от переполнения стека
    bytes_to_copy = (ret_len > 128) ? 128 : ret_len;

    // Читаем данные из User Space в Kernel Space
    if (probe_read(kbuf, ctx->user_buffer, bytes_to_copy) == 0) {
        
        sensors = (short*)kbuf;
        
        // --- ВНЕДРЕНИЕ АИМА ---
        // Стратегия "Дробовик": Пишем в обе вероятные позиции.
        // [0],[1] - Если читается только Гироскоп
        // [3],[4] - Если читается Акселерометр + Гироскоп
        
        sensors[0] += (short)g_aim_x;
        sensors[1] += (short)g_aim_y;
        
        // Проверка длины, чтобы не записать за границы
        if (bytes_to_copy >= 12) {
             sensors[3] += (short)g_aim_x;
             sensors[4] += (short)g_aim_y;
        }
        
        // Записываем измененные данные обратно игре
        probe_write(ctx->user_buffer, kbuf, bytes_to_copy);
        
        // Сбрас координат (один тик отработан)
        g_aim_x = 0;
        g_aim_y = 0;
    }

    return 0;
}

// Инициализация хука
int init_gyro_hook(void) {
    int ret;
    
    // Основная цель: iio_buffer_read_outer
    gyro_kretprobe.kp.symbol_name = "iio_buffer_read_outer";
    gyro_kretprobe.handler = gyro_ret_handler;      
    gyro_kretprobe.entry_handler = gyro_entry_handler; 
    gyro_kretprobe.data_size = sizeof(struct gyro_context);
    gyro_kretprobe.maxactive = 32;

    ret = register_kretprobe(&gyro_kretprobe);
    if (ret < 0) {
        printk(KERN_ERR "JiangNight: iio_buffer_read_outer failed (%d), trying fallback...", ret);
        
        // Запасная цель: iio_buffer_read
        gyro_kretprobe.kp.symbol_name = "iio_buffer_read"; 
        ret = register_kretprobe(&gyro_kretprobe);
        if (ret < 0) {
             printk(KERN_ERR "JiangNight: Fatal - All gyro hooks failed.");
             return ret;
        }
    }
    
    printk(KERN_INFO "JiangNight: Gyro Hook Installed at %s", gyro_kretprobe.kp.symbol_name);
    return 0;
}

// ==========================================================
//                   DEVICE DRIVER PART
// ==========================================================

static struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
} memdev;

static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

// Функция для обновления координат из IOCTL
void kernel_gyro_move(int x, int y) {
    g_aim_x = x;
    g_aim_y = y;
    
    // Если PID еще не захвачен, берем PID текущего процесса (чита)
    // В идеале PID игры нужно передавать отдельно через ioctl,
    // но обычно это работает, если чит инжектится или форкает процесс.
    if (g_target_pid == 0) {
        // g_target_pid = current->tgid; // Раскомментировать если нужно
    }
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    
    // Структура данных для аима
    struct GyroData {
        int x;
        int y;
    } data;
    
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
            if (copy_from_user(&data, (void __user *)arg, sizeof(data))) return -EFAULT;
            kernel_gyro_move(data.x, data.y);
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
    
    // resolve_kernel_symbols(); // Если используется в memory.c

    printk(KERN_INFO "JiangNight: Driver Initializing...");
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
    
    // Установка хука
    init_gyro_hook(); 

    printk(KERN_INFO "JiangNight: Driver Loaded Successfully.");
    return 0;
}

static void __exit driver_unload(void) {
    // Снимаем хук ПЕРЕД удалением устройства
    unregister_kretprobe(&gyro_kretprobe);
    
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
    printk(KERN_INFO "JiangNight: Driver Unloaded.");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");
