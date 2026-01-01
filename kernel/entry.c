
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

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
#include "breakpoint.h"

// ================= БЛОК СОВМЕСТИМОСТИ (ВАЖНО!) =================
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
    #define copy_from_user_nofault(dst, src, size) probe_kernel_read(dst, src, size)
    #define copy_to_user_nofault(dst, src, size)   probe_kernel_write(dst, src, size)
#else
    #ifndef copy_from_user_nofault
        #define copy_from_user_nofault(dst, src, size) __copy_from_user_inatomic(dst, src, size)
        #define copy_to_user_nofault(dst, src, size)   __copy_to_user_inatomic(dst, src, size)
    #endif
#endif
// ===============================================================

// Глобальные переменные
struct task_struct *task = NULL; 
struct task_struct *hide_pid_process_task = NULL;
int hide_process_pid = 0;
int hide_process_state = 0;

// Аимбот переменные
static int g_aim_x = 0;
static int g_aim_y = 0;
static int g_target_pid = 0; 

// ==========================================================
//                   KPROBES GYRO IMPLEMENTATION
// ==========================================================

struct gyro_data {
    char __user *user_buf; 
};

static struct kretprobe gyro_kretprobe;

static int gyro_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gyro_data *data;

    // ВРЕМЕННО ОТКЛЮЧЕНО ДЛЯ ТЕСТА (Чтобы работало всегда)
    // if (g_target_pid > 0 && current->tgid != g_target_pid) {
    //    return 1; 
    // }

    data = (struct gyro_data *)ri->data;
    // ARM64: X1 = 2-й аргумент функции (буфер)
    data->user_buf = (char __user *)regs->regs[1];

    return 0;
}

static int gyro_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gyro_data *data = (struct gyro_data *)ri->data;
    ssize_t ret_len = regs_return_value(regs); 
    
    // ОБЪЯВЛЕНИЯ ПЕРЕМЕННЫХ В НАЧАЛЕ БЛОКА (C90 Style)
    char kbuf[64];
    size_t copy_size;
    short *sensor_data;
    
    // ОТЛАДКА: Если аим активен, пишем в лог
    if (g_aim_x != 0 || g_aim_y != 0) {
        printk(KERN_INFO "JiangNight: Gyro Move Request! X=%d Y=%d (RetLen=%ld)", g_aim_x, g_aim_y, ret_len);
    }

    if (ret_len >= 12 && (g_aim_x != 0 || g_aim_y != 0)) {
        
        copy_size = (ret_len > 64) ? 64 : ret_len;

        if (copy_from_user_nofault(kbuf, data->user_buf, copy_size) == 0) {
            
            sensor_data = (short*)kbuf;
            
            // --- ЛОГИКА СМЕЩЕНИЯ ---
            // Выбрали индексы [2] и [3] (по вашей просьбе)
            // Но лучше писать и в [0][1], если не уверены
            
            sensor_data[0] += (short)g_aim_x; // Пробуем все каналы для надежности
            sensor_data[1] += (short)g_aim_y;
            
            sensor_data[2] += (short)g_aim_x;
            sensor_data[3] += (short)g_aim_y;

            sensor_data[4] += (short)g_aim_x;
            sensor_data[5] += (short)g_aim_y;
            
            printk(KERN_INFO "JiangNight: WRITING TO MEMORY!");
            
            copy_to_user_nofault(data->user_buf, kbuf, copy_size);
            
            g_aim_x = 0;
            g_aim_y = 0;
        } else {
             printk(KERN_ERR "JiangNight: Failed to read user memory!");
        }
    }
    return 0;
}

int init_gyro_hook(void) {
    int ret; 

    // Используем найденное имя
    gyro_kretprobe.kp.symbol_name = "iio_buffer_read_outer";
    
    gyro_kretprobe.handler = gyro_ret_handler;      
    gyro_kretprobe.entry_handler = gyro_entry_handler; 
    gyro_kretprobe.data_size = sizeof(struct gyro_data);
    gyro_kretprobe.maxactive = 20;

    ret = register_kretprobe(&gyro_kretprobe);
    if (ret < 0) {
        printk(KERN_ERR "JiangNight: iio_buffer_read_outer failed, trying backup...");
        gyro_kretprobe.kp.symbol_name = "iio_buffer_read"; 
        ret = register_kretprobe(&gyro_kretprobe);
        if (ret < 0) {
             printk(KERN_ERR "JiangNight: Fatal - Gyro hook failed completely.");
             return ret;
        }
    }
    
    printk(KERN_INFO "JiangNight: Gyro Hook Installed at: %p", gyro_kretprobe.kp.addr);
    return 0;
}

// ==========================================================
//                   DEVICE DRIVER PART
// ==========================================================

static struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
} memdev;

static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

void kernel_gyro_move(int x, int y) {
    g_aim_x = x;
    g_aim_y = y;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    struct GyroData data; 
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
            
            // Захват PID текущего процесса при первом вызове аима
            if (g_target_pid == 0) {
                 g_target_pid = current->tgid;
            }
            
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
    g_target_pid = current->tgid;
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    g_target_pid = 0;
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
    
    resolve_kernel_symbols(); 

    printk(KERN_INFO "JiangNight: Debug System Initialized.");
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
    
    init_gyro_hook(); 

    printk(KERN_INFO "JiangNight: Driver Loaded.");
    return 0;
}

static void __exit driver_unload(void) {
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
