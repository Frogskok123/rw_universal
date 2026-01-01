#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/input.h> // <--- ВАЖНО ДЛЯ INPUT
#include <linux/slab.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
#include "breakpoint.h"

// Глобальные переменные
struct task_struct *task = NULL; 
struct task_struct *hide_pid_process_task = NULL;
int hide_process_pid = 0;
int hide_process_state = 0;

// ==========================================================
//                VIRTUAL MOUSE IMPLEMENTATION
// ==========================================================

static struct input_dev *vmouse_dev = NULL;

// Инициализация виртуальной мыши
int init_virtual_mouse(void) {
    int error;

    // Выделяем память под устройство ввода
    vmouse_dev = input_allocate_device();
    if (!vmouse_dev) {
        printk(KERN_ERR "JiangNight: Failed to allocate mouse device");
        return -ENOMEM;
    }

    // Настраиваем имя и ID (притворяемся обычной USB мышью)
    vmouse_dev->name = "Virtual Input Mouse"; 
    vmouse_dev->phys = "virtual/input/mouse";
    vmouse_dev->id.bustype = BUS_USB;
    vmouse_dev->id.vendor  = 0x1234;
    vmouse_dev->id.product = 0x5678;
    vmouse_dev->id.version = 0x0100;

    // 1. Включаем поддержку ОТНОСИТЕЛЬНЫХ координат (Мышь)
    set_bit(EV_REL, vmouse_dev->evbit);
    set_bit(REL_X, vmouse_dev->relbit);
    set_bit(REL_Y, vmouse_dev->relbit);
    
    // 2. Включаем кнопки (Левая/Правая), чтобы Android признал устройство мышью
    set_bit(EV_KEY, vmouse_dev->evbit);
    set_bit(BTN_LEFT, vmouse_dev->keybit);
    set_bit(BTN_RIGHT, vmouse_dev->keybit);

    // Регистрируем в системе
    error = input_register_device(vmouse_dev);
    if (error) {
        printk(KERN_ERR "JiangNight: Failed to register mouse device");
        input_free_device(vmouse_dev);
        return error;
    }

    printk(KERN_INFO "JiangNight: Virtual Mouse Registered!");
    return 0;
}

// Функция движения (вызывается из IOCTL)
void kernel_mouse_move(int x, int y) {
    if (!vmouse_dev) return;

    // Отправляем относительное смещение
    // REL_X - движение по горизонтали
    // REL_Y - движение по вертикали
    input_report_rel(vmouse_dev, REL_X, x);
    input_report_rel(vmouse_dev, REL_Y, y);
    
    // Синхронизация (применить изменения)
    input_sync(vmouse_dev);
}

void cleanup_virtual_mouse(void) {
    if (vmouse_dev) {
        input_unregister_device(vmouse_dev); // Это также освобождает память vmouse_dev
        vmouse_dev = NULL;
    }
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

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    
    // Используем ту же структуру GyroData, чтобы не менять User Space
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
            
        case OP_GYRO_MOVE: // Используем тот же код операции
            if (copy_from_user(&data, (void __user *)arg, sizeof(data))) return -EFAULT;
            
            // Передаем данные в функцию мыши
            kernel_mouse_move(data.x, data.y);
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
    
    // resolve_kernel_symbols(); // Не нужно для мыши, это стандартный Input API

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
    
    // Инициализация мыши
    if (init_virtual_mouse() != 0) {
        printk(KERN_ERR "JiangNight: Failed to init mouse!");
        // Не выходим с ошибкой, чтобы хотя бы чтение памяти работало
    }

    printk(KERN_INFO "JiangNight: Driver Loaded.");
    return 0;
}

static void __exit driver_unload(void) {
    cleanup_virtual_mouse();
    
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
