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

// Глобальные переменные
struct task_struct *task = NULL; 
struct task_struct *hide_pid_process_task = NULL;
int hide_process_pid = 0;
int hide_process_state = 0;

// Аимбот переменные
static int g_aim_x = 0;
static int g_aim_y = 0;
static int g_target_pid = 0; // PID игры, чтобы не ломать гироскоп другим приложениям

// ==========================================================
//                   KPROBES GYRO IMPLEMENTATION
// ==========================================================

// Структура для хранения данных между входом и выходом функции
struct gyro_data {
    char __user *user_buf; // Адрес буфера в User Space
};

static struct kretprobe gyro_kretprobe;

// Эта функция вызывается ПРИ ВХОДЕ в iio_buffer_read
// Мы должны сохранить указатель на user_buf, так как при выходе он может быть недоступен в регистрах
static int gyro_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gyro_data *data;

    // Проверяем, что это наша игра (по PID)
    if (g_target_pid > 0 && current->tgid != g_target_pid) {
        return 1; // Пропускаем хук для других процессов
    }

    data = (struct gyro_data *)ri->data;

    // ВНИМАНИЕ: Зависит от архитектуры (ARM64)
    // Аргумент 1 (struct file *) -> X0
    // Аргумент 2 (char __user *buf) -> X1  <-- Нам нужен этот
    // Аргумент 3 (size_t count) -> X2
    data->user_buf = (char __user *)regs->regs[1];

    return 0;
}

// Эта функция вызывается ПРИ ВЫХОДЕ из iio_buffer_read
// Данные уже записаны в user_buf.
static int gyro_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gyro_data *data = (struct gyro_data *)ri->data;
    ssize_t ret_len = regs_return_value(regs); // Получаем возвращаемое значение (кол-во байт)

    // Если чтение успешно и аим активен
    if (ret_len >= 12 && (g_aim_x != 0 || g_aim_y != 0)) {
        char kbuf[64];
        size_t copy_size = (ret_len > 64) ? 64 : ret_len;

        // ВАЖНО: Мы находимся в atomic context (прерывания выключены).
        // copy_from_user / copy_to_user могут вызвать page fault и панику.
        // Но так как мы только что вернулись из функции чтения, страницы памяти 
        // скорее всего находятся в TLB (горячие), и это может сработать.
        // Для 100% надежности нужен task_work_add, но попробуем "грязный" метод, который часто работает в читах.
        
        // Используем probe_kernel_read / write (новые ядра: copy_from_kernel_nofault)
        // Но нам нужен доступ к USER памяти.
        
        if (copy_from_user_nofault(kbuf, data->user_buf, copy_size) == 0) {
            
            // Интерпретируем данные как массив short (int16)
            short *sensor_data = (short*)kbuf;
            
            // --- ЛОГИКА СМЕЩЕНИЯ ---
            // Экспериментально! Обычно [0]=X, [1]=Y или [3]=X, [4]=Y
            // Для теста меняем первые два канала
            sensor_data[0] += (short)g_aim_x;
            sensor_data[1] += (short)g_aim_y;
            
            // Пишем обратно
            copy_to_user_nofault(data->user_buf, kbuf, copy_size);
            
            // Сброс (применили 1 раз)
            g_aim_x = 0;
            g_aim_y = 0;
        }
    }
    return 0;
}

int init_gyro_hook(void) {
    // 1. Ищем функцию. Самая популярная для сенсоров:
    gyro_kretprobe.kp.symbol_name = "iio_buffer_read_first_n_outer";
    
    // 2. Настраиваем обработчики
    gyro_kretprobe.handler = gyro_ret_handler;      // Выход (Post)
    gyro_kretprobe.entry_handler = gyro_entry_handler; // Вход (Pre)
    gyro_kretprobe.data_size = sizeof(struct gyro_data);
    gyro_kretprobe.maxactive = 20;

    int ret = register_kretprobe(&gyro_kretprobe);
    if (ret < 0) {
        printk(KERN_ERR "JiangNight: Failed to hook primary function, trying backup...");
        // Запасной вариант (для некоторых MTK/Samsung)
        gyro_kretprobe.kp.symbol_name = "iio_buffer_read";
        ret = register_kretprobe(&gyro_kretprobe);
        if (ret < 0) {
             printk(KERN_ERR "JiangNight: Fatal - Gyro hook failed completely.");
             return ret;
        }
    }
    
    // ХИТРОСТЬ: Kprobes сам нашел адрес!
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

// Новая функция движения
void kernel_gyro_move(int x, int y) {
    g_aim_x = x;
    g_aim_y = y;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static HW_BP bp_args;
    static struct process p_process;
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
        {
            struct GyroData data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data))) return -EFAULT;
            
            // Если PID не установлен, берем его из текущего процесса (который шлет команды)
            if (g_target_pid == 0 && current->tgid > 1000) {
                // Но лучше, чтобы User Space явно передавал PID игры
                // Пока оставим так: предполагаем, что чит запущен в процессе игры
                // g_target_pid = current->tgid; 
            }
            
            kernel_gyro_move(data.x, data.y);
            break;
        }

        // ... остальные case (BP, HIDE) ...
        default:
            ret = -EINVAL;
            break;
    }
    return ret;
}

int dispatch_open(struct inode *node, struct file *file) {
    file->private_data = &memdev;
    task = current; 
    // Если чит внедряется в игру, можно захватить PID здесь
    g_target_pid = current->tgid;
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    // Очистка
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
    
    // resolve_kernel_symbols(); // Больше не нужно для гироскопа, Kprobes сделает это

    init_breakpoint_system(); 
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
    
    // ЗАПУСК ХУКА ГИРОСКОПА
    init_gyro_hook();

    printk(KERN_INFO "JiangNight: Driver Loaded.");
    return 0;
}

static void __exit driver_unload(void) {
    // ОТКЛЮЧЕНИЕ ХУКА
    unregister_kretprobe(&gyro_kretprobe);
    
    remove_all_breakpoints(); 
    cleanup_breakpoint_system();
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
