#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
#include "breakpoint.h"
// === ИСПРАВЛЕНИЕ: ОПРЕДЕЛЕНИЕ ПЕРЕМЕННОЙ ===
// Здесь мы выделяем память под переменную. 
// Другие файлы используют extern struct task_struct *task;
struct task_struct *task = NULL; 

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

struct task_struct *hide_pid_process_task = NULL;
int hide_process_pid = 0;
int hide_process_state = 0;

static struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
} memdev;

static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

#include <linux/input.h>

static struct input_dev *vimu_dev = NULL;

// Определяем свойство, если его нет в старых хедерах
#ifndef INPUT_PROP_ACCELEROMETER
#define INPUT_PROP_ACCELEROMETER 0x06
#endif

// Инициализация Виртуального IMU (Inertial Measurement Unit)
int init_virtual_imu(void) {
    int error;

    vimu_dev = input_allocate_device();
    if (!vimu_dev) {
        printk(KERN_ERR "LKM: Failed to allocate IMU device");
        return -ENOMEM;
    }

    // ХИТРОСТЬ 1: Используем имя реального популярного чипа
    // Android Sensor HAL часто сканирует /dev/input/event* и ищет знакомые строки.
    vimu_dev->name = "bmi160_imu"; 
    
    vimu_dev->phys = "virtual/input/imu";
    vimu_dev->id.bustype = BUS_VIRTUAL;
    vimu_dev->id.vendor  = 0xDEAD;
    vimu_dev->id.product = 0xBEEF;
    vimu_dev->id.version = 0x0100;

    // ХИТРОСТЬ 2: Указываем системе, что это Акселерометр/Сенсор
    set_bit(INPUT_PROP_ACCELEROMETER, vimu_dev->propbit);

    // Включаем EV_ABS (Абсолютные данные сенсоров)
    set_bit(EV_ABS, vimu_dev->evbit);

    // 1. Настраиваем ГИРОСКОП (Вращение) - ABS_RX, ABS_RY, ABS_RZ
    // Данные здесь = угловая скорость (rad/s или deg/s в сыром виде)
    set_bit(ABS_RX, vimu_dev->absbit);
    set_bit(ABS_RY, vimu_dev->absbit);
    set_bit(ABS_RZ, vimu_dev->absbit);
    input_set_abs_params(vimu_dev, ABS_RX, -32768, 32767, 0, 0);
    input_set_abs_params(vimu_dev, ABS_RY, -32768, 32767, 0, 0);
    input_set_abs_params(vimu_dev, ABS_RZ, -32768, 32767, 0, 0);

    // 2. Настраиваем АКСЕЛЕРОМЕТР (Гравитация) - ABS_X, ABS_Y, ABS_Z
    // Некоторые игры требуют наличия этих осей, чтобы признать устройство сенсором
    set_bit(ABS_X, vimu_dev->absbit);
    set_bit(ABS_Y, vimu_dev->absbit);
    set_bit(ABS_Z, vimu_dev->absbit);
    input_set_abs_params(vimu_dev, ABS_X, -32768, 32767, 0, 0);
    input_set_abs_params(vimu_dev, ABS_Y, -32768, 32767, 0, 0);
    input_set_abs_params(vimu_dev, ABS_Z, -32768, 32767, 0, 0);

    // MSC_TIMESTAMP часто нужен для сенсоров
    set_bit(EV_MSC, vimu_dev->evbit);
    set_bit(MSC_TIMESTAMP, vimu_dev->mscbit);

    error = input_register_device(vimu_dev);
    if (error) {
        printk(KERN_ERR "LKM: Failed to register IMU");
        input_free_device(vimu_dev);
        return error;
    }

    printk(KERN_INFO "LKM: Virtual BMI160 Gyro Registered!");
    return 0;
}

// Функция движения
// x, y - это "Сила поворота" (Скорость).
// Если x=0, y=0 -> вращения нет.
// Если x=50, y=-50 -> камера поворачивается вправо-вверх с постоянной скоростью.
void kernel_gyro_move(int x, int y) {
    if (!vimu_dev) {
        if (init_virtual_imu() != 0) return;
    }

    // Отправляем данные ГИРОСКОПА (Скорость вращения)
    // В Android сырые данные гироскопа обычно приходят в ABS_RX/RY/RZ
    
    // Инверсия осей (зависит от ориентации, подберите экспериментально)
    // int out_x = y; 
    // int out_y = x;
    
    // Прямая передача (стандарт)
    input_report_abs(vimu_dev, ABS_RX, x);
    input_report_abs(vimu_dev, ABS_RY, y);
    
    // Акселерометр можно не трогать, или слать константу (гравитация вниз),
    // чтобы игра не думала, что телефон падает.
    // input_report_abs(vimu_dev, ABS_Z, 9800); // Гравитация по Z

    // Синхронизация
    input_sync(vimu_dev);
}

void gyro_cleanup(void) {
    if (vimu_dev) {
        input_unregister_device(vimu_dev);
        vimu_dev = NULL;
    }
}
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static HW_BP bp_args; // Переменная для аргументов
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

case OP_SET_HW_BP:
        if (copy_from_user(&bp_args, (void __user*)arg, sizeof(bp_args))) return -EFAULT;
        // Используем новую функцию с возвратом ошибок
        ret = install_breakpoint(bp_args.pid, bp_args.addr, bp_args.type);
        // ret уже содержит код ошибки или 0
        break;

    case OP_DEL_HW_BP:
        if (copy_from_user(&bp_args, (void __user*)arg, sizeof(bp_args))) return -EFAULT;
        ret = remove_breakpoint(bp_args.pid, bp_args.addr);
        break;

    case OP_GET_DEBUG_EVENT:
        // arg - указатель на буфер DEBUG_EVENT в user-space
        ret = get_debug_event_fw(arg);
        break;
        
        case OP_HIDE_PROCESS:
            // task устанавливается в open
            if (task) hide_process(task, &hide_process_state);
            break;

        case OP_PID_HIDE_PROCESS:
            if (copy_from_user(&hide_process_pid, (void __user*)arg, sizeof(hide_process_pid))) return -EFAULT;
            
            rcu_read_lock();
            hide_pid_process_task = pid_task(find_vpid(hide_process_pid), PIDTYPE_PID);
            if (hide_pid_process_task) get_task_struct(hide_pid_process_task);
            rcu_read_unlock();

            if (hide_pid_process_task) {
                hide_pid_process(hide_pid_process_task);
                // put_task_struct делаем при выгрузке или восстановлении, 
                // но для простоты здесь не делаем put, чтобы ссылка жила до close.
                // Это утечка, если делать много раз, но для чита ок.
            }
            break;

        case OP_GET_PROCESS_PID:
            if (copy_from_user(&p_process, (void __user*)arg, sizeof(p_process))) return -EFAULT;
            p_process.process_pid = get_process_pid(p_process.process_comm);
            if (copy_to_user((void __user*)arg, &p_process, sizeof(p_process))) return -EFAULT;
            break;
// Внутри switch(cmd)
case OP_GYRO_MOVE:
{
    struct GyroData data;
    if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
        return -EFAULT;
    }
    // Передаем int напрямую
    kernel_gyro_move(data.x, data.y);
    break;
}
        default:
            ret = -EINVAL;
            break;
    }
    return ret;
}

int dispatch_open(struct inode *node, struct file *file) {
    file->private_data = &memdev;
    task = current; // Сохраняем текущий процесс (кто открыл драйвер)
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    if (hide_process_state && task) {
        recover_process(task);
    }
    if (hide_process_pid != 0 && hide_pid_process_task) {
        recover_process(hide_pid_process_task);
        put_task_struct(hide_pid_process_task); // Освобождаем
        hide_pid_process_task = NULL;
    }
    task = NULL;
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
    
    // Инициализация поиска адресов
    resolve_kernel_symbols();

    init_breakpoint_system(); // Инициализация списков и FIFO
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
    
    printk(KERN_INFO "JiangNight: Driver Loaded.");
    return 0;
}

static void __exit driver_unload(void) {
    remove_all_breakpoints(); // Очистка всех висящих BP
    cleanup_breakpoint_system(); // <-- Добавить это
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
