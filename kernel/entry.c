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
#include <linux/fs.h>
#include <linux/uaccess.h>

// Глобальные переменные гироскопа
static struct file *gyro_filp = NULL;
static char gyro_path[32] = {0};

// --- FILE I/O WRAPPERS (GKI COMPATIBLE) ---

// Функция открытия файла
struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = filp_open(path, flags, rights);
    return IS_ERR(filp) ? NULL : filp;
}

// Функция чтения файла (для новых ядер используем kernel_read)
// ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos);
int read_file_content(const char *path, char *buf, int max_len) {
    struct file *f;
    int len;
    loff_t pos = 0;

    f = file_open(path, O_RDONLY, 0);
    if (!f) return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = kernel_read(f, buf, max_len, &pos);
#else
    // Фоллбэк для старых ядер
    mm_segment_t oldfs = get_fs();
    set_fs(get_ds());
    len = vfs_read(f, buf, max_len, &pos);
    set_fs(oldfs);
#endif

    filp_close(f, NULL);
    if (len > 0 && len < max_len) buf[len] = 0; // Null terminate
    return len;
}

// Функция записи в файл
int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) {
    int ret;
    loff_t pos = offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    ret = kernel_write(file, data, size, &pos);
#else
    mm_segment_t oldfs = get_fs();
    set_fs(get_ds());
    ret = vfs_write(file, data, size, &pos);
    set_fs(oldfs);
#endif
    return ret;
}

// --- GYRO LOGIC ---

// Автопоиск (исправленный)
void gyro_auto_find(void) {
    int i;
    char sys_path[128];
    char dev_name[256];
    char dev_path[32];
    struct file *f;

    if (gyro_filp) return;

    printk(KERN_INFO "LKM: Starting Gyro Auto-Search...");

    for (i = 0; i < 30; i++) {
        // Формируем путь
        snprintf(sys_path, sizeof(sys_path), "/sys/class/input/event%d/device/name", i);
        
        // Очищаем буфер
        memset(dev_name, 0, sizeof(dev_name));
        
        // Читаем имя
        if (read_file_content(sys_path, dev_name, 255) <= 0) {
            snprintf(sys_path, sizeof(sys_path), "/sys/class/input/event%d/name", i);
            if (read_file_content(sys_path, dev_name, 255) <= 0) continue;
        }

        // Проверка имен
        if (strstr(dev_name, "bmi") || strstr(dev_name, "lsm") || 
            strstr(dev_name, "icm") || strstr(dev_name, "gyro") || 
            strstr(dev_name, "accelerometer") || strstr(dev_name, "qcom,smd-irq")) 
        {
            snprintf(dev_path, sizeof(dev_path), "/dev/input/event%d", i);
            printk(KERN_INFO "LKM: Found potential gyro: %s -> %s", dev_name, dev_path);
            
            f = file_open(dev_path, O_RDWR, 0);
            if (f) {
                gyro_filp = f;
                // strlcpy(gyro_path, dev_path, sizeof(gyro_path)); // В ядре strlcpy безопаснее
                memcpy(gyro_path, dev_path, sizeof(gyro_path));
                printk(KERN_INFO "LKM: Hooked gyro: %s", dev_path);
                return;
            }
        }
    }
}

// Функция движения (исправленная)
void kernel_gyro_move(float x, float y) {
    struct input_event ev[3];
    int val_x, val_y;

    if (!gyro_filp) {
        gyro_auto_find();
        if (!gyro_filp) return;
    }

    val_x = (int)(x * 10.0f);
    val_y = (int)(y * 10.0f);

    ev[0].type = EV_REL; ev[0].code = REL_RX; ev[0].value = val_x;
    ev[1].type = EV_REL; ev[1].code = REL_RY; ev[1].value = val_y;
    ev[2].type = EV_SYN; ev[2].code = SYN_REPORT; ev[2].value = 0;

    file_write(gyro_filp, 0, (unsigned char*)ev, sizeof(ev));
}

// Очистка при выгрузке (вызови это в cleanup_module)
void gyro_cleanup(void) {
    if (gyro_filp) {
        filp_close(gyro_filp, NULL);
        gyro_filp = NULL;
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
    // Обязательно добавь scope {}, чтобы можно было объявить data
    if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
        return -EFAULT;
    }
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
