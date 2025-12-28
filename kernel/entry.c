#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

// Подключаем наши хедеры. 
// ВАЖНО: memory.h должен быть подключен, так как там реализация
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"

// Если используете Kernel 5.3+ и VFS хаки
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

struct task_struct *task = NULL;
struct task_struct *hide_pid_process_task;
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

// Основной обработчик IOCTL
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static struct process p_process;
    static char name[0x100] = {0};

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) return -1;
            if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) return -1;
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) return -1;
            if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) return -1;
            break;

        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0
             || copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) != 0) {
                return -1;
            }
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) != 0) return -1;
            break;

        case OP_HIDE_PROCESS:
            hide_process(task, &hide_process_state);
            break;

        case OP_PID_HIDE_PROCESS:
            if (copy_from_user(&hide_process_pid, (void __user*)arg, sizeof(hide_process_pid)) != 0) return -1;
            hide_pid_process_task = pid_task(find_vpid(hide_process_pid), PIDTYPE_PID);
            hide_pid_process(hide_pid_process_task);
            break;

        case OP_GET_PROCESS_PID:
            if (copy_from_user(&p_process, (void __user*)arg, sizeof(p_process)) != 0) return -1;
            p_process.process_pid = get_process_pid(p_process.process_comm);
            if (copy_to_user((void __user*)arg, &p_process, sizeof(p_process)) != 0) return -1;
            break;

        default:
            break;
    }
    return 0;
}

int dispatch_open(struct inode *node, struct file *file) {
    file->private_data = &memdev;
    task = current;
     printk("Open device called by pid:%d", task->pid);
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    if (hide_process_state) {
        recover_process(task);
    }
    if (hide_process_pid != 0) {
        recover_process(hide_pid_process_task);
    }
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
    
    // Инициализируем поиск символов перед началом работы
    resolve_kernel_symbols();

    // Генерация случайного имени (заглушка или ваша функция)
    // devicename = get_rand_str(); 
    devicename = "mtk_tersafe"; // Временное имя, если get_rand_str нет

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

    // Удаление следов в proc (опционально)
    // remove_proc_entry("uevents_records", NULL);
    // list_del_rcu(&THIS_MODULE->list);
    
    return 0;
}

static void __exit driver_unload(void) {
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");
