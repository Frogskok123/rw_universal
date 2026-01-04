#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/kprobes.h> // <--- ВАЖНО для фикса 6.1
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
#include "breakpoint.h"

// --- Глобальные переменные ---
static struct task_struct *task_to_hide = NULL;
static struct task_struct *hide_pid_task_ptr = NULL;
static int hide_process_pid_val = 0;
static int hide_state_val = 0;

static dev_t mem_tool_dev_t;
static struct {
    struct cdev cdev;
} memdev;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

// --- FIX для GKI 6.1: Динамический поиск функций ---
unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

// Функция для безопасного поиска скрытых символов ядра
static int resolve_kallsyms_via_kprobe(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        // Если не нашли kallsyms, пробуем альтернативы или падаем
        printk(KERN_ERR "jiangnight: Failed to find kallsyms_lookup_name via kprobe");
        return -1;
    }
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    printk(KERN_INFO "jiangnight: kallsyms found at %p", kallsyms_lookup_name_ptr);
    return 0;
}
// ----------------------------------------------------

// Обработчики открытия и закрытия
static int dispatch_open(struct inode *node, struct file *file) {
    task_to_hide = current; 
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file) {
    if (hide_state_val && task_to_hide) {
        recover_process(task_to_hide);
    }
    if (hide_pid_task_ptr) {
        recover_process(hide_pid_task_ptr);
        put_task_struct(hide_pid_task_ptr);
        hide_pid_task_ptr = NULL;
    }
    return 0;
}

// Функция hijack
int hijack_thread_with_args(THREAD_HIJACK_ARGS *ctx) {
    struct task_struct *task;
    struct pt_regs *regs;

    // ВАЖНО: find_vpid и pid_task тоже могут быть скрыты, нужно искать их через kallsyms
    // Но пока оставим так, если они есть в хедерах. Если нет - упадет при линковке.
    task = pid_task(find_vpid(ctx->pid), PIDTYPE_PID);
    if (!task) return -ESRCH;

    regs = task_pt_regs(task);
    if (!regs) return -EFAULT;

    regs->pc = ctx->rip;       
    regs->regs[0] = ctx->x0;   
    regs->regs[1] = ctx->x1;   
    regs->regs[2] = ctx->x2;   
    regs->regs[3] = ctx->x3;   
    
    return 0;
}

// IOCTL
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static HW_BP bp_args;
    static struct process p_process;
    static char name_buf[0x100];
    int ret = 0;

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            ret = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            ret = write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
            break;

        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb))) return -EFAULT;
            if (copy_from_user(name_buf, (void __user*)mb.name, sizeof(name_buf)-1)) return -EFAULT;
            name_buf[sizeof(name_buf)-1] = '\0';
            mb.base = get_module_base(mb.pid, name_buf);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) return -EFAULT;
            break;

        case OP_SET_HW_BP:
            if (copy_from_user(&bp_args, (void __user*)arg, sizeof(bp_args))) return -EFAULT;
            ret = install_breakpoint(bp_args.pid, bp_args.addr, bp_args.type);
            break;

        case OP_DEL_HW_BP:
            if (copy_from_user(&bp_args, (void __user*)arg, sizeof(bp_args))) return -EFAULT;
            ret = remove_breakpoint(bp_args.pid, bp_args.addr);
            break;

        case OP_GET_DEBUG_EVENT:
            ret = get_debug_event_fw(arg);
            break;

        case OP_HIDE_PROCESS:
            if (task_to_hide) hide_process(task_to_hide, &hide_state_val);
            break;

        case OP_PID_HIDE_PROCESS:
            if (copy_from_user(&hide_process_pid_val, (void __user*)arg, sizeof(hide_process_pid_val))) return -EFAULT;
            rcu_read_lock();
            hide_pid_task_ptr = pid_task(find_vpid(hide_process_pid_val), PIDTYPE_PID);
            if (hide_pid_task_ptr) get_task_struct(hide_pid_task_ptr);
            rcu_read_unlock();
            if (hide_pid_task_ptr) hide_pid_process(hide_pid_task_ptr);
            break;

        case OP_HIJACK_THREAD_ARGS: {
            THREAD_HIJACK_ARGS ctx;
            if (copy_from_user(&ctx, (void __user *)arg, sizeof(ctx))) return -EFAULT;
            return hijack_thread_with_args(&ctx);
        }

        case OP_GET_PROCESS_PID:
            if (copy_from_user(&p_process, (void __user*)arg, sizeof(p_process))) return -EFAULT;
            p_process.process_pid = get_process_pid(p_process.process_comm);
            if (copy_to_user((void __user*)arg, &p_process, sizeof(p_process))) return -EFAULT;
            break;

        default:
            ret = -EINVAL;
            break;
    }
    return (long)ret;
}

static struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static int __init driver_entry(void) {
    int ret;
    
    // --- 1. ПЕРВЫМ ДЕЛОМ ИЩЕМ СИМВОЛЫ ---
    // Без этого любой вызов системной функции убьет ядро 6.1
    if (resolve_kallsyms_via_kprobe() < 0) {
        printk(KERN_ERR "jiangnight: Aborting load, symbols not found.");
        return -EFAULT; 
    }
    
    // Теперь можно инициализировать подсистемы, которым нужны символы
    // (ВАЖНО: В твоем коде init_breakpoint_system ищет символы? Если да, ей нужен kallsyms_ptr)
    
    // Ищем указатели для соседних файлов (memory.c, process.c)
    // Например:
    find_task_by_vpid_ptr = (void *)kallsyms_lookup_name_ptr("find_task_by_vpid");
    if (!find_task_by_vpid_ptr) printk(KERN_WARNING "jiangnight: find_task_by_vpid not found!");
    
    init_breakpoint_system();
    
    // 2. Регистрация устройства
    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, "");
    if (ret < 0) return ret;
    
    cdev_init(&memdev.cdev, &dispatch_functions);
    memdev.cdev.owner = THIS_MODULE;
    ret = cdev_add(&memdev.cdev, mem_tool_dev_t, 1);
    if (ret < 0) {
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return ret;
    }
    
    // 3. Скрытие (ВНИМАНИЕ: Включать только на релизе! Для тестов закомментируй)
    /*
    list_del_init(&THIS_MODULE->list);
    list_del_init(&THIS_MODULE->source_list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    memset(THIS_MODULE->name, 0, MODULE_NAME_LEN);
    */
    
    printk(KERN_INFO "jiangnight: Driver loaded successfully. Major: %d", MAJOR(mem_tool_dev_t));
    return 0;
}

static void __exit driver_unload(void) {
    // Если скрывали модуль, вернуть его в список нельзя, просто удаляем ресурсы
    // list_add_tail_rcu(&THIS_MODULE->list, THIS_MODULE->list.prev);
    
    remove_all_breakpoints();
    cleanup_breakpoint_system();
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
    printk(KERN_INFO "jiangnight: Driver unloaded.");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oneplus");
