#ifndef _BREAKPOINT_H
#define _BREAKPOINT_H

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/kfifo.h>
#include <asm/ptrace.h>

#include "comm.h"

// === Настройки FIFO ===
// Размер буфера (должен быть степенью двойки)
// 1024 * 288 байт (примерно) = ~294 КБ
#define FIFO_SIZE (128 * sizeof(DEBUG_EVENT))

// Используем указатель на FIFO (динамическое выделение)
static struct kfifo debug_events;
static wait_queue_head_t event_wait_queue;
static spinlock_t bp_lock; // Спинлок для защиты списка
static spinlock_t fifo_lock; // Спинлок для защиты FIFO (если нужен)

// === Структура для хранения активного BP ===
struct bp_node {
    struct list_head list;
    pid_t pid;
    uintptr_t addr;
    struct perf_event *pe;
};

// Глобальный список активных брейкпоинтов
static LIST_HEAD(bp_list_head);

// Инициализация подсистемы (вызвать в driver_entry)
int init_breakpoint_system(void) {
    int ret;
    
    init_waitqueue_head(&event_wait_queue);
    spin_lock_init(&bp_lock);
    spin_lock_init(&fifo_lock);
    
    // Выделяем память под FIFO динамически
    ret = kfifo_alloc(&debug_events, FIFO_SIZE, GFP_KERNEL);
    if (ret) {
        printk(KERN_ERR "JiangNight: Failed to alloc kfifo");
        return ret;
    }
    
    return 0;
}

// Очистка памяти FIFO (вызвать при выгрузке)
void cleanup_breakpoint_system(void) {
    kfifo_free(&debug_events);
}

// === Обработчик срабатывания ===
static void sample_hbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    DEBUG_EVENT event;
    int i;

    // Заполняем структуру события
    event.pid = current->pid;
    event.pc = regs->pc;
    event.sp = regs->sp;
    event.pstate = regs->pstate;
    event.fault_addr = bp->attr.bp_addr;

    for (i = 0; i < 31; i++) {
        event.regs[i] = regs->regs[i];
    }

    // kfifo_in ожидает const void* буфер, если FIFO создано через kfifo_alloc
    // Используем kfifo_in_spinlocked для безопасности в прерывании (хотя perf handler это NMI/IRQ контекст)
    if (kfifo_avail(&debug_events) >= sizeof(event)) {
        kfifo_in(&debug_events, &event, sizeof(event));
        wake_up_interruptible(&event_wait_queue);
    } else {
        // printk в прерывании лучше не злоупотреблять, но для дебага оставим
        // printk(KERN_WARNING "JiangNight: FIFO overflow!");
    }
}

// === Установка BP ===
int install_breakpoint(pid_t pid, uintptr_t addr, int type)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    struct perf_event *pe;
    struct bp_node *node;

    // 1. Проверяем наличие
    spin_lock(&bp_lock);
    list_for_each_entry(node, &bp_list_head, list) {
        if (node->pid == pid && node->addr == addr) {
            spin_unlock(&bp_lock);
            return -EEXIST;
        }
    }
    spin_unlock(&bp_lock);

    // 2. Настройка атрибутов
    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    
    if (type == BP_TYPE_EXEC)
        attr.bp_type = HW_BREAKPOINT_X;
    else if (type == BP_TYPE_WRITE)
        attr.bp_type = HW_BREAKPOINT_W;
    else
        attr.bp_type = HW_BREAKPOINT_RW | HW_BREAKPOINT_R;

    attr.sample_period = 1;
    attr.precise_ip = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;

    pe = perf_event_create_kernel_counter(&attr, -1, task, sample_hbp_handler, NULL);
    put_task_struct(task);

    if (IS_ERR(pe)) {
        printk(KERN_ERR "JiangNight: Failed to create BP: %ld", PTR_ERR(pe));
        return PTR_ERR(pe);
    }

    node = kmalloc(sizeof(struct bp_node), GFP_KERNEL);
    if (!node) {
        perf_event_release_kernel(pe);
        return -ENOMEM;
    }
    node->pid = pid;
    node->addr = addr;
    node->pe = pe;

    spin_lock(&bp_lock);
    list_add_tail(&node->list, &bp_list_head);
    spin_unlock(&bp_lock);

    printk(KERN_INFO "JiangNight: BP installed at %lx for PID %d", addr, pid);
    return 0;
}

// === Удаление BP ===
int remove_breakpoint(pid_t pid, uintptr_t addr)
{
    struct bp_node *node, *tmp;
    int found = 0;

    spin_lock(&bp_lock);
    list_for_each_entry_safe(node, tmp, &bp_list_head, list) {
        if (node->pid == pid && node->addr == addr) {
            list_del(&node->list);
            perf_event_release_kernel(node->pe);
            kfree(node);
            found = 1;
            break; 
        }
    }
    spin_unlock(&bp_lock);

    if (found) 
        printk(KERN_INFO "JiangNight: BP removed at %lx", addr);
    else 
        return -ENOENT;

    return 0;
}

// === Очистка всех BP ===
void remove_all_breakpoints(void) {
    struct bp_node *node, *tmp;
    spin_lock(&bp_lock);
    list_for_each_entry_safe(node, tmp, &bp_list_head, list) {
        list_del(&node->list);
        perf_event_release_kernel(node->pe);
        kfree(node);
    }
    spin_unlock(&bp_lock);
}

// === Получение события ===
int get_debug_event_fw(unsigned long arg) {
    DEBUG_EVENT event;
    int copied;

    // kfifo_out возвращает количество скопированных байт
    copied = kfifo_out(&debug_events, &event, sizeof(event));
    
    if (copied > 0) {
        if (copy_to_user((void __user*)arg, &event, sizeof(event)))
            return -EFAULT;
        return 1; // Успех
    }
    return 0; // Пусто
}

#endif
