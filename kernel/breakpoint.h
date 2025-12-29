// breakpoint.h
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
// Размер буфера событий (должен быть степенью двойки)
#define EVENT_FIFO_SIZE 1024 * sizeof(DEBUG_EVENT)

static DECLARE_KFIFO(debug_events, unsigned char, EVENT_FIFO_SIZE);
static wait_queue_head_t event_wait_queue;
static spinlock_t bp_lock; // Спинлок для защиты списка

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
void init_breakpoint_system(void) {
    init_waitqueue_head(&event_wait_queue);
    spin_lock_init(&bp_lock);
    INIT_KFIFO(debug_events);
}

// === Обработчик срабатывания ===
static void sample_hbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    DEBUG_EVENT event;
    int i;

    // Заполняем структуру события данными из регистров
    event.pid = current->pid;
    event.pc = regs->pc;
    event.sp = regs->sp;
    event.pstate = regs->pstate;
    // Адрес, вызвавший срабатывание (для watchpoint доступен через perf_sample_data, 
    // но для простоты берем адрес самого BP или instruction pointer)
    event.fault_addr = bp->attr.bp_addr;

    // Копируем РОН (X0-X30)
    for (i = 0; i < 31; i++) {
        event.regs[i] = regs->regs[i];
    }

    // Записываем в кольцевой буфер (без блокировок, используем kfifo_put)
    // kfifo_in_spinlocked если нужно из прерывания, но здесь обработчик perf, 
    // обычно kfifo_in достаточно, если один продюсер.
    if (kfifo_avail(&debug_events) >= sizeof(event)) {
        kfifo_in(&debug_events, &event, sizeof(event));
        // Будим читающий поток (user-space), если он ждет в ioctl
        wake_up_interruptible(&event_wait_queue);
    } else {
        // Буфер переполнен, можно инкрементировать счетчик дропов
        printk(KERN_WARNING "JiangNight: Debug Event FIFO overflow!");
    }
}

// === Установка BP ===
int install_breakpoint(pid_t pid, uintptr_t addr, int type)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    struct perf_event *pe;
    struct bp_node *node;
    int ret = 0;

    // 1. Проверяем, не установлен ли уже такой BP
    spin_lock(&bp_lock);
    list_for_each_entry(node, &bp_list_head, list) {
        if (node->pid == pid && node->addr == addr) {
            spin_unlock(&bp_lock);
            return -EEXIST; // Уже есть
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
    attr.exclude_kernel = 1; // Не ловим в ядре
    attr.exclude_hv = 1;

    // 3. Получаем task_struct
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;

    // 4. Создаем perf event
    pe = perf_event_create_kernel_counter(&attr, -1, task, sample_hbp_handler, NULL);
    put_task_struct(task);

    if (IS_ERR(pe)) {
        printk(KERN_ERR "JiangNight: Failed to create BP: %ld", PTR_ERR(pe));
        return PTR_ERR(pe);
    }

    // 5. Сохраняем в список
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
            // Удаляем из списка и освобождаем
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

// === Очистка всех BP при выгрузке ===
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

// === Получение события (для IOCTL) ===
int get_debug_event_fw(unsigned long arg) {
    DEBUG_EVENT event;
    int ret;

    // Ждем события, если буфер пуст (блокирующий вызов)
    // Можно убрать wait_event, если хотите опрашивать (polling) в цикле из user-mode
    // ret = wait_event_interruptible(event_wait_queue, !kfifo_is_empty(&debug_events));
    // if (ret) return ret; // Прервано сигналом

    if (kfifo_out(&debug_events, &event, sizeof(event)) > 0) {
        if (copy_to_user((void __user*)arg, &event, sizeof(event)))
            return -EFAULT;
        return 1; // Успех, вернули 1 событие
    }
    return 0; // Буфер пуст
}

#endif
