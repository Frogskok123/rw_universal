#ifndef _BREAKPOINT_H
#define _BREAKPOINT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ratelimit.h> /* Для ограничения частоты */
#include "comm.h"

// Размер буфера: 512 КБ (чтобы вместить спам событий)
#define FIFO_SIZE (512 * 1024)

// Настройки лимитов: 5000 событий в секунду макс.
// Все что выше - отбрасывается, чтобы не повесить телефон.
#define EVENT_RATELIMIT_INTERVAL (1 * HZ)
#define EVENT_RATELIMIT_BURST    5000

static struct kfifo debug_events;
static void *fifo_buffer = NULL;
static wait_queue_head_t event_wait_queue;
static spinlock_t bp_lock;

// Структура для Rate Limiting
static DEFINE_RATELIMIT_STATE(hbp_ratelimit_state, EVENT_RATELIMIT_INTERVAL, EVENT_RATELIMIT_BURST);

// Список активных BP
struct bp_node {
    struct list_head list;
    pid_t pid;
    uintptr_t addr;
    struct perf_event *pe;
};

static LIST_HEAD(bp_list_head);

// --------------------------------------------------------------------------
// ИНИЦИАЛИЗАЦИЯ
// --------------------------------------------------------------------------
int init_breakpoint_system(void) {
    int ret;
    init_waitqueue_head(&event_wait_queue);
    spin_lock_init(&bp_lock);

    fifo_buffer = vmalloc(FIFO_SIZE);
    if (!fifo_buffer) {
        printk(KERN_ERR "HBP: Failed to vmalloc FIFO");
        return -ENOMEM;
    }

    // Инициализируем kfifo.
    // Важно: kfifo в Linux ядре оптимизирован и почти lockless для одного писателя и читателя.
    ret = kfifo_init(&debug_events, fifo_buffer, FIFO_SIZE);
    if (ret) {
        vfree(fifo_buffer);
        fifo_buffer = NULL;
        return ret;
    }
    return 0;
}

void cleanup_breakpoint_system(void) {
    if (fifo_buffer) {
        vfree(fifo_buffer);
        fifo_buffer = NULL;
    }
}

// --------------------------------------------------------------------------
// ГЛАВНЫЙ ОБРАБОТЧИК (HANDLER)
// --------------------------------------------------------------------------
/* 
   Этот код выполняется в atomic context (IRQ/NMI).
   ЗДЕСЬ НЕЛЬЗЯ СПАТЬ, ВЫДЕЛЯТЬ ПАМЯТЬ ИЛИ ИСПОЛЬЗОВАТЬ ТЯЖЕЛЫЕ БЛОКИРОВКИ.
*/
static void sample_hbp_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    DEBUG_EVENT event;
    int i;
    
    // 1. RATE LIMITING (Спасение от зависания)
    // Если событий слишком много, мы просто игнорируем лишние.
    // __ratelimit вернет 0, если лимит превышен.
    if (!__ratelimit(&hbp_ratelimit_state)) {
        return; 
    }

    // 2. Проверка места в буфере
    // kfifo_avail быстрая операция. Если места нет - выходим.
    if (kfifo_avail(&debug_events) < sizeof(event)) {
        // Можно добавить atomic счетчик потерянных событий для отладки
        return;
    }

    // 3. Заполнение структуры (Минимизируем копирование)
    event.pid = current->pid;
    event.pc = regs->pc;
    event.sp = regs->sp;
    event.pstate = regs->pstate;
    event.fault_addr = bp->attr.bp_addr;
    
    // Копируем регистры.
    // ОПТИМИЗАЦИЯ: Если вам нужны только X0-X7 (аргументы), 
    // измените цикл на i < 8. Это ускорит обработчик в 3 раза.
    for (i = 0; i < 31; i++) {
        event.regs[i] = regs->regs[i];
    }

    // 4. Запись в буфер
    kfifo_in(&debug_events, &event, sizeof(event));

    // 5. Пробуждение (Optimized Wakeup)
    // Будим процесс, если кто-то ждет.
    if (waitqueue_active(&event_wait_queue)) {
        wake_up_interruptible(&event_wait_queue);
    }
}

// --------------------------------------------------------------------------
// УПРАВЛЕНИЕ БРЕЙКПОИНТАМИ (INSTALL/REMOVE)
// --------------------------------------------------------------------------
int install_breakpoint(pid_t pid, uintptr_t addr, int type) {
    struct perf_event_attr attr;
    struct task_struct *task;
    struct perf_event *pe;
    struct bp_node *node;

    // Проверка на дубликаты
    spin_lock(&bp_lock);
    list_for_each_entry(node, &bp_list_head, list) {
        if (node->pid == pid && node->addr == addr) {
            spin_unlock(&bp_lock);
            return -EEXIST;
        }
    }
    spin_unlock(&bp_lock);

    // Настройка атрибутов perf
    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    
    if (type == BP_TYPE_EXEC) attr.bp_type = HW_BREAKPOINT_X;
    else if (type == BP_TYPE_WRITE) attr.bp_type = HW_BREAKPOINT_W;
    else attr.bp_type = HW_BREAKPOINT_RW | HW_BREAKPOINT_R;

    attr.sample_period = 1;
    attr.precise_ip = 1;
    attr.exclude_kernel = 1; // Не ловим ядро
    attr.exclude_hv = 1;     // Не ловим гипервизор

    // Получаем task_struct процесса
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;

    // Создаем событие ядра
    pe = perf_event_create_kernel_counter(&attr, -1, task, sample_hbp_handler, NULL);
    put_task_struct(task);

    if (IS_ERR(pe)) return PTR_ERR(pe);

    // Сохраняем в список
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

    return 0;
}

int remove_breakpoint(pid_t pid, uintptr_t addr) {
    struct bp_node *node, *tmp;
    int found = 0;

    spin_lock(&bp_lock);
    list_for_each_entry_safe(node, tmp, &bp_list_head, list) {
        if (node->pid == pid && node->addr == addr) {
            list_del(&node->list);
            perf_event_release_kernel(node->pe); // Отключает BP
            kfree(node);
            found = 1;
            break;
        }
    }
    spin_unlock(&bp_lock);
    return found ? 0 : -ENOENT;
}

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

// Чтение событий из user-space
int get_debug_event_fw(unsigned long arg) {
    DEBUG_EVENT event;
    int ret;
    
    // Если буфер пуст - ждем, но не бесконечно (чтобы не застрять)
    // Можно использовать wait_event_interruptible, если нужен блокирующий вызов
    
    ret = kfifo_out(&debug_events, &event, sizeof(event));
    if (ret > 0) {
        if (copy_to_user((void __user*)arg, &event, sizeof(event)))
            return -EFAULT;
        return 1; // Успех, данные есть
    }
    return 0; // Данных нет
}

#endif
