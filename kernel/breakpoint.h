#ifndef _BREAKPOINT_H
#define _BREAKPOINT_H

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>

// Массив для хранения активных брейкпоинтов (по одному на ядро или процесс)
// В реальном проекте лучше использовать список или хеш-мапу
static struct perf_event * __percpu *sample_hbp;

// Обработчик срабатывания брейкпоинта
static void sample_hbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    // ЗДЕСЬ ВАША ЛОГИКА
    // regs->regs[0] ... regs->regs[30] - регистры общего назначения
    // regs->pc - адрес инструкции
    
    printk(KERN_INFO "JiangNight: BP hit at %llx! X0: %llx X1: %llx", 
           regs->pc, regs->regs[0], regs->regs[1]);

    // Если это Watchpoint (на данные), просто логируем.
    // Если это Breakpoint (на код), нужно аккуратно обработать продолжение исполнения,
    // иначе будет вечный цикл срабатывания. Обычно perf сам отключает BP на один шаг.
}

// Установка брейкпоинта
int install_breakpoint(pid_t pid, uintptr_t addr, int type)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    
    hw_breakpoint_init(&attr);
    
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    
    // Тип: HW_BREAKPOINT_X (Execute), HW_BREAKPOINT_W (Write), HW_BREAKPOINT_RW
    if (type == 0) attr.bp_type = HW_BREAKPOINT_X;
    else if (type == 1) attr.bp_type = HW_BREAKPOINT_W;
    else attr.bp_type = HW_BREAKPOINT_RW | HW_BREAKPOINT_R;

    // Настраиваем callback
    attr.sample_period = 1;
    attr.precise_ip = 1; // Точный IP
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    
    if (!task) return -ESRCH;

    // Регистрация события
    // perf_event_create_kernel_counter(attr, cpu, task, callback, context)
    // cpu = -1 (любое ядро), task = целевой процесс
    struct perf_event *bp = perf_event_create_kernel_counter(
        &attr, -1, task, sample_hbp_handler, NULL
    );

    put_task_struct(task);

    if (IS_ERR(bp)) {
        printk(KERN_ERR "JiangNight: Failed to create BP: %ld", PTR_ERR(bp));
        return PTR_ERR(bp);
    }

    printk(KERN_INFO "JiangNight: BP installed at %lx for PID %d", addr, pid);
    
    // Сохраняем указатель bp, чтобы потом удалить (нужна глобальная структура хранения)
    // Для примера просто вернем успех, но в реальности нужно сохранить bp в список
    return 0;
}

#endif
