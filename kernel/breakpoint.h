#ifndef _BREAKPOINT_H
#define _BREAKPOINT_H

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>

// Массив для хранения активных брейкпоинтов (заглушка)
// В реальном проекте здесь должен быть список или map
static struct perf_event * __percpu *sample_hbp;

// Обработчик срабатывания брейкпоинта
static void sample_hbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    // Логируем срабатывание. 
    // В regs->pc адрес инструкции, в regs->regs[0..30] регистры.
    // %llx выводит 64-битное число в hex
    printk(KERN_INFO "JiangNight: BP hit at %llx! X0: %llx X1: %llx", 
           regs->pc, regs->regs[0], regs->regs[1]);
}

// Установка брейкпоинта
int install_breakpoint(pid_t pid, uintptr_t addr, int type)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    struct perf_event *bp; // Объявление переменной В НАЧАЛЕ функции
    
    hw_breakpoint_init(&attr);
    
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    
    // Тип: 0=Execute, 1=Write, 2=Read/Write
    if (type == 0) 
        attr.bp_type = HW_BREAKPOINT_X;
    else if (type == 1) 
        attr.bp_type = HW_BREAKPOINT_W;
    else 
        attr.bp_type = HW_BREAKPOINT_RW | HW_BREAKPOINT_R;

    attr.sample_period = 1;
    attr.precise_ip = 1;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    
    if (!task) return -ESRCH;

    // Регистрация события
    bp = perf_event_create_kernel_counter(
        &attr, -1, task, sample_hbp_handler, NULL
    );

    put_task_struct(task);

    if (IS_ERR(bp)) {
        printk(KERN_ERR "JiangNight: Failed to create BP: %ld", PTR_ERR(bp));
        return PTR_ERR(bp);
    }

    printk(KERN_INFO "JiangNight: BP installed at %lx for PID %d", addr, pid);
    
    // Внимание: здесь мы теряем указатель 'bp' (утечка ресурса), 
    // так как не сохраняем его в глобальный список для последующего удаления.
    // Для теста ок, для продакшена нужно добавить механизм сохранения.
    
    return 0;
}

#endif
