
#ifndef _MEMORY_H
#define _MEMORY_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

// ==========================================
// ЧТЕНИЕ / ЗАПИСЬ (ЧЕРЕЗ ACCESS_PROCESS_VM)
// ==========================================

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    int ret;
    void* kbuf;

    // 1. Находим процесс
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return false;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }

    // 2. Выделяем временный буфер ядра
    // (access_process_vm копирует в буфер ядра, а не user-space)
    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) {
        mmput(mm);
        put_task_struct(task);
        return false;
    }

    // 3. Читаем память (Стандартная функция ядра)
    // Она сама делает mmap_lock, find_vma, handle_mm_fault и т.д.
    // Это на 100% безопасно и не вызывает Kernel Panic.
    ret = access_process_vm(task, addr, kbuf, size, 0);

    // 4. Копируем результат пользователю
    if (ret == size) {
        if (copy_to_user(buffer, kbuf, size)) {
            ret = -1; // Ошибка копирования
        }
    } else {
        // Если прочли меньше или ошибка - обнуляем
        if (clear_user(buffer, size)) { }
    }

    kfree(kbuf);
    mmput(mm);
    put_task_struct(task);
    
    return (ret == size);
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    int ret;
    void* kbuf;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return false;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) {
        mmput(mm);
        put_task_struct(task);
        return false;
    }

    if (copy_from_user(kbuf, buffer, size)) {
        kfree(kbuf);
        mmput(mm);
        put_task_struct(task);
        return false;
    }

    // access_process_vm с флагом FOLL_WRITE (1)
    ret = access_process_vm(task, addr, kbuf, size, 1);

    kfree(kbuf);
    mmput(mm);
    put_task_struct(task);

    return (ret == size);
}

// Заглушка для совместимости, если resolve_kernel_symbols вызывается в entry.c
static void resolve_kernel_symbols(void) {
    // Больше не нужно искать символы вручную, access_process_vm экспортирован
    printk(KERN_INFO "JiangNight: Using standard access_process_vm");
}

// Заглушка для get_module_base (он использует только VMA списки, не память)
// Оставляем как есть в process.h

#endif
