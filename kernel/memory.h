#ifndef _MEMORY_H
#define _MEMORY_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/slab.h>

// ==========================================
// 1. ДИНАМИЧЕСКИЙ ПОИСК ФУНКЦИЙ ЯДРА
// ==========================================

// Определяем типы функций
typedef int (*valid_phys_addr_range_t)(phys_addr_t addr, size_t size);
typedef long (*probe_kernel_read_t)(void *dst, const void *src, size_t size);
typedef long (*probe_kernel_write_t)(void *dst, const void *src, size_t size);

// Глобальные указатели
static valid_phys_addr_range_t g_valid_phys_addr_range = NULL;
static probe_kernel_read_t g_probe_read = NULL;
static probe_kernel_write_t g_probe_write = NULL;

static unsigned long lookup_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static void resolve_kernel_symbols(void) {
    // 1. Валидация
    g_valid_phys_addr_range = (valid_phys_addr_range_t)lookup_symbol("valid_phys_addr_range");
    if (!g_valid_phys_addr_range) {
        g_valid_phys_addr_range = (valid_phys_addr_range_t)lookup_symbol("memblock_is_map_memory");
    }
    
    // 2. Чтение ядра (безопасное)
    g_probe_read = (probe_kernel_read_t)lookup_symbol("copy_from_kernel_nofault");
    if (!g_probe_read) {
        g_probe_read = (probe_kernel_read_t)lookup_symbol("probe_kernel_read");
    }

    // 3. Запись ядра (безопасная)
    g_probe_write = (probe_kernel_write_t)lookup_symbol("copy_to_kernel_nofault");
    if (!g_probe_write) {
        g_probe_write = (probe_kernel_write_t)lookup_symbol("probe_kernel_write");
    }

    if (g_valid_phys_addr_range) printk(KERN_INFO "JiangNight: validation found at %p", g_valid_phys_addr_range);
    if (g_probe_read) printk(KERN_INFO "JiangNight: probe_read found at %p", g_probe_read);
    if (g_probe_write) printk(KERN_INFO "JiangNight: probe_write found at %p", g_probe_write);
}

// ==========================================
// 2. ТРАНСЛЯЦИЯ
// ==========================================

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) return 0;

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return 0;

    pud = pud_offset(p4d, va);
    if(pud_none(*pud) || pud_bad(*pud)) return 0;

    pmd = pmd_offset(pud, va);
    if(pmd_none(*pmd)) return 0;

    pte = pte_offset_kernel(pmd, va);
    if(pte_none(*pte) || !pte_present(*pte)) return 0;

    return (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT) + (va & (PAGE_SIZE - 1));
}

// ==========================================
// 3. ЧТЕНИЕ / ЗАПИСЬ (ЧЕРЕЗ НАЙДЕННЫЕ ФУНКЦИИ)
// ==========================================

size_t read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    void* kbuf;
    
    if (g_valid_phys_addr_range && !g_valid_phys_addr_range(pa, size)) return 0;
    if (!g_valid_phys_addr_range && !pfn_valid(__phys_to_pfn(pa))) return 0;

    mapped = (void*)phys_to_virt(pa);
    if (!mapped) return 0;

    // Если функцию чтения не нашли - ничего не поделаешь, выходим
    if (!g_probe_read) return 0;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) return 0;

    // Вызываем найденную функцию по указателю
    if (g_probe_read(kbuf, mapped, size) < 0) {
        kfree(kbuf);
        return 0; 
    }

    if (copy_to_user(buffer, kbuf, size)) {
        kfree(kbuf);
        return 0;
    }

    kfree(kbuf);
    return size;
}

size_t write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    void* kbuf;

    if (g_valid_phys_addr_range && !g_valid_phys_addr_range(pa, size)) return 0;
    if (!g_valid_phys_addr_range && !pfn_valid(__phys_to_pfn(pa))) return 0;

    mapped = (void*)phys_to_virt(pa);
    if (!mapped) return 0;

    if (!g_probe_write) return 0;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) return 0;

    if (copy_from_user(kbuf, buffer, size)) {
        kfree(kbuf);
        return 0;
    }

    // Вызываем найденную функцию по указателю
    if (g_probe_write(mapped, kbuf, size) < 0) {
        kfree(kbuf);
        return 0;
    }

    kfree(kbuf);
    return size;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;

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

    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));

        if (pa) {
            read_physical_address(pa, buffer, max);
        } else {
            if (clear_user(buffer, max)) { }
        }

        size -= max;
        buffer = (char*)buffer + max;
        addr += max;
    }

    mmput(mm);
    put_task_struct(task);
    return true;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;

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

    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));

        if (pa) {
            write_physical_address(pa, buffer, max);
        }

        size -= max;
        buffer = (char*)buffer + max;
        addr += max;
    }

    mmput(mm);
    put_task_struct(task);
    return true;
}

#endif
