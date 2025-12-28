
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
#include <linux/mmap_lock.h>

// ==========================================
// 1. ПОИСК ФУНКЦИЙ
// ==========================================

typedef int (*valid_phys_addr_range_t)(phys_addr_t addr, size_t size);
typedef long (*probe_kernel_read_t)(void *dst, const void *src, size_t size);
typedef long (*probe_kernel_write_t)(void *dst, const void *src, size_t size);

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
    g_valid_phys_addr_range = (valid_phys_addr_range_t)lookup_symbol("valid_phys_addr_range");
    if (!g_valid_phys_addr_range) {
        g_valid_phys_addr_range = (valid_phys_addr_range_t)lookup_symbol("memblock_is_map_memory");
    }
    
    g_probe_read = (probe_kernel_read_t)lookup_symbol("copy_from_kernel_nofault");
    if (!g_probe_read) g_probe_read = (probe_kernel_read_t)lookup_symbol("probe_kernel_read");

    g_probe_write = (probe_kernel_write_t)lookup_symbol("copy_to_kernel_nofault");
    if (!g_probe_write) g_probe_write = (probe_kernel_write_t)lookup_symbol("probe_kernel_write");

    if (g_valid_phys_addr_range) printk(KERN_INFO "JiangNight: Validation enabled");
}

// ==========================================
// 2. ТРАНСЛЯЦИЯ (С ПРОВЕРКОЙ MMIO)
// ==========================================

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
    // 1. Проход по таблицам страниц
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) return 0;

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return 0;

    pud = pud_offset(p4d, va);
    if(pud_none(*pud) || pud_bad(*pud)) return 0;

    pmd = pmd_offset(pud, va);
    if(pmd_none(*pmd)) return 0;

    pte = pte_offset_kernel(pmd, va);
    
    // 2. Критические проверки (Fix Kernel Panic)
    if(pte_none(*pte) || !pte_present(*pte)) return 0;

    // НЕ ЧИТАТЬ СПЕЦИАЛЬНЫЕ СТРАНИЦЫ (Device Memory / MMIO)
    // Это главная причина крашей при сканировании памяти
    if (pte_special(*pte)) return 0; 
    
    // НЕ ЧИТАТЬ СТРАНИЦЫ УСТРОЙСТВ (GPU и т.д.)
#ifdef pte_devmap
    if (pte_devmap(*pte)) return 0;
#endif

    return (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT) + (va & (PAGE_SIZE - 1));
}

// ==========================================
// 3. БЕЗОПАСНОЕ ЧТЕНИЕ/ЗАПИСЬ
// ==========================================

size_t read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    void* kbuf;
    
    if (g_valid_phys_addr_range && !g_valid_phys_addr_range(pa, size)) return 0;
    if (!g_valid_phys_addr_range && !pfn_valid(__phys_to_pfn(pa))) return 0;

    mapped = (void*)phys_to_virt(pa);
    if (!mapped) return 0;
    if (!g_probe_read) return 0;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) return 0;

    // Чтение в буфер ядра
    if (g_probe_read(kbuf, mapped, size) < 0) {
        kfree(kbuf);
        return 0; 
    }

    // Копирование пользователю
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

    if (g_probe_write(mapped, kbuf, size) < 0) {
        kfree(kbuf);
        return 0;
    }

    kfree(kbuf);
    return size;
}

// ==========================================
// 4. ЦИКЛ ОБРАБОТКИ
// ==========================================

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t chunk_size;
    size_t processed = 0;

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
        chunk_size = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        
        // БЛОКИРОВКА ТОЛЬКО НА МОМЕНТ ТРАНСЛЯЦИИ
        // Это предотвращает дедлоки с copy_to_user
        if (mmap_read_lock_killable(mm)) {
            break; // Если процесс умирает, выходим
        }
        
        pa = translate_linear_address(mm, addr);
        
        mmap_read_unlock(mm); // Сразу разблокируем

        if (pa) {
            if (read_physical_address(pa, buffer, chunk_size) != chunk_size) {
                 // Ошибка чтения физической памяти (но не паника!)
                 if (clear_user(buffer, chunk_size)) { /* ignore */ }
            }
        } else {
            // Страница не загружена или это спец. память
            if (clear_user(buffer, chunk_size)) { /* ignore */ }
        }

        size -= chunk_size;
        buffer = (char*)buffer + chunk_size;
        addr += chunk_size;
        processed += chunk_size;
    }

    mmput(mm);
    put_task_struct(task);
    return true;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t chunk_size;

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
        chunk_size = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));

        if (mmap_read_lock_killable(mm)) break;
        pa = translate_linear_address(mm, addr);
        mmap_read_unlock(mm);

        if (pa) {
            write_physical_address(pa, buffer, chunk_size);
        }

        size -= chunk_size;
        buffer = (char*)buffer + chunk_size;
        addr += chunk_size;
    }

    mmput(mm);
    put_task_struct(task);
    return true;
}

#endif
