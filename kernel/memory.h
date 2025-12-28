#ifndef _MEMORY_H
#define _MEMORY_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h> // Добавлено для lookup_symbol

// ==========================================
// СЕКЦИЯ ПОИСКА СКРЫТЫХ СИМВОЛОВ (KPROBES)
// ==========================================

// Определение типа функции valid_phys_addr_range
typedef int (*valid_phys_addr_range_t)(phys_addr_t addr, size_t size);
static valid_phys_addr_range_t g_valid_phys_addr_range = NULL;

// Функция для поиска адреса символа по имени
static unsigned long lookup_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    
    if (register_kprobe(&kp) < 0) {
        return 0;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

// Эту функцию нужно вызвать в driver_entry (в entry.c)
bool resolve_kernel_symbols(void) {
    g_valid_phys_addr_range = (valid_phys_addr_range_t)lookup_symbol("valid_phys_addr_range");
    if (g_valid_phys_addr_range) {
        printk(KERN_INFO "JiangNight: valid_phys_addr_range found at %p", g_valid_phys_addr_range);
    } else {
        printk(KERN_WARNING "JiangNight: valid_phys_addr_range NOT found, falling back to pfn_valid");
    }
    return true;
}

// ==========================================
// ТРАНСЛЯЦИЯ АДРЕСОВ И ЧТЕНИЕ/ЗАПИСЬ
// ==========================================

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
    phys_addr_t page_addr;
    uintptr_t page_offset;

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

    // Получаем физический адрес страницы и добавляем смещение
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);

    return page_addr + page_offset;
}

size_t read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    // 1. Проверка валидности физического адреса
    if (g_valid_phys_addr_range) {
        // Если нашли функцию проверки, используем её (более надежно)
        if (!g_valid_phys_addr_range(pa, size)) return 0;
    } else {
        // Фолбэк на pfn_valid
        if (!pfn_valid(__phys_to_pfn(pa))) return 0;
    }

    // 2. ИСПРАВЛЕНИЕ: Используем phys_to_virt для RAM вместо ioremap
    // ioremap часто падает на Android GKI при попытке чтения системной памяти
    mapped = (void*)phys_to_virt(pa);
    
    if (!mapped) return 0;

    if(copy_to_user(buffer, mapped, size)) {
        return 0;
    }

    return size;
}

size_t write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    if (g_valid_phys_addr_range) {
        if (!g_valid_phys_addr_range(pa, size)) return 0;
    } else {
        if (!pfn_valid(__phys_to_pfn(pa))) return 0;
    }

    // ИСПРАВЛЕНИЕ: phys_to_virt вместо ioremap
    mapped = (void*)phys_to_virt(pa);
    
    if (!mapped) return 0;

    if(copy_from_user(mapped, buffer, size)) {
        return 0;
    }

    return size;
}

// Функция чтения памяти процесса
bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) return false;

    mm = get_task_mm(task);
    if (!mm) return false;

    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        
        // Сколько байт можно прочитать в пределах одной страницы
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));

        if (!pa) {
            // Если адрес не транслируется, пропускаем блок (заполняем нулями или просто идем дальше)
            // Но лучше прервать или записать 0 в буфер пользователя, чтобы не сдвигать смещения
            if (clear_user(buffer, max)) {
                 // ошибка очистки буфера
            }
        } else {
            count = read_physical_address(pa, buffer, max);
        }

        size -= max;
        buffer += max;
        addr += max;
    }

    mmput(mm);
    return true;
}

// Функция записи памяти процесса
bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) return false;

    mm = get_task_mm(task);
    if (!mm) return false;

    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));

        if (pa) {
            count = write_physical_address(pa, buffer, max);
        }

        size -= max;
        buffer += max;
        addr += max;
    }

    mmput(mm);
    return true;
}

#endif // _MEMORY_H
