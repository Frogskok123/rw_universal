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

// --- KPROBES & VALIDATION ---

typedef int (*valid_phys_addr_range_t)(phys_addr_t addr, size_t size);
static valid_phys_addr_range_t g_valid_phys_addr_range = NULL;

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
    if (g_valid_phys_addr_range) {
        printk(KERN_INFO "JiangNight: Validation function found at %p
", g_valid_phys_addr_range);
    }
}

// --- TRANSLATION ---

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

// --- SAFE R/W OPERATIONS ---

size_t read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    void* kbuf;
    
    // 1. Validate Address
    if (g_valid_phys_addr_range) {
        if (!g_valid_phys_addr_range(pa, size)) return 0;
    } else {
        if (!pfn_valid(__phys_to_pfn(pa))) return 0;
    }

    // 2. Map (phys_to_virt is safer for RAM than ioremap)
    mapped = (void*)phys_to_virt(pa);
    if (!mapped) return 0;

    // 3. Allocate Temp Buffer (Never copy directly to user from unsafe source)
    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) return 0;

    // 4. Safe Copy from Kernel Memory (Prevents Panic)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    if (copy_from_kernel_nofault(kbuf, mapped, size) < 0) {
#else
    if (probe_kernel_read(kbuf, mapped, size) < 0) {
#endif
        kfree(kbuf);
        return 0; 
    }

    // 5. Copy to User
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

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) return 0;

    if (copy_from_user(kbuf, buffer, size)) {
        kfree(kbuf);
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    if (copy_to_kernel_nofault(mapped, kbuf, size) < 0) {
#else
    if (probe_kernel_write(mapped, kbuf, size) < 0) {
#endif
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
    size_t count = 0;

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
            count = read_physical_address(pa, buffer, max);
        } else {
            // Fill with zeros if page not mapped to avoid offset drift
            if (clear_user(buffer, max)) { /* ignore error */ }
        }

        size -= max;
        buffer = (char*)buffer + max; // Fix pointer arithmetic
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
