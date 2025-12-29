#ifndef _COMM_H
#define _COMM_H

#include <linux/types.h>

#define OP_INIT_KEY          0x800
#define OP_READ_MEM          0x801
#define OP_WRITE_MEM         0x802
#define OP_MODULE_BASE       0x803
#define OP_HIDE_PROCESS      0x804
#define OP_PID_HIDE_PROCESS  0x805
#define OP_GET_PROCESS_PID   0x806
// Новый код операции
#define OP_SET_HW_BP         0x807 
#define OP_DEL_HW_BP         0x808

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

struct process {
    pid_t process_pid;
    char process_comm[0x100];
};

// Структура для брейкпоинта
typedef struct _HW_BP {
    pid_t pid;
    uintptr_t addr;     // Адрес, где ставим брейкпоинт
    int type;           // 0 = Execute, 1 = Write (Watchpoint), 2 = Read/Write
    size_t len;         // Длина (обычно 4 байта)
} HW_BP;

#endif
