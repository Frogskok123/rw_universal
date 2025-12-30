// comm.h
#ifndef _COMM_H
#define _COMM_H

#include <linux/types.h>

#define OP_INIT_KEY 0x800
#define OP_READ_MEM 0x801
#define OP_WRITE_MEM 0x802
#define OP_MODULE_BASE 0x803
#define OP_HIDE_PROCESS 0x804
#define OP_PID_HIDE_PROCESS 0x805
#define OP_GET_PROCESS_PID 0x806

// Улучшенные опкоды для дебаггера
#define OP_SET_HW_BP 0x807
#define OP_DEL_HW_BP 0x808
#define OP_GET_DEBUG_EVENT 0x809 // Получить событие (срабатывание BP)
#define OP_GYRO_MOVE  0x810 // Или любой свободный номер
// Типы брейкпоинтов
#define BP_TYPE_EXEC  0
#define BP_TYPE_WRITE 1
#define BP_TYPE_RW    2

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

// Аргументы для установки/удаления BP
typedef struct _HW_BP {
    pid_t pid;
    uintptr_t addr;
    int type;     // 0=Exec, 1=Write, 2=RW
    size_t len;   // Обычно 4
} HW_BP;

// Структура события отладки (snapshot регистров)
typedef struct _DEBUG_EVENT {
    pid_t pid;
    uintptr_t pc;       // Program Counter
    uintptr_t sp;       // Stack Pointer
    uintptr_t pstate;   // CPSR/PSTATE
    uintptr_t regs[31]; // X0-X30 для ARM64
    uintptr_t fault_addr; // Адрес, к которому был доступ (для Watchpoint)
} DEBUG_EVENT;
// В enum OPERATIONS добавь:


// Добавь структуру для передачи данных:
// comm.h
struct GyroData {
    int x; // float * 100
    int y; // float * 100
};
#endif
