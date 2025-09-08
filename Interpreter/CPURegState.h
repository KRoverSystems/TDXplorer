#ifndef __CPU_REG_STATE_H__
#define __CPU_REG_STATE_H__

#include <asm/ptrace.h>

struct MacReg {
    struct pt_regs regs;
    unsigned long fs_base;
    unsigned long gs_base;
    //for %ds %es
    unsigned long ds_base;
    unsigned long es_base;
};

#endif  // !__CPU_REG_STATE_H__
