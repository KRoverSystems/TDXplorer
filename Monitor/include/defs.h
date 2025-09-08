#pragma once

#include <stdio.h>
#include "configs.h"

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)

/*4 level PT idx masks*/
#define PML4_IDX_SHIFT      39
#define PDPT_IDX_SHIFT      30
#define PD_IDX_SHIFT        21
#define PT_IDX_SHIFT        12
#define PGT_IDX_MASK		0x1ffUL
#define PAGE_ADR_MASK		0xfffffffffffff000
#define VA_TO_PG_VA_MASK    PAGE_ADR_MASK
#define PTE_TO_PA_MASK		0xfffffff000UL
#define LAST_32_BITS		0xffffffffUL

#define PAGE_OFST           0xfffUL

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 9)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)
#define CR4_PKS (1U << 24)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/*debug regs*/
#define DR6_CUR_BP_MASK         0xfUL
#define DR6_SINGLE_STEP_MASK    (1UL << 14)
#define DEBUG_DR0               0UL
#define DEBUG_DR1               1UL
#define DEBUG_DR2               2UL
#define DEBUG_DR3               3UL
#define DR7_CONDITION_DR0       (1UL << 16)
#define DR7_CONDITION_DR1       (1UL << 20)
#define DR7_CONDITION_DR2       (1UL << 24)
#define DR7_CONDITION_DR3       (1UL << 28)
#define DR7_DB_LENGTH_DR0       (1UL << 18)
#define DR7_DB_LENGTH_DR1       (1UL << 22)
#define DR7_DB_LENGTH_DR2       (1UL << 26)
#define DR7_DB_LENGTH_DR3       (1UL << 30)
#define DB_CONDITION_INS_EXEC   0b00
#define DB_CONDITION_DATA_WR    0b01
#define DB_CONDITION_DATA_RDWR  0b11   /*not ins fetches*/
#define DB_LENGTH_1_BYTE        0b00
#define DB_LENGTH_2_BYTE        0b01
#define DB_LENGTH_8_BYTE        0b10  /*Only defined for some intel processors*/
#define DB_LENGTH_4_BYTE        0b11


#define CANONICAL_ADDRESS_MASK 0xffff800000000000UL

/*for x2apic*/
#define X2APIC_ENABLE (1UL << 10) | (1UL << 11)

#define UNUSED(...)

#define LOG_ON
#ifdef LOG_ON
    // #define LOG(...) printf(__VA_ARGS__)
    // #define LOG(f, ...)
	#define LOGR(...) printf("R-MGR: " __VA_ARGS__)
	#define LOGSEAM(...) printf("SEAM: " __VA_ARGS__)
    // #define SELOG(...) printf("SE: " __VA_ARGS__)
#else
    #define LOG(f, ...)
    // #define SELOG(f,...)
#endif

#if TURN_ON_MONITOR_LOGS == 1
    #define LOG(...) printf(__VA_ARGS__)
#else
    #define LOG(...)
#endif

#if TURN_ON_NP_SEAMLDR_LOGS == 1
    #define NPLOG(...) printf(__VA_ARGS__)
#else
    #define NPLOG(...)
#endif

#if TURN_ON_INTERPRETER_MGR_LOGS == 1
    #define SELOG(...) printf("SE: " __VA_ARGS__)
#else
    #define SELOG(...)
#endif

#if TURN_ON_TDXCALL_LOGS == 1
    #define TDXCALL_LOG(...) printf(__VA_ARGS__)
#else
    #define TDXCALL_LOG(...)
#endif
