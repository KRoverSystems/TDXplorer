
#ifndef __KDEFS_H
#define __KDEFS_H

/* 64-bit page * entry bits */
#define PDE64_PRESENT       1
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
#define PTE_TO_PA_MASK		0xfffffff000UL
#define LAST_32_BITS		0xffffffffUL

#define PG_SIZE_4K          0x1000UL
#define PG_SIZE_2M          0x200000UL


#define PA_TO_PAGE_ADR_MASK     0xfffffffffffff000UL
#define CR3_KERNEL_TO_USER_MASK 0x1000UL /*If the 12th bit is clear, kernel CR3. Add the mask to get user CR3*/

#define LOG_ON
#ifdef LOG_ON
    #define LOG(...) printk("kernel_agent: " __VA_ARGS__)
#else
    #define LOG(f, ...)
#endif

/*#define LOG_DEBUG_ON*/
#ifdef LOG_DEBUG_ON
    #define LOGD(...) printk("kernel_agent: " __VA_ARGS__)
#else
    #define LOGD(f, ...)
#endif

/*#define PRINT_USER_PML4_AT_END*/


#endif
