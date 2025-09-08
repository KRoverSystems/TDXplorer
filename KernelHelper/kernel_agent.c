#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/kconfig.h>

#include <asm/cpufeature.h>
#include <linux/sched.h>
#include <linux/mm.h>        
#include <asm/pgtable.h>
#include <linux/highmem.h>

#include <linux/gfp.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/highmem.h>

#include "kernel_agent.h"
#include "kdefs.h"

typedef unsigned long ulong;

static struct s_adr seam_adr_k[TDXMODULE_MAPPED_PAGE_COUNT];

unsigned long read_int3(void){
    unsigned long cr3_val = 0;

    asm volatile("movq %%cr3, %0; \n\t"
                :"=r"(cr3_val)::);
    return cr3_val;
}

#ifdef PRINT_USER_PML4_AT_END
static void print_pml4(ulong *pml4){

    int idx;

    LOG("Printing pml4 entries present...");
    idx = 0;
    while(idx < 512){
        if(pml4[idx] & PDE64_PRESENT){
            LOG("idx: %03d value: %lx\n", idx, pml4[idx]);
        }
        idx++;
    }
}
#endif

static ulong do_seam_va_sanity_checks(ulong * pml4){
    ulong count, pml4_idx;

    count = 0;
    while((seam_adr_k[count].seam_va != 0) && (count < TDXMODULE_MAPPED_PAGE_COUNT)){
    
        if(seam_adr_k[count].page_size == PG_SIZE_2M){
            LOG("Currently we do not handle 2M pages, seam_va: %lx\n", seam_adr_k[count].seam_va);
            return 0;
        }

        /*checking for address space overlaps*/
        pml4_idx = (seam_adr_k[count].seam_va >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
        if(pml4[pml4_idx] & PDE64_PRESENT){
            LOG("PML4 idx: %lu already present in user PTs\n", pml4_idx);
            return 0;
        }
        count++;
    }
    return count;

}

/*
static ulong *pa_to_va(ulong pa){

    unsigned pfn;
    struct page *pg;
    ulong *ptr;

    pfn = pa >> 12;
    pg = pfn_to_page(pfn);
    ptr = (ulong *)kmap_atomic(pg);

    return ptr;
}

static void pa_to_va_free(void *va){
    kunmap_atomic(va);
}*/

/*Working, but we are using the shorter vertion using kernel's inbuilt functions
static ulong get_physical_address(ulong *pml4, ulong va, ulong page_size){

    ulong *pdpt, *pd, *pt, pg_sz;
    ulong pml4_idx, pdpt_idx, pd_idx, pt_idx;
    ulong page_pa = 0;

    pml4_idx = (va >> PML4_IDX_SHIFT) & PGT_IDX_MASK;
    if(pml4[pml4_idx] & PDE64_PRESENT){ 
        pdpt = (ulong *)phys_to_virt(pml4[pml4_idx] & PTE_TO_PA_MASK);
        LOG("pdpt: %lx\n", (ulong)pdpt);
    }
    else{
        LOG("pml4 entry, not present for host va translation, va: %lx\n", va);
        return 0;
    }

    pdpt_idx = (va >> PDPT_IDX_SHIFT) & PGT_IDX_MASK;
    if(pdpt[pdpt_idx] & PDE64_PRESENT){
        pd = (ulong *)phys_to_virt(pdpt[pdpt_idx] & PTE_TO_PA_MASK);
        LOG("pd: %lx\n", (ulong)pd);
    }
    else{
        LOG("pdpt entry, not present for host va translation, va: %lx\n", va);
        return 0;
    }

    pd_idx = (va >> PD_IDX_SHIFT) & PGT_IDX_MASK;
    if(pd[pdpt_idx] & PDE64_PRESENT){
        if((page_size == PG_SIZE_2M) & (pd[pd_idx] & PDE64_PS)){
            LOG("Currenty we do not handle 2M pages\n");
            return 0;
        }
        pt = (ulong *)phys_to_virt(pd[pd_idx] & PTE_TO_PA_MASK);
        LOG("pt: %lx\n", (ulong)pt);
    }
    else{
        LOG("pd entry, not present for host va translation, va: %lx\n", va);
        return 0;
    }

    pt_idx = (va >> PT_IDX_SHIFT) & PGT_IDX_MASK;
    if(pt[pt_idx] & PDE64_PRESENT){
        page_pa = pt[pt_idx] & PTE_TO_PA_MASK;
        // page_pa = (ulong *)phys_to_virt(pt[pt_idx] & PTE_TO_PA_MASK);
        LOG("page_pa: %lx\n", page_pa);
    }
    else{
        LOG("pt entry, not present for host va translation, va: %lx\n", va);
        return 0;
    }

    return page_pa;
}*/

static unsigned long get_physical_address(ulong user_address)
{
    struct page *page;
    unsigned long phys_addr = 0;
    int ret;

    /*get_user_pages_fast() function provides the physical pages from user-space 
    virtual addresses. 
    The pages are pinned, meaning the kernel will ensure they remain in physical 
    memory for the duration of the operation. This prevents the memory from 
    being swapped out or otherwise moved. The function returns a reference to 
    the pages, and we should manage this reference correctly. If we pin a page, 
    we need to release it later using put_page() to decrement the reference 
    count and allow it to be swapped out or freed if necessary*/
    ret = get_user_pages_fast(user_address, 1, FOLL_WRITE, &page);
    if (ret > 0) {
        phys_addr = page_to_phys(page) + (user_address & ~PAGE_MASK);
        put_page(page); /*this is essential to unpin the page.*/
    }

    return phys_addr;
}

static ulong *update_pgt(ulong *pgt, ulong idx){
        
        ulong *next_pgt, next_pgt_pa;
        struct page *pg;

        if(pgt[idx] & PDE64_PRESENT){ /*if entry is present, use the existing next level PGT*/
            next_pgt_pa = pgt[idx] & PTE_TO_PA_MASK;
            next_pgt = (ulong *)phys_to_virt(next_pgt_pa);
            LOGD("next level pgt pa: %lx\n", next_pgt_pa);
            LOGD("next level pgt :%lx\n", (ulong)next_pgt);
        }
        else{ /*if entry is not present, allocate next level PGT*/
            LOGD("allocating new pg\n");
            pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
            if(!pg){
                LOG("alloc_page for pgt error");
                return 0;
            }
            next_pgt_pa = page_to_phys(pg);
            next_pgt = page_address(pg);
            LOGD("next level pgt pa: %lx\n", next_pgt_pa);
            LOGD("next level pgt :%lx\n", (ulong)next_pgt);

		    pgt[idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | next_pgt_pa;
        }

        return next_pgt;
}

static int update_page_tables(ulong arg){

    ulong *pml4_kernel_va, pml4_kernel_pa, pml4_user_pa;
    ulong user_data_size, seam_adr_count;
    ulong pml4_idx, pdpt_idx, pd_idx, pt_idx;
    ulong *pml4, *pdpt, *pd, *pt;
    ulong seam_va, page_pa, seam_pg_count;

    printk("\n");
    LOG("IOCTL_UPDATE_PT, RECEIVED ...\n");
    LOG("task name\t\t: %s\n", current->comm);

    pml4_kernel_pa = read_int3() & PA_TO_PAGE_ADR_MASK;
    pml4_user_pa = pml4_kernel_pa | CR3_KERNEL_TO_USER_MASK;

    pml4_kernel_va  = phys_to_virt(pml4_kernel_pa);
    pml4 = phys_to_virt(pml4_user_pa);
    LOG("cr3_kernel\t\t: %lx\n", pml4_kernel_pa);
    LOG("cr3_user\t\t: %lx\n", pml4_user_pa);
    LOG("pml4_kernel_va\t: %lx\n", (ulong)pml4_kernel_va);
    LOG("pml4_user_va\t\t: %lx\n", (ulong)pml4);

    user_data_size = sizeof(seam_adr_k);
    LOG("ioctl arg\t\t: %lx\n", arg);
    LOG("user data size\t: 0x%lx\n", user_data_size);
    /*copy_from_user returns the number of bytes it could not copy. So at success : return 0*/
    if(copy_from_user((void *)seam_adr_k, (const void __user *)arg, user_data_size)){
        LOG("copy_from_user ERR\n");
        return -1;
    }
    LOG("copy_from_user \t: SUCCESS\n");

    seam_pg_count = do_seam_va_sanity_checks(pml4);
    if(seam_pg_count == 0 || seam_pg_count >= TDXMODULE_MAPPED_PAGE_COUNT){
        LOG("do_seam_va_sanity_checks Failed\n");
        return -1;
    }
    LOG("seam_pg_count\t: %lu\n", seam_pg_count);

    seam_adr_count = 0;
    while(seam_adr_count < seam_pg_count){

        seam_va = seam_adr_k[seam_adr_count].seam_va;
        page_pa = get_physical_address(seam_adr_k[seam_adr_count].host_va);
        if(!page_pa){
            LOG("PT translation error\n");
            return -1;
        }
        LOGD("%03lu seam va %03lu: %lx -----------------------------------------\n",seam_adr_count, seam_va);

        pml4_idx = (seam_va >> PML4_IDX_SHIFT) & (PGT_IDX_MASK);
        LOGD("pml4_idx: %lu", pml4_idx);
        pdpt = update_pgt(pml4, pml4_idx);
        if(!pdpt){
            return -1;
        }

        pdpt_idx = (seam_va >> PDPT_IDX_SHIFT) & (PGT_IDX_MASK);
        LOGD("pdpt_idx: %lu\n", pdpt_idx);
        pd  = update_pgt(pdpt, pdpt_idx);
        if(!pd){
            return -1;
        }

        pd_idx  = (seam_va >> PD_IDX_SHIFT) & (PGT_IDX_MASK);
        LOGD("pd_idx: %lu\n", pd_idx);
        pt  = update_pgt(pd, pd_idx);
        if(!pt){
            return -1;
        }

        pt_idx  = (seam_va >> PT_IDX_SHIFT) & (PGT_IDX_MASK);
        if(pt[pt_idx] & PDE64_PRESENT){
            LOG("pt entry is present, ERROR\n");
            return -1;
        }
        pt[pt_idx] = PDE64_PRESENT | PDE64_RW | PDE64_USER | page_pa;

        seam_adr_count++;
    }

#ifdef PRINT_USER_PML4_AT_END
    LOG("print user pml4 after PT updates\n");
    print_pml4(pml4);
#endif

    return 0;
}

static long ioctl_handler(struct file *file, unsigned int ioctl_command, unsigned long arg){

    switch (ioctl_command) {
        case IOCTL_UPDATE_PT:{
            if(update_page_tables(arg) != 0){
                return -EINVAL;
            }
            LOG("IOCTL_UPDATE_PT\t: SUCCESS\n");
        } break;
        default: {
            return -EINVAL;
        }
    }
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = ioctl_handler,
};

static struct miscdevice kernel_agent_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name   = "kernel_agent_device",
    .fops   = &fops,
};

static int __init agent_init(void){

    int status;

    /*check if PTI is enabled for the kernel dung compilation*/
    if(IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION)){
        printk("\n");
        LOG("CONFIG_PAGE_TABLE_ISOLATION is enabled.\n");

        /*Check if the Page Table Isolation is turned on at boot time and is effective*/
        if (boot_cpu_has(X86_FEATURE_PTI)) {
            LOG("PTI is turned on.\n");
        } else {
            LOG("PTI is not turned on. set command line boot parameter pti=on\n");
            return -1;
        }
    }
    else{
        LOG("CONFIG_PAGE_TABLE_ISOLATION is not enabled, recompile the kernel with the config enabled.\n");
        return -1;
    }

    /*register a new character device*/
    status = misc_register(&kernel_agent_device);
    if(status){
        LOG("unable to register kernel_agent_device");
        return status;
    }

    LOG("kernel_agent loaded\n");
    return 0;
}

static void __exit agent_exit(void){

    misc_deregister(&kernel_agent_device);
    LOG("kernel agent unloaded\n");
}

module_init(agent_init);
module_exit(agent_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TDXplorer");
MODULE_DESCRIPTION(
    "This module exposes an ioctl() to user space. Upon the request of the user    "
    "process, agent will update the PTs of the user process to provide mappings    "
    "for a given list of VAs provided in ioctl() arguments.                        "
    ""
    "Usage: Include the kernel_agent.h and implement the user space ioctl() issuer."
    "ioctl(fd, IOCTL_UPDATE_PT, struct s_adr *buffer);                             "
    "buffer of type s_adr to be prepared by user space                             "
);
