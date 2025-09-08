
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "common.h"
#include "defs.h"
#include "seam.h"
#include "interpreter_manager.h"
#include "configs.h"
#include "../../KernelHelper/kernel_agent.h"
#include "../../Interpreter/interpreterAPI.h"


void lfence(){
	asm volatile("lfence; \n\t");
}

void launch_interpreter();
extern struct comArea *com;

/*only use vm->mem, which is the base address of seam env
vm->mem refers to seam pa 0*/
struct vm *vm; 

extern ulong get_region_base_pa(REGION region);

/*for kernel agents use*/
struct s_adr seam_adr[TDXMODULE_MAPPED_PAGE_COUNT];

uint64_t *seam_pa_to_hva(uint64_t pa){
    return (uint64_t *)(pa + (uint64_t)vm->mem);
}

uint64_t idx_to_va(uint64_t pml4_idx, uint64_t pdpt_idx, uint64_t pd_idx, uint64_t pt_idx, uint64_t page_size){
    
    uint64_t va;

    if(page_size == PAGE_SIZE_2M){
        va = (pml4_idx << PML4_IDX_SHIFT) | (pdpt_idx << PDPT_IDX_SHIFT) | (pd_idx << PD_IDX_SHIFT);
    }
    else{
        va = (pml4_idx << PML4_IDX_SHIFT) | (pdpt_idx << PDPT_IDX_SHIFT) | (pd_idx << PD_IDX_SHIFT) | (pt_idx << PT_IDX_SHIFT);
    }

    if(pml4_idx > 255){
        va |= CANONICAL_ADDRESS_MASK;
    }

    return va;    
}

int update_seam_adr_buf(){
    uint64_t *pml4, *pdpt, *pd, *pt;
    uint64_t pg_pa, page_count, pml4_idx, pdpt_idx, pd_idx, pt_idx;
    
    pg_pa = get_region_base_pa(RGN_PML4);
    /*pg_pa = SEAM_AGENT_PT_BASE_PA; use this if Agent needes to be analyzed by the interpreter*/
    pml4 = seam_pa_to_hva(pg_pa);
    SELOG("TDX Mod pml4 pa: %lx hva:%lx\n", (ulong)pg_pa, (ulong)pml4);

    page_count = 0;
    pml4_idx = 0;
    while(pml4_idx < 512){
        /*SELOG("pml4 idx: %lu\n", pml4_idx);*/
        if(pml4[pml4_idx] & PDE64_PRESENT){ /*pml4 entry is present*/
            /* SELOG("PML4_IDX:%lu present\n", pml4_idx);*/
            pg_pa = pml4[pml4_idx] & PTE_TO_PA_MASK;
            pdpt = seam_pa_to_hva(pg_pa);

            pdpt_idx = 0;
            while(pdpt_idx < 512){
                if(pdpt[pdpt_idx] & PDE64_PRESENT){ /*pdpt entry is present*/
                    /*SELOG("PDPT_IDX:%lu present\n", pdpt_idx);*/
                    pg_pa = pdpt[pdpt_idx] & PTE_TO_PA_MASK;
                    pd = seam_pa_to_hva(pg_pa);

                    pd_idx = 0;
                    while(pd_idx < 512){
                        if(pd[pd_idx] & PDE64_PRESENT){
                            /*SELOG("PD_IDX:%lu present\n", pd_idx);*/
                            if(pd[pd_idx] & PDE64_PS){ /*2M page*/
                                /*lets drop 2M pages, these are from P-SEAM-Loader's mappings*/
                            }
                            else{
                                pg_pa = pd[pd_idx] & PTE_TO_PA_MASK;
                                pt = seam_pa_to_hva(pg_pa);

                                pt_idx = 0;
                                while(pt_idx < 512){
                                    if(pt[pt_idx] & PDE64_PRESENT){
                                        /*SELOG("PT_IDX:%lu present\n", pt_idx);*/
                                        pg_pa = pt[pt_idx] & PTE_TO_PA_MASK;
                                        seam_adr[page_count].page_size = PAGE_SIZE_4K;
                                        seam_adr[page_count].seam_va = idx_to_va(pml4_idx, pdpt_idx, pd_idx, pt_idx, PAGE_SIZE_4K);
                                        seam_adr[page_count].host_va = (ulong)seam_pa_to_hva(pg_pa);
                                        /*SELOG("pa: %lx\n", pg_pa);*/
                                        /*SELOG("pg: %lu seam va: %lx host va: %lx page size: 4K\n", page_count, seam_adr[page_count].seam_va, seam_adr[page_count].host_va);*/
                                        page_count++;
                                    }
                                    pt_idx++;
                                }
                            }
                        }
                        pd_idx++;
                    }
                }
                pdpt_idx++;
            }
        }
        pml4_idx++;
    }
    if(page_count >= TDXMODULE_MAPPED_PAGE_COUNT){
        SELOG("seam_adr buffer to overflow. Increase TDXMODULE_MAPPED_PAGE_COUNT to be : %lu\n", page_count + 1);
        exit(0);
    }
    SELOG("page_count: %lu \n", page_count);
    SELOG("struct s_adr sz: %lu size of seam_adr: %lu\n", sizeof(struct s_adr), sizeof(seam_adr));

    return 0;
}

void get_seam_env_mappings(){

    int fd, status;
    
    update_seam_adr_buf();
    fd = open("/dev/kernel_agent_device", O_RDWR);
    if(fd < 0){
        SELOG("kernel_agent_device open ERROR ...");
        exit(0);
    }

    SELOG("seam_adr struct buffer adr: %lx\n", (ulong)&seam_adr);
    status = ioctl(fd, IOCTL_UPDATE_PT, &seam_adr);
    if(status < 0){
        SELOG("kernel_agent_device ioctl ERROR ...");
        close(fd);
        exit(0);
    }
    SELOG("ioctl IOCTL_UPDATE_PT success\n");
    close(fd);
}

void launch_interpreter(){

	SELOG("krover_manager's wait for tdx module install: START\n");
    while(true){
        
        if(com->current_sw == SEAM_SW_TDXMODULE)
            break;
    }
    SELOG("krover_manager's wait for tdx module install: END\n");
    get_seam_env_mappings();

    com->se.interpreter_pt_updates_done = true; /*seam manager should wait for this flag before running tdx module*/


    /*do tdx platform init before dispatching to Interpreter
    */
    while(true){
        if(com->seam_state == SE_START_SEAM_STATE)
            break;
    }

    interpreterStart();
}