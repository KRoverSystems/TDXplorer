
#include <linux/kvm.h>
#include <stdlib.h>
#include <string.h>

#include "analyzer.h"
#include "vmm_agent.h"
#include "td_agent.h"
#include "state.h"
#include "defs.h"

extern struct comArea *com;
extern ulong td_0_created;
extern void fill_khole_refs(ulong lp);

static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo | ((unsigned long long) hi << 32));
}

void analyzer_function(){

    struct kvm_regs regs;
    ulong ret, page_pa;
    ulong t_0 = 0;
    ulong t_1 = 0;

    com->sreq.is_td_call = -1;
    com->sreq.tdx_call_number = -1;

#ifdef IN_SINGLE_CALL_TESTS
    char c;
    ulong num;

    LOG("\nanalyzer function start\n");
    LOG("enter the TDX call number: ");

    if(scanf(" %c%ld", &c, &num) == 2) {
        if((c == 's') || (c == 'S')){
            com->sreq.is_td_call = 0;
        }
        else if((c == 't') || (c == 'T')){
            com->sreq.is_td_call = 1;
        }
        else {
            printf("Invalid input format.\n");
            exit(0);    
        }

        com->sreq.tdx_call_number = num;
    } else {
        printf("Invalid input format.\n");
        exit(0);
    }
#endif
    
#ifdef MEASURE_PLATFORM_INIT_TIME_AND_STOP
	LOG("\ninit platform, start");
    t_0 = rdtsc();
#endif;
    init_tdx_module();

#ifdef MEASURE_PLATFORM_INIT_TIME_AND_STOP
    t_1 = rdtsc();
	LOG("\ntdx platform init, completed\n");
	LOG("\nplatform init, time cost: %lu\n", (t_1 - t_0));
	exit(0);
#endif;

#if DO_ARTF_TEST1 == 1

    ulong keyid, tdr;

#if TURN_ON_ARTF_TEST1_SYM_ANALYSIS == 1
    
    LOG("Faithfullness test1: symbolic analysis\n");

    com->sreq.is_td_call = -1;
    com->sreq.tdx_call_number = TDH_MNG_CREATE;
	tdr = reserve_and_get_tdmr_next_avl_pa(TD_0, TDX_GLOBAL_PRIVATE_HKID,TDX_MOD);
	keyid = reserve_and_get_next_available_hkid();
	com->td[TD_0].tdr = tdr;
	com->td[TD_0].hkid = keyid;
    start_se();

	if(tdh_mng_create(LP_0, tdr, keyid) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_CREATE Failed\n");
		exit(0);
	}

#elif TURN_ON_ARTF_TEST1_REPLAY == 1

    LOG("\n\nFaithfullness test1: replay on TDXplorer --------------------------------\n");

    tdr = reserve_and_get_tdmr_next_avl_pa(TD_0, TDX_GLOBAL_PRIVATE_HKID,TDX_MOD);
	
    //fail path replay, alpha = 32 (Keyid = 32)
    LOG("\nfail path replay 1, alpha = 32 (Keyid = 32)\n");
    keyid = 32;
	com->td[TD_0].tdr = tdr;
	com->td[TD_0].hkid = keyid;
	if(tdh_mng_create(LP_0, tdr, keyid) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_CREATE Failed\n");
	}

    //failpath replay, alpha = 0x8000 (Keyid = 0x8000)
    LOG("\nfail path replay 2, alpha = 0x8000 (Keyid = 0x8000)\n");
    keyid = 0x8000;
	com->td[TD_0].tdr = tdr;
	com->td[TD_0].hkid = keyid;
	if(tdh_mng_create(LP_0, tdr, keyid) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_CREATE Failed\n");
	}

    //success path replay, alpha = 32 (Keyid = 32)
    LOG("\nsuccess path replay, alpha = 33 (Keyid = 33)\n");
    keyid = 33;
	com->td[TD_0].tdr = tdr;
	com->td[TD_0].hkid = keyid;
	if(tdh_mng_create(LP_0, tdr, keyid) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_CREATE Failed\n");
	}

#endif

    exit(0);
#endif

#ifdef MEASURE_TD_BUILD_TIME_AND_STOP
    LOG("\n\nTD creation and build sequence, start\n");
    t_0 = rdtsc();
#endif
    create_td(TD_0, LP_0, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);
#ifdef MEASURE_TD_BUILD_TIME_AND_STOP
    t_1 = rdtsc();
    LOG("TD creation and build sequence, completed\n\n");
    LOG("TD creation and build, time cost: %lu\n\n", (t_1 - t_0));
    exit(0);
#endif

#ifdef ENABLE_SERVTD_BINDING
	td_0_created = 1;
#endif
    create_td(TD_1, LP_1, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);

#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_VP_RD){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td[TD_0].tdvpr;
    regs.rdx = -1;
    regs.rax = TDH_VP_RD | (1UL << 16);
    do_seamcall(LP_0, &regs);
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_VP_RD){
				exit(0);
			}
		}
#endif

    run_td(TD_0, com->td[TD_0].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_0].vcpu_associated_lp] = TD_0;

	com->sreq.td_running = 1;
	run_td(TD_1, com->td[TD_1].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_1].vcpu_associated_lp] = TD_1;

#ifdef IN_MEMORY_TEST
    com->sreq.is_td_call = 1;
    com->sreq.tdx_call_number = TDG_MEM_PAGE_ATTR_WR;
    fill_khole_refs(LP_0);
    start_se();
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0; //(1UL << 48);; /*GPA*/
    regs.rdx = 0;
    regs.r8 = 0;
    regs.rax = TDG_MEM_PAGE_ATTR_WR;
    do_tdcall(LP_0, &regs);

    exit(0);
#endif

    page_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    ret = tdh_mem_sept_add(LP_2, (1UL << 48), SEPT_LVL_4, com->td[TD_0].tdr, page_pa);
    ulong lp = LP_0;
#ifdef IN_SINGLE_CALL_TESTS
    if(com->sreq.is_td_call == 1){
        if(com->sreq.tdx_call_number == TDG_MEM_PAGE_ATTR_RD){
        #ifdef IN_SE_MODE
            start_se();
            fill_khole_refs(lp); //for symbol address
        #endif
        }
    }
#endif 
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rax = TDG_MEM_PAGE_ATTR_RD;
    regs.rcx = 0;
    do_tdcall(lp, &regs);
#ifdef IN_SINGLE_CALL_TESTS
    if(com->sreq.is_td_call == 1){
        if(com->sreq.tdx_call_number == TDG_MEM_PAGE_ATTR_RD){
            exit(0);
        }
    }
#endif

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    ulong field_id = 0x9110000300000010;
    ulong data = 0x1;
    ulong write_mask = 0x1;
    regs.rax = TDG_VM_WR;
    regs.rdx = field_id;
    regs.r8 = data;
    regs.r9 = write_mask;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rax = TDG_VP_INFO;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td_mem.next_td_page_gpa;
    regs.rdx = 0;
    regs.rax = TDG_MR_RTMR_EXTEND;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rax = TDG_VP_VEINFO_GET;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 3;
    regs.rax = TDG_VP_CPUIDVE_SET;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = _4K*TD_INITIAL_PAGE_COUNT;
    regs.rdx = com->td[TD_0].tdr;
    regs.r8 = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    regs.rax = TDH_MEM_PAGE_AUG;
    do_seamcall(LP_2, &regs);

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call == 1){
		if(com->sreq.tdx_call_number == TDG_MEM_PAGE_ACCEPT){
		#ifdef IN_SE_MODE
			start_se();
            fill_khole_refs(LP_0);
		#endif
		}
	}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = _4K*TD_INITIAL_PAGE_COUNT;
    regs.rax = TDG_MEM_PAGE_ACCEPT;
    do_tdcall(LP_0, &regs);
#ifdef IN_SINGLE_CALL_TESTS
    if(com->sreq.is_td_call == 1){
        if(com->sreq.tdx_call_number == TDG_MEM_PAGE_ACCEPT){
            exit(0);
        }
    }
#endif

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call == 1){
		if(com->sreq.tdx_call_number == TDG_VM_RD){
		#ifdef IN_SE_MODE
			start_se();
            fill_khole_refs(LP_0);
		#endif
		}
	}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0;
    regs.rdx = -1;
    regs.rax = TDG_VM_RD | (1UL << 16);
    do_tdcall(LP_0, &regs);
#ifdef IN_SINGLE_CALL_TESTS
    if(com->sreq.is_td_call == 1){
        if(com->sreq.tdx_call_number == TDG_VM_RD){
            exit(0);
        }
    }
#endif

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0;
    regs.rdx = 0xa020000200000002;
    regs.rax = TDG_VP_RD;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0;
    regs.rdx = 0x9110000300000010;
    regs.r8 = 0x1;
    regs.r9 = 0x1;
    regs.rax = TDG_VP_WR;
    do_tdcall(LP_0, &regs);

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call == 1){
		if(com->sreq.tdx_call_number == TDG_SYS_RD){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
	regs.rax = TDG_SYS_RD;
	regs.rdx = 0x800000200000000; 
    do_tdcall(LP_0, &regs);
#ifdef IN_SINGLE_CALL_TESTS
    if(com->sreq.is_td_call == 1){
        if(com->sreq.tdx_call_number == TDG_SYS_RD){
            exit(0);
        }
    }
#endif

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call == 1){
		if(com->sreq.tdx_call_number == TDG_SYS_RDALL){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rdx = 0; 
    regs.r8 = -1;
    regs.rax = TDG_SYS_RDALL;
    do_tdcall(LP_0, &regs);
#ifdef IN_SINGLE_CALL_TESTS
    if(com->sreq.is_td_call == 1){
        if(com->sreq.tdx_call_number == TDG_SYS_RDALL){
            exit(0);
        }
    }
#endif


    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rdx = 0; 
    regs.r8 = -1;
    regs.rax = TDG_SYS_RDALL;
    do_tdcall(LP_0, &regs);

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call == 1){
		if(com->sreq.tdx_call_number == TDG_MEM_PAGE_ATTR_WR){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0; //(1UL << 48);; /*GPA*/
    regs.rdx = 0;
    regs.r8 = 0;
    regs.rax = TDG_MEM_PAGE_ATTR_WR;
    do_tdcall(LP_0, &regs);
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call == 1){
		if(com->sreq.tdx_call_number == TDG_MEM_PAGE_ATTR_WR){
			exit(0);
		}
	}
#endif

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td[TD_0].servtd.binding_handle;
    regs.rdx = 0x8010000300000020;
    regs.r10 = com->td[TD_0].servtd.targtd_uuid_0_63;
    regs.r11 = com->td[TD_0].servtd.targtd_uuid_64_127;
    regs.r12 = com->td[TD_0].servtd.targtd_uuid_128_191;
    regs.r13 = com->td[TD_0].servtd.targtd_uuid_192_255;
    regs.rax = TDG_SERVTD_RD;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td[TD_0].servtd.binding_handle;
    regs.rdx = 0x9810000300000010;
    regs.r8 = 0x1234567812345678;
    regs.r9 = 0xffffffffffffffff;
    regs.r10 = com->td[TD_0].servtd.targtd_uuid_0_63;
    regs.r11 = com->td[TD_0].servtd.targtd_uuid_64_127;
    regs.r12 = com->td[TD_0].servtd.targtd_uuid_128_191;
    regs.r13 = com->td[TD_0].servtd.targtd_uuid_192_255;
    regs.rax = TDG_SERVTD_WR;
    do_tdcall(LP_0, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td[TD_0].tdr;
    regs.rdx = 0x9110000300000012;
    regs.r8 = 0;
    regs.r9 = -1;
    regs.rax = TDH_MNG_WR;
    do_seamcall(LP_2, &regs);

#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MNG_RD){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td[TD_0].tdr;
	regs.rdx = 0x9010000200000001;
    regs.rax = TDH_MNG_RD | (1UL << 16);
    do_seamcall(LP_2, &regs);
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MNG_RD){
				exit(0);
			}
		}
#endif

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0x1000;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RD;
    do_seamcall(LP_2, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = 0x1000;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.r8 = 0xbeecbeec;
    regs.rax = TDH_MEM_WR;
    do_seamcall(LP_2, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rdx = SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K;
	regs.r8 = 0xA200000300000005;
    regs.rax = TDH_SYS_RDALL;
    do_seamcall(LP_2, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
	regs.r8 = 0xA200000300000005;
    regs.rax = TDH_SYS_RD;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
	memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rax = TDH_MEM_SEPT_RD;
    regs.rcx = 0;
    regs.rdx = com->td[TD_0].tdr;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
    ulong gpa = 2UL << 48;
    ulong sept_pa;
    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa, SEPT_LVL_4, com->td[TD_0].tdr, sept_pa);

    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa, SEPT_LVL_3, com->td[TD_0].tdr, sept_pa);

    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa, SEPT_LVL_2, com->td[TD_0].tdr, sept_pa);

    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa, SEPT_LVL_1, com->td[TD_0].tdr, sept_pa);

    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa + _2M, SEPT_LVL_1, com->td[TD_0].tdr, sept_pa);

    //remove
    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa + _4M, SEPT_LVL_1, com->td[TD_0].tdr, sept_pa);

    //reloc
    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa + _6M, SEPT_LVL_1, com->td[TD_0].tdr, sept_pa);

    //sept-rem
    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa + _8M, SEPT_LVL_1, com->td[TD_0].tdr, sept_pa);

    //promote
    sept_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    tdh_mem_sept_add(LP_2, gpa + _10M, SEPT_LVL_1, com->td[TD_0].tdr, sept_pa);


    //promote
	int i = 0;
	ulong gpa_st = 0;
	while(i < 512){

        memset((void *)&regs, 0, sizeof(struct kvm_regs));
        com->td_owner_for_next_tdxcall = TD_0;
        regs.rcx = gpa + _10M + gpa_st;
        regs.rdx = com->td[TD_0].tdr;
        regs.r8 = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
        regs.rax = TDH_MEM_PAGE_AUG;
        do_seamcall(LP_2, &regs);

		gpa_st += _4K;
		i++;
	}

    //reloc
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = gpa + _6M;
    regs.rdx = com->td[TD_0].tdr;
    regs.r8 = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    regs.rax = TDH_MEM_PAGE_AUG;
    do_seamcall(LP_2, &regs);

    //remove
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = gpa + _4M;
    regs.rdx = com->td[TD_0].tdr;
    regs.r8 = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    regs.rax = TDH_MEM_PAGE_AUG;
    do_seamcall(LP_2, &regs);

    //sept remove
    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa) | SEPT_LVL_1;
    // regs.rcx = 0 | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_BLOCK;
    do_seamcall(LP_2, &regs);

    //sept remove
    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa  + _8M) | SEPT_LVL_1;
    // regs.rcx = 0 | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_BLOCK;
    do_seamcall(LP_2, &regs);

    //remove
    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa  + _4M); // | SEPT_LVL_1;
    // regs.rcx = 0 | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_BLOCK;
    do_seamcall(LP_2, &regs);

    //reloc
    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa  + _6M); // | SEPT_LVL_1;
    // regs.rcx = 0 | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_BLOCK;
    do_seamcall(LP_2, &regs);

    //sept remove
    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa  + _10M) | SEPT_LVL_1;
    // regs.rcx = 0 | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_BLOCK;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa + _2M) | SEPT_LVL_1;
    // regs.rcx = 0 | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_BLOCK;
    do_seamcall(LP_2, &regs);

    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rcx = com->td[TD_0].tdr;
    regs.rax = TDH_MEM_TRACK;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 1UL << 2;
    regs.rax = TDG_VP_VMCALL;
    do_tdcall(LP_0, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 	(gpa + _2M) | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_RANGE_UNBLOCK;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
	memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = (gpa + _10M) | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_PAGE_PROMOTE | (1UL << 16);
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
	memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = (gpa + _8M) | SEPT_LVL_1;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_SEPT_REMOVE;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
	memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = gpa + _6M;
    regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.r8 = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    regs.rax = TDH_MEM_PAGE_RELOCATE;
    do_seamcall(LP_2, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = gpa  + _4M;
	regs.rdx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MEM_PAGE_REMOVE;
    do_seamcall(LP_2, &regs);
   
    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = com->td[com->td_owner_for_next_tdxcall].tdvpr;
    regs.rax = TDH_VP_FLUSH;
    do_seamcall(LP_0, &regs);

    com->td_owner_for_next_tdxcall = TD_0;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
	regs.rcx = com->td[com->td_owner_for_next_tdxcall].tdr;
    regs.rax = TDH_MNG_VPFLUSHDONE;
    do_seamcall(LP_0, &regs);

#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call == 1){
			if(com->sreq.tdx_call_number == TDG_MR_REPORT){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
    com->td_owner_for_next_tdxcall = TD_1;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = _4K*(TD_INITIAL_PAGE_COUNT + 1);
	regs.rdx = _4K*(TD_INITIAL_PAGE_COUNT + 2);
	regs.r8 = 0;
    regs.rax = TDG_MR_REPORT;
    do_tdcall(com->td_owner_for_next_tdxcall, &regs);
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call == 1){
			if(com->sreq.tdx_call_number == TDG_MR_REPORT){
				exit(0);
			}
		}
#endif

#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call == 1){
			if(com->sreq.tdx_call_number == TDG_VP_INVEPT){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
    com->td_owner_for_next_tdxcall = TD_1;
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 0;
    regs.rax = TDG_VP_INVEPT;
    do_tdcall(com->td_owner_for_next_tdxcall, &regs);
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call == 1){
			if(com->sreq.tdx_call_number == TDG_VP_INVEPT){
				exit(0);
			}
		}
#endif

    exit(0);
}