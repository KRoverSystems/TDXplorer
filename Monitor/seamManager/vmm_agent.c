#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

#include "defs.h"
#include "seam.h"
#include "common.h"
#include "td_control_structures.h"
#include "tdx_local_data.h"

#include "state.h"
#include "vmm_agent.h"

// #define ENABLE_SERVTD_BINDING

void remove_debug_bp(ulong dr_num);
void set_debug_bp(ulong address, ulong dr_num, ulong trigger_condition, ulong bp_size);
extern int switch_to_tdx_module_context(TDXCALL_TYPE call_type);
extern ulong do_tdxcall(ulong seamcall);
extern uint64_t get_saved_register_value(REGS_64 reg);
extern void log_active_keyhole_mappings();
extern void block_persistant_khole_mappings(ulong current_lp);
extern ulong get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner);
extern ulong get_tdr_va_of_running_td(ulong pa, ulong lp);
extern ulong va_to_pa(ulong cr3, ulong va);
extern ulong get_region_base_pa(REGION region);
extern void fill_khole_refs(ulong lp);

ulong get_offset(OFFSET_TYPE type);

extern struct vm *vm;

void start_se();
extern void setup_and_do_tdcal(ulong tdcall_number, ulong lp);
void run_servtd_bind();
void do_tdh_mng_rd(ulong td, ulong lp);

#define SEAMCALL(...) do_tdxcall(__VA_ARGS__)

extern struct comArea *com;

#ifdef ENABLE_SERVTD_BINDING
ulong td_0_created = 0;
#endif


void start_se(){
	LOG("Starting _se\n");
	com->seam_state = SEAM_STATE_TEMP;
	com->single_step_on = true;
}

void set_common_seamcall_state(ulong lp_id, ulong scall){

	com->is_tdcall = 0;
	com->current_lp = lp_id;
	com->seamcall_vmcs[lp_id].vm_exit_reason = VMEXIT_REASON_SEAMCALL;
	com->current_tdx_vmcs_pa = com->seamcall_vmcs[lp_id].vmcs_pa;
	memset((void *)&com->last_seamcall, 0, sizeof(struct tdxCall));
	com->last_seamcall.tdxcall = scall;
	com->last_seamcall.state = STATE_DO_SEAMCALL;
}

ulong tdh_sys_init(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_INIT);
	regs.rax = TDH_SYS_INIT;
	regs.rcx = 0;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_INIT);
}

ulong tdh_sys_lp_init(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_LP_INIT);
	regs.rax = TDH_SYS_LP_INIT;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_LP_INIT);
}

ulong tdh_sys_config(ulong lp_id, ulong tdmrinfo_pa, ulong num_ptrs, ulong global_hkid){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_CONFIG);
	regs.rax = TDH_SYS_CONFIG;
	regs.rcx = tdmrinfo_pa;
	regs.rdx = num_ptrs;
	regs.r8 = global_hkid;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_CONFIG);
}

ulong tdh_sys_key_config(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_KEY_CONFIG);
	regs.rax = TDH_SYS_KEY_CONFIG;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_KEY_CONFIG);
}

ulong tdh_sys_tdmr_init(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_TDMR_INIT);
	regs.rax = TDH_SYS_TDMR_INIT;
	regs.rcx = TDX_TDMR0_START_PA;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_TDMR_INIT);
}

ulong tdh_mng_create(ulong lp_id, ulong tdr, ulong hkid){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_CREATE);

	regs.rax = TDH_MNG_CREATE;
	regs.rcx = tdr;
	regs.rdx = hkid;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_CREATE);
}

ulong tdh_mng_key_config(ulong lp_id, ulong tdr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_KEY_CONFIG);

	regs.rax = TDH_MNG_KEY_CONFIG;
	regs.rcx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_KEY_CONFIG);
}

ulong tdh_mng_addcx(ulong lp_id, ulong tdr, ulong page_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_ADDCX);

	regs.rax = TDH_MNG_ADDCX;
	regs.rcx = page_pa;
	regs.rdx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_ADDCX);
}

ulong tdh_sys_info(ulong lp_id, ulong tdsysinfo_page_pa, ulong tdsysinfo_page_size, ulong cmrinfo_ary_pa, ulong num_cmrinfo_entries){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_INFO);

	regs.rax = TDH_SYS_INFO;
	regs.rcx = tdsysinfo_page_pa;
	regs.rdx = tdsysinfo_page_size;
	regs.r8 = cmrinfo_ary_pa;
	regs.r9 = num_cmrinfo_entries;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_INFO);
}

ulong tdh_mng_init(ulong lp_id, ulong tdr, ulong tdparams_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_INIT);

	regs.rax = TDH_MNG_INIT;
	regs.rcx = tdr;
	regs.rdx = tdparams_pa;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_INIT);
}

ulong tdh_vp_create(ulong lp_id, ulong tdr, ulong tdvps_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_VP_CREATE);

	regs.rax = TDH_VP_CREATE;
	regs.rcx = tdvps_pa;
	regs.rdx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_CREATE);
}

ulong tdh_vp_addcx(ulong lp_id, ulong tdvpr, ulong tdcx_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_VP_ADDCX);

	regs.rax = TDH_VP_ADDCX;
	regs.rcx = tdcx_pa;
	regs.rdx = tdvpr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_ADDCX);
}

ulong tdh_vp_init(ulong lp_id, ulong tdvpr, ulong initial_rcx){

	struct kvm_regs regs;
	ulong vp_init_leaf_version = 0;
	uint32_t x2apic_id = 0;

	set_common_seamcall_state(lp_id, TDH_VP_INIT);

	regs.rax = TDH_VP_INIT | (vp_init_leaf_version << 16);
	regs.rcx = tdvpr;
	regs.rdx = initial_rcx;
	regs.r8 |= x2apic_id;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_INIT);
}

ulong tdh_mem_sept_add(ulong lp_id, ulong gpa, ulong level, ulong tdr, ulong new_sept_pa){

	struct kvm_regs regs;
	ulong allow_existing = 0;
	ulong sept_add_leaf_version = 1;

	set_common_seamcall_state(lp_id, TDH_MEM_SEPT_ADD);

	regs.rax = TDH_MEM_SEPT_ADD | (sept_add_leaf_version << 16);
	regs.rcx = gpa | (level & 0b111UL);
	regs.rdx = tdr | (allow_existing & 0x1);
	regs.r8 = new_sept_pa;
	regs.r9 = -1;
	regs.r10 = -1;
	regs.r11 = -1;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);
	
	return SEAMCALL(TDH_MEM_SEPT_ADD);
}

ulong tdh_mem_page_add(ulong lp_id, ulong gpa, ulong level, ulong tdr, ulong target_page, ulong source_page){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MEM_PAGE_ADD);

	regs.rax = TDH_MEM_PAGE_ADD;
	regs.rcx = gpa | (level & 0b111UL);
	regs.rdx = tdr;
	regs.r8 = target_page;
	regs.r9 = source_page;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MEM_PAGE_ADD);
}

ulong tdh_mr_extend(ulong lp_id, ulong gpa, ulong tdr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MR_EXTEND);

	regs.rax = TDH_MR_EXTEND;
	regs.rcx = gpa;
	regs.rdx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MR_EXTEND);
}

ulong tdh_mr_finalize(ulong lp_id, ulong tdr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MR_FINALIZE);

	regs.rax = TDH_MR_FINALIZE;
	regs.rcx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MR_FINALIZE);
}

ulong tdh_vp_enter(ulong lp_id, ulong tdvpr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_VP_ENTER);

	regs.rax = TDH_VP_ENTER;
	regs.rcx = tdvpr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_ENTER);
}

ulong do_seamcall(ulong lp_id, struct kvm_regs *regs){

	set_common_seamcall_state(lp_id, regs->rax & 0xffff);
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, regs);

	return SEAMCALL(regs->rax);
}

/*TD Creation and Key Resource Assignment-----------
	TDH_MNG_CREATE,
	TDH_MNG_KEY_CONFIG,
TDCS Memory Allocation and TD Initialization--------
	TDH_MNG_ADDCX,
	TDH_SYS_INFO,
	TDH_MNG_INIT,
Virtual Processor Creation and Configuration--------
	TDH_VP_CREATE,
	TDH_VP_ADDCX,
	TDH_VP_INIT,
	TDH_VP_WR -The host VMM may modify a few TD VMCS execution control fields using this SEAMCALL
TD Boot Memory Setup, measurement & finalize--------
	TDH_MEM_SEPT_ADD,
	TDH_MEM_PAGE_ADD,
	TDH_MR_EXTEND
	TDH_MR_FINALIZE*/
void create_td(ulong td_id, ulong lp_id, ulong initial_gpa_max, ulong initial_pages_to_add){

	// ulong lp_id = 0;
	ulong tdcs_add_count, tdvps_add_count, sept_parent_level, gpa_start, pg_count, pg_start;
	ulong chunk_gpa;
	ulong tdr, hkid, page_pa, current_lvl, current_gpa;
	ulong tdsysinfo_page_pa, tdsysinfo_page_size, cmrinfo_ary_pa, num_cmrinfo_entries;
	struct kvm_regs regs;

	if((td_id >= MAX_TDS) || (td_id < 0)){
		LOG("invalid TD id: %lu\n", td_id);
		exit(0);
	}
	if((initial_gpa_max <= 0) || (initial_gpa_max > TD_GPA_RANGE_MAX) || (initial_gpa_max & PAGE_OFST != 0)){
		LOG("invalid initial_gpa_max: 0x%lx\n", initial_gpa_max);
		exit(0);
	}
	com->current_td_being_setup = td_id;
	com->td[td_id].initial_gpa_max = initial_gpa_max;
	com->td[td_id].next_gpa_to_allocate_in_sept = initial_gpa_max;

	/*TD Creation and Key Resource Assignment------------*/
	tdr = reserve_and_get_tdmr_next_avl_pa(td_id, TDX_GLOBAL_PRIVATE_HKID,TDX_MOD);
	hkid = reserve_and_get_next_available_hkid();
	com->td[td_id].tdr = tdr;
	com->td[td_id].hkid = hkid;

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_CREATE){
		#ifdef IN_SE_MODE
			start_se();
			fill_khole_refs(lp_id);
		#endif
		}
	}
#endif
	if(tdh_mng_create(lp_id, tdr, hkid) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_CREATE Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_CREATE){
			exit(0);
		}
	}
#endif

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_KEY_CONFIG){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
	if(tdh_mng_key_config(lp_id, tdr) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_KEY_CONFIG Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_KEY_CONFIG){
			exit(0);
		}
	}
#endif

	/*TDCS Memory Allocation and TD Initialization-------*/
	tdcs_add_count = 0;
	do{
		if (tdcs_add_count == 0){
			com->td[td_id].tdcs_base = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		}
		else if(tdcs_add_count == 3){
			com->td[td_id].tdcs_eptp_root = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		}
		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_ADDCX){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
		if(tdh_mng_addcx(lp_id, tdr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_MNG_ADDCX Failed\n");
		}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_ADDCX){
			exit(0);
		}
	}
#endif

		tdcs_add_count++;
	}while(tdcs_add_count < MIN_NUM_TDCS_PAGES);

	tdsysinfo_page_pa = SEAM_AGENT_SEAMCALL_DATA_PA;
	cmrinfo_ary_pa = SEAM_AGENT_SEAMCALL_DATA_PA + _4K;
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_INFO){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
	tdh_sys_info(lp_id, tdsysinfo_page_pa, _4K, cmrinfo_ary_pa, MAX_CMR);
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_INFO){
			exit(0);
		}
	}
#endif
	/*TDH_MNG_INIT uses data retrived from TDH_SYS_INFO*/

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_INIT){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
	memset((void *)&regs, 0, sizeof(struct kvm_regs));
	prep_tdh_mng_init_args(&regs);
	regs.rax = TDH_MNG_INIT;
	if(do_seamcall(lp_id, &regs) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_INIT Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_MNG_INIT){
			exit(0);
		}
	}
#endif


	/*testing TDH_SERVTD_BIND*/
#ifdef ENABLE_SERVTD_BINDING
	run_servtd_bind();
#endif

	/*Virtual Processor Creation and Configuration-------*/
	/*In the current design, we provide only 1 vCPU for a TD (i.e. only 1 VP CREATE). If this is 
	changed in future, we also need to update all places where we consider a TD to only have 1 vCPU.*/
	page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
	com->td[td_id].tdvpr = page_pa;
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_CREATE){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
	if(tdh_vp_create(lp_id, tdr, page_pa) != SEAMCALL_SUCCESS){
		LOG("TDH_VP_CREATE Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_CREATE){
			exit(0);
		}
	}
#endif

	tdvps_add_count = 0;
	do{
		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdvps_add_count == 0){
			com->tdcall_vmcs[td_id].vmcs_pa = page_pa;
		}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_ADDCX){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
		if(tdh_vp_addcx(lp_id, com->td[td_id].tdvpr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_VP_ADDCX Failed\n");
			exit(0);
		}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_ADDCX){
			exit(0);
		}
	}
#endif

		tdvps_add_count++;
	}while(tdvps_add_count < (MAX_TDVPS_PAGES - 1));

#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_INIT){
		#ifdef IN_SE_MODE
			start_se();
		#endif
		}
	}
#endif
	if(tdh_vp_init(lp_id, com->td[td_id].tdvpr, 0x0) != SEAMCALL_SUCCESS){
		LOG("TDH_VP_INIT Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_INIT){
			exit(0);
		}
	}
#endif
	/*As noticed, during VP Init the corresponding tdvps is associated with the current LP id.
	This is the LP on which the VMLAUNCH must take place. So we save the value for future use.*/
	com->td[td_id].vcpu_associated_lp = lp_id;

	/*TD Boot Memory Setup : sept-------------------------------*/
	/*here we create the initial sept tree. the root sept page, sPML4 (for 4 level ept) OR sPML5
	(for 5 level ept) has already been created,
	under TDH_MNG_ADDCX. Now, we add the remaining lower level sEPT pages accordingly.
	For 4 level EPT : one sPDPT (parent sept level 3), one sPD (parent sept level 2), and one or 
	few sPT (parent sept level 1) pages.	
	For 5 level EPT : one sPML4 (parent sept level 4), one sPDPT (parent sept level 3), one sPD 
	(parent sept level 2), and one or few sPT (parent sept level 1) pages.	
	The number of sPT pages added depends on the initial_gpa_max. Eg: if initial_gpa_max = 4M, we 
	add a sPT page for each 2M block. i.e. 1 for GPA range starting at 0, another for GPA range 
	starting at 2M*/
	gpa_start = 0;
	sept_parent_level = TDX_SEPT_LEVELS;
	while(sept_parent_level > 0){

		current_lvl = sept_parent_level;
		current_gpa = gpa_start;
		// com->sept.septe_level = sept_parent_level;
		// com->sept.start_gpa = 0;

		if(sept_parent_level == 1){
			if(gpa_start < initial_gpa_max){
				// com->sept.start_gpa = gpa_start;
				gpa_start += _2M;
			}
			else{
				break;
			}
		}
		else{
			// com->sept.start_gpa = 0;
			sept_parent_level--;
		}

		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MEM_SEPT_ADD){
			#ifdef IN_SE_MODE
				fill_khole_refs(lp_id);
				start_se();
			#endif
			}
		}
#endif
		if(tdh_mem_sept_add(lp_id, current_gpa, current_lvl, tdr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_ADD Failed\n");
			exit(0);
		}
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MEM_SEPT_ADD){
				exit(0);
			}
		}
#endif
		/*For TDH.MEM.SEPT.ADD version 1 or higher: If a provided L1 SEPT page has been added, R8 returns -1*/
		if(get_saved_register_value(R8) != NULL_PA){
			LOG("SEPT add issue, investiate ...\n");
			exit(0);
		}
	}

	/*TD Boot Memory Setup : initial pages---------------------------*/
	pg_count = 0;
	pg_start = 0;
	while (pg_count < initial_pages_to_add){
		
		/*We do not actually run  the TD. Therefore, for the moment we do not need to pass actuall data 
		in to td pages being added. So, we use some page in the host as the source page. 
		we have used the first 2 pages of SEAM_AGENT_SEAMCALL_DATA_PA, so use the 3rd page here.*/

		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MEM_PAGE_ADD){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
		if(tdh_mem_page_add(lp_id, pg_start, SEPT_LVL_0, tdr, page_pa, SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_PAGE_ADD Failed\n");
			exit(0);
		}
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MEM_PAGE_ADD){
				exit(0);
			}
		}
#endif

		pg_start += _4K;
		com->td[td_id].next_4k_pg_gpa_to_add = pg_start + _4K;
		pg_count++;
	}

/*faithfullness test 2-------------------------------------------------------*/
#if DO_ARTF_TEST2 == 1

	if(td_id == TD_0){

		/*Adding sept pages to EPT tree*/
		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdh_mem_sept_add(lp_id, 0xc0000000, SEPT_LVL_2, tdr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_ADD Failed\n");
			exit(0);
		}
		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdh_mem_sept_add(lp_id, 0xffc00000, SEPT_LVL_1, tdr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_ADD Failed\n");
			exit(0);
		}
		
		/*Adding 512 guest pages to the PT mapped via PD idx 510*/ 
		ulong gpa_to_add = 0xffc00000;
		int pt_index1 = 0;
		while(pt_index1 < 512){
			LOG("\n\nadding new td page at PT index %d, gpa: 0x%lx\n", pt_index1, gpa_to_add);
			page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
			if(tdh_mem_page_add(lp_id, gpa_to_add, SEPT_LVL_0, tdr, page_pa, SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K) != SEAMCALL_SUCCESS){
				LOG("TDH_MEM_PAGE_ADD Failed\n");
				exit(0);
			}
			pt_index1++;
			gpa_to_add += _4K;
		}

		/*reading SEPT tree*/
		struct kvm_regs regs;
		ulong gpa_to_read, sept_level;
    	
		com->td_owner_for_next_tdxcall = TD_0;

		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		gpa_to_read = 0;
		sept_level = SEPT_LVL_4;
		LOG("\n\nreading pml5 idx 0 gpa:0x%lx\n", gpa_to_read);
		regs.rcx = gpa_to_read | sept_level;
		regs.rdx = tdr;
		regs.rax = TDH_MEM_SEPT_RD;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_RD Failed\n");
			exit(0);
		}

		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		gpa_to_read = 0;
		sept_level = SEPT_LVL_3;
		LOG("\n\nreading pml4 idx 0 gpa:0x%lx\n", gpa_to_read);
		regs.rcx = gpa_to_read | sept_level;
		regs.rdx = tdr;
		regs.rax = TDH_MEM_SEPT_RD;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_RD Failed\n");
			exit(0);
		}

		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		gpa_to_read = 0xc0000000;
		sept_level = SEPT_LVL_2;
		LOG("\n\nreading pdpt idx 3 gpa:0x%lx\n", gpa_to_read);
		regs.rcx = gpa_to_read | sept_level;
		regs.rdx = tdr;
		regs.rax = TDH_MEM_SEPT_RD;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_RD Failed\n");
			exit(0);
		}

		LOG("\n###reading the entire PD--------------------------------------------\n");
		int pd_idx = 0;
		while(pd_idx < 512){

			memset((void *)&regs, 0, sizeof(struct kvm_regs));
			gpa_to_read = (3UL << 30) | (pd_idx << 21);
			sept_level = SEPT_LVL_1;
			LOG("\n\nreading pd idx %d gpa:0x%lx\n", pd_idx, gpa_to_read);
			regs.rcx = gpa_to_read | sept_level;
			regs.rdx = tdr;
			regs.rax = TDH_MEM_SEPT_RD;
			if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
				LOG("TDH_MEM_SEPT_RD Failed\n");
				exit(0);
			}
			pd_idx++;
		}

		LOG("\n###reading the entire PT--------------------------------------------\n");
		int pt_idx = 0;
		while(pt_idx < 512){

			memset((void *)&regs, 0, sizeof(struct kvm_regs));
			gpa_to_read = 0xffc00000 | (pt_idx << 12);
			sept_level = SEPT_LVL_0;
			LOG("\n\nreading pt idx %d gpa:0x%lx\n", pt_idx, gpa_to_read);
			regs.rcx = gpa_to_read | sept_level;
			regs.rdx = tdr;
			regs.rax = TDH_MEM_SEPT_RD;
			if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
				LOG("TDH_MEM_SEPT_RD Failed\n");
				exit(0);
			}
			pt_idx++;
		}
	}
	exit(0);
#endif
/*faithfullness test 2-------------------------------------------------------*/


	/*TD Boot Memory Setup : measurement-----------------------------*/
	chunk_gpa = 0;
	while (chunk_gpa < initial_pages_to_add*_4K){
		
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MR_EXTEND){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
		if(tdh_mr_extend(lp_id, chunk_gpa, tdr) != SEAMCALL_SUCCESS){
			LOG("TDH_MR_EXTEND Failed\n");
			exit(0);	
		}
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_MR_EXTEND){
				exit(0);
			}
		}
#endif

		chunk_gpa += 256; /*each chunk is 256B*/
	}

	/*TD Boot Memory Setup : finalize--------------------------------*/
	if(tdh_mr_finalize(lp_id, tdr) != SEAMCALL_SUCCESS){
		LOG("TDH_MR_FINALIZE Failed\n");
		exit(0);
	}
	com->td[td_id].is_created = true;
}

void init_tdx_module(){

	ulong lp;
	ulong next_to_init_adr;
	struct kvm_regs regs;

#ifndef MEASURE_PLATFORM_INIT_TIME_AND_STOP
	LOG("init_tdx_module\n");
#endif
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_INIT){
		#ifdef IN_SE_MODE
			start_se();
		#endif		
		}
	}
#endif
	/*TDH_SYS_INIT-----------------------------------*/
	if(tdh_sys_init(LP_0) != SEAMCALL_SUCCESS){
		LOG("TDH_SYS_INIT Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_INIT){
			exit(0);
		}
	}
#endif

	/*TDH_SYS_LP_INIT--------------------------------*/
	lp = LP_0;
	while(lp < NUM_ADDRESSIBLE_LPS){
		com->current_lp = lp;

	#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_SYS_LP_INIT){
			#ifdef IN_SE_MODE
				start_se();
			#endif			
			}
		}
	#endif
		if(tdh_sys_lp_init(lp) != SEAMCALL_SUCCESS){
			LOG("TDH_SYS_LP_INIT Failed\n");
			exit(0);
		}
	#ifdef IN_SINGLE_CALL_TESTS
			if(com->sreq.is_td_call != 1){
				if(com->sreq.tdx_call_number == TDH_SYS_LP_INIT){
					exit(0);
				}
			}
	#endif
		lp++;
	}

	/*TDH_SYS_CONFIG-----------------------------------*/
	lp = LP_0;
	com->current_lp = lp;

	prep_tdh_sys_config_args(&regs);
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_CONFIG){
		#ifdef IN_SE_MODE
			start_se();
			fill_khole_refs(LP_0);
		#endif			
		}
	}
#endif
	regs.rax = TDH_SYS_CONFIG;
	if(do_seamcall(lp, &regs) != SEAMCALL_SUCCESS){
		LOG("TDH_SYS_CONFIG Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_CONFIG){
			exit(0);
		}
	}
#endif

	/*TDH_SYS_KEY_CONFIG-------------------------------*/
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_KEY_CONFIG){
		#ifdef IN_SE_MODE
			start_se();
		#endif			
		}
	}
#endif
	if(tdh_sys_key_config(lp) != SEAMCALL_SUCCESS){
		LOG("TDH_SYS_KEY_CONFIG Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_KEY_CONFIG){
			exit(0);
		}
	}
#endif

	/*TDH_SYS_TDMR_INIT--------------------------------*/
	do{
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_TDMR_INIT){
		#ifdef IN_SE_MODE
			start_se();
		#endif			
		}
	}
#endif
		 if(tdh_sys_tdmr_init(lp) != SEAMCALL_SUCCESS){
			LOG("TDH_SYS_TDMR_INIT Failed\n");
			exit(0);
		 }
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_SYS_TDMR_INIT){
			exit(0);
		}
	}
#endif
		next_to_init_adr = get_saved_register_value(RDX);
	}while(next_to_init_adr < (TDX_TDMR0_START_PA + TDX_TDMR0_FULL_SIZE));
	/*The above terminating condition is consistant with the specs and kvm.
	The returned rdx is the block in the tdmr to be initialized next.*/
}

void run_td(ulong td_id, ulong lp){

	/*LOG("\nRun td: %lu", td_id);*/
	
	com->td_owner_for_next_tdxcall = td_id;
	com->tdcall_vmcs[td_id].vm_exit_qualification = 0;
	com->tdcall_vmcs[td_id].rip = TD_START_RIP;
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_ENTER){
		#ifdef IN_SE_MODE
			start_se();
		#endif			
		}
	}
#endif
	if(tdh_vp_enter(lp, com->td[td_id].tdvpr) != SEAMCALL_SUCCESS){
		LOG("TDH_VP_ENTER Failed\n");
		exit(0);
	}
#ifdef IN_SINGLE_CALL_TESTS
	if(com->sreq.is_td_call != 1){
		if(com->sreq.tdx_call_number == TDH_VP_ENTER){
			exit(0);
		}
	}
#endif
	com->td[td_id].is_running = true;
}

#ifdef ENABLE_SERVTD_BINDING
void run_servtd_bind(){
	
	if(td_0_created == 1){

		ulong target_td = TD_1;
		ulong service_td = TD_0;

		/*gathering object offsets for symbolization*/
		tdcs_t tdcs_base;
		/*offset for  tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state  1 byte*/
		ulong binding_state_ofst = (ulong)&tdcs_base.service_td_fields.servtd_bindings_table[0].state - (ulong)&tdcs_base;
		/*offset for  attributes  8 bytes , can also consider the first 4 bytes to capture migratable flag*/
		ulong attributes_offset = (ulong)&tdcs_base.executions_ctl_fields.attributes - (ulong)&tdcs_base;
		/*offset for  tdcs_p->management_fields.op_state   4 bytes*/
		ulong op_state_ofst = (ulong)&tdcs_base.management_fields.op_state - (ulong)&tdcs_base;

		com->sreq.tdcs_binding_state_ofst = binding_state_ofst;
		com->sreq.tdcs_attributes_offset = attributes_offset;
		com->sreq.tdcs_op_state_ofst = op_state_ofst;
		com->sreq.tdcs_start_pa = com->td[target_td].tdcs_base;

		/*ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + get_offset(OFFSET_TYPE_TDH_SERVTD_BIND_LEAF);
		set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);
		start_se();*/

		/*service td binding*/
#if SERVTD_BIND_TYPE == TD_BIND
		struct kvm_regs regs;
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_SERVTD_BIND){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		com->current_td_being_setup = target_td;
		com->serv_td_owenr_being_setup = service_td;
		prep_tdh_servtd_bind_args(&regs);
		regs.rax = TDH_SERVTD_BIND;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_SERVTD_BIND Failed\n");
			exit(0);
		}
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_SERVTD_BIND){
				exit(0);
			}
		}
#endif
#endif

		com->td[service_td].servtd.binding_handle =  get_saved_register_value(RCX);
		com->td[service_td].servtd.targtd_uuid_0_63 =  get_saved_register_value(R10);
		com->td[service_td].servtd.targtd_uuid_64_127 = get_saved_register_value(R11);
		com->td[service_td].servtd.targtd_uuid_128_191 = get_saved_register_value(R12);
		com->td[service_td].servtd.targtd_uuid_192_255 = get_saved_register_value(R13);

		/*service td prebinding*/
#if SERVTD_BIND_TYPE == TD_PREBIND
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_SERVTD_PREBIND){
			#ifdef IN_SE_MODE
				start_se();
			#endif
			}
		}
#endif
		struct kvm_regs regs;
		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		com->current_td_being_setup = target_td;
		com->serv_td_owenr_being_setup = service_td;
		prep_tdh_servtd_prebind_args(&regs);
		regs.rax = TDH_SERVTD_PREBIND;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_SERVTD_PREBIND Failed\n");
			exit(0);
		}
#ifdef IN_SINGLE_CALL_TESTS
		if(com->sreq.is_td_call != 1){
			if(com->sreq.tdx_call_number == TDH_SERVTD_PREBIND){
				exit(0);
			}
		}
#endif
		LOG("prebind test done ending execution\n");
		exit(0);
#endif
		/*LOG("Ending TD binding test case.\n");
		exit(0);*/
	}

}
#endif

void vmm_agent(){
	
    LOG("VMM agent\n");
}

