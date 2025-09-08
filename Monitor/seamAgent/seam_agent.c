#include <stddef.h>
#include <stdint.h>

#include "seam.h"
#include "common.h"
#include "emulator.h"
#include "configs.h"
#include "defs.h"

#define DO_HCALL(...) request_host_service(__VA_ARGS__)
#define SAVED_TARGET_CPU_STATE			SEAM_AGENT_STACK
#define SAVED_TARGET_CPU_STATE_PF		SEAM_AGENT_STACK_PF

#define PTE_PRESENT 1

void hlt(){
	asm volatile("hlt; \n\t");
}

void lfence(){
	asm volatile("lfence; \n\t");
}

void request_host_service(HCALL hcall_no, CODE hcall_code){
	
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	com->hcall_no = hcall_no;
	com->hcall_code = hcall_code;
	asm ("movq $0xdeade001, %rax \n");
	hlt();
	/*com->hcall_no = NO_HCALL; to be clean host must do this*/
}

void vmsucceed_rflags_update(){
	
	ia32_rflags_t saved_rflsgs;
	uint64_t *target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));

	saved_rflsgs.raw = target_rsp[3];
	saved_rflsgs.cf = 0;
	saved_rflsgs.of = 0;
	saved_rflsgs.sf = 0;
	saved_rflsgs.zf = 0;
	saved_rflsgs.af = 0;
	saved_rflsgs.pf = 0;
	target_rsp[3] = saved_rflsgs.raw;

	/*ulong tmp = target_rsp[4];
	tmp += 0x10;
	ulong val = *(ulong *)tmp;
	asm volatile("movq %0, %%rax; \n\t"
				"movq %1, %%rbx; \n\t"
				"movq %2, %%rcx; \n\t"
				"movq %3, %%rdx; \n\t"
				::"m"(target_rsp[4]), "m"(tmp), "m"(val), "m"(target_rsp):"%rax", "%rbx", "%rcx", "%rdx");
	hlt();*/

}

int max_bit_in_4bits(long n){

	int pos;

	n &= 0xfUL;
	for(pos = 3; ((n<<=1) <= 0xf) && (pos >= 0); pos--){}

	return pos;
}

volatile struct tdx_vmcs* vmcs_pa_to_vmcs(ulong vmcs_pa){
	
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	unsigned int idx;

	/*Check among per lp seamcall vmcs*/
	idx = 0;
	while(idx < NUM_ADDRESSIBLE_LPS){
		if(com->seamcall_vmcs[idx].vmcs_pa == vmcs_pa)
			return &com->seamcall_vmcs[idx];
		idx++;
	}

	/*Check among tdcall vmcs. Untill the TD/s are created or being created, checking 
	in tdcall vmcs is of no use. But tdcall vmcs initial values are 0, so no issue/harm.*/
	idx = 0;
	while(idx < MAX_TDS){
		if(com->tdcall_vmcs[idx].vmcs_pa == vmcs_pa)
			return &com->tdcall_vmcs[idx];
		idx++;
	}

	DO_HCALL(HCALL_SEAM_ERROR, CODE_UNABLE_TO_FIND_VMCS);
	/*We do not come back here.*/
}

uint64_t *get_saved_reg_adr(REGS_64 reg){

	uint64_t *adr, *current_target_rsp;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	
	if(reg == RIP){
		current_target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));
		adr = &current_target_rsp[1];
	}
	if(reg == RSP){
		current_target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));
		adr = &current_target_rsp[4];
	}
	else if(reg == R15){
		current_target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));
		adr = &current_target_rsp[0];
	}
	else{
		adr = (uint64_t *)(SAVED_TARGET_CPU_STATE - com->int3_stack_offsets[reg]);
	}

	return adr;
}

uint64_t get_saved_reg_value(REGS_64 reg){

	if(reg == RIP)
		return *get_saved_reg_adr(reg) - 1;
	else
		return *get_saved_reg_adr(reg);
}

void memcpy(uint8_t *dest, uint8_t *src, ulong len){

	if(len <= 0){
		asm volatile("hlt; \n\t");
	}
	while(len > 0){
		*dest = *src;
		dest = (uint8_t *)((ulong)dest + 1);
		src = (uint8_t *)((ulong)src + 1);
		len--;
	}
}

BOOL int3_adr_to_ins(struct insInfo *ins_info){
	uint64_t adr = ins_info->int3_adr;
	struct insData *idata;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	ulong max_ins_ct;

	if(com->current_sw == SEAM_SW_PSEAMLDR){
		idata = (struct insData *)com->pseamldr_ins;
		max_ins_ct = PSEAMLDR_SPECIAL_INS_COUNT;
	}
	else{
		idata = (struct insData *)com->tdxmodule_ins;
		max_ins_ct = TDXMODULE_SPECIAL_INS_COUNT;
	}
	
	uint64_t ins_count = 0;
	// struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	while((ins_count < max_ins_ct) && (idata[ins_count].size != 0)){
		
		if(adr == idata[ins_count].va){
			ins_info->in = idata[ins_count].in;
			ins_info->insdata_idx = ins_count;

			return true;
		}
		ins_count++;
	}
	return false;
}

void set_int3_ins_info(struct insInfo *int3_ins_info, struct insInfo *ins_info){
	int3_ins_info->in = ins_info->in;
	int3_ins_info->insdata_idx = ins_info->insdata_idx;
	int3_ins_info->int3_adr = ins_info->int3_adr;
}

void clear_int3_ins_info(struct insInfo *int3_ins_info){
	int3_ins_info->in = START_INS;
	int3_ins_info->insdata_idx = PSEAMLDR_SPECIAL_INS_COUNT;
	int3_ins_info->int3_adr = 0x0;
}

void update_saved_reg64(REGS_64 reg, uint64_t value){

	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	uint64_t offset = com->int3_stack_offsets[reg];
	*(uint64_t *)(SAVED_TARGET_CPU_STATE - offset) = value;
}

/*leaf EAX*/
void handle_cpuid(){

	uint64_t leaf = *(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RAX_OFFSET) & R32_BITS;
	uint64_t subleaf;
	cpu_cache_params_t cpu_cache_params;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	/*If a switch contains more than five items, it's implemented using a lookup table or a hash list.
	So we resort to if-else ladder here*/
	if(leaf == CPUID_GET_MAX_PA_LEAF){
		update_saved_reg64(RCX, 0);
		update_saved_reg64(RDX, 0);

		/*EBX
		Bits 08-00: Reserved = 0.
		Bit 09: WBNOINVD is available if 1.: we do not have this instructions.
		Bits 31-10: Reserved = 0.*/
		update_saved_reg64(RBX, 0);

		/*EAX Linear/Physical Address size.
		Bits 07-00: #Physical Address Bits*. : we set this to 42
		Bits 15-08: #Linear Address Bits. : we set this to 48
		Bits 31-16: Reserved = 0*/
		update_saved_reg64(RAX, ((48 << 8) | 42));
	}
	else if(leaf == CPUID_GET_TOPOLOGY_LEAF){
		/*this is calld by the get_current_lpid() in p-seamldr. This function only returns 
		the %edx returned by the CPUID. 
		Now we support multiple LPS.  we send the lpid = com->current_lp in %edx. Do not set other regs at the moment.*/
		update_saved_reg64(RDX, com->current_lp);
	}
	else if(leaf == CPUID_DET_CACHE_PARAMS_LEAF){
		subleaf = *(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RCX_OFFSET) & R32_BITS;
	
		if(subleaf == CPUID_DET_CACHE_PARAMS_SUBLEAF){
			cpu_cache_params.rsvd = 0;
			cpu_cache_params.rsvd1 = 0;
			cpu_cache_params.max_num_of_lps_sharing_cache = NUM_ADDRESSIBLE_LPS - 1;
			update_saved_reg64(RAX, (uint64_t)cpu_cache_params.raw);
		}
		else{
			/*unhandled CPUID leaf*/
			DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_CPUID_SUBLEAF);
			/*we don't' come back here, seam manager will terminate*/
			return;
		}
	}
	else if(leaf == CPUID_MAX_INPUT_VAL_LEAF){
		/*tdx module validates the value to be >= 0x1f (CPUID_MIN_LAST_CPU_BASE_LEAF)*/
		update_saved_reg64(RAX, 0x1f);
		/*we do not need to return valid values for the rest*/
		update_saved_reg64(RBX, 0);
		update_saved_reg64(RCX, 0);
		update_saved_reg64(RDX, 0);
	}
	else if(leaf == CPUID_MAX_EXTENDED_VAL_LEAF){
		/*tdx module validates the value to ne >= 0x80000008 (CPUID_LAST_EXTENDED_LEAF)*/
		update_saved_reg64(RAX, 0x80000008);
		/*we do not need to return valid values for the rest*/
		update_saved_reg64(RBX, 0);
		update_saved_reg64(RCX, 0);
		update_saved_reg64(RDX, 0);
	}
	else{
		/*unhandled CPUID leaf*/
		DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_CPUID);
		/*we don't' come back here, seam manager will terminate*/
		return;
	}

}

void handle_tdxmodule_rdmsr(){
	uint64_t edx, eax;
	uint64_t msr_idx;

	msr_idx = *(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RCX_OFFSET) & R32_BITS;
	eax = edx = 0;
	
	/*If a switch contains more than five items, it's implemented using a lookup table or a hash list.
	So we resort to if-else ladder here*/
	if(msr_idx == IA32_SPEC_CTRL_MSR_ADDR){
		/*do nothing,
		the tdx module just reads this, saves and wrmsr a different value. Later restores the old valie,
		Therefore, we do not need a real value, return 0*/
	}
	else if(msr_idx == IA32_CORE_CAPABILITIES){
		/*do nothing, the tdx module just reads this and,
		if core_capabilities.lam_supported is set, does some msr updates, we ignore this, return 0*/
	}
	else if(msr_idx == IA32_ARCH_CAPABILITIES){
		ia32_arch_capabilities_t arch_cap;
		arch_cap.raw = 0;

		arch_cap.rdcl_no = 1;//Bit 0
        arch_cap.irbs_all = 1;// Bit 1
        arch_cap.rsba = 0;// Bit 2
        arch_cap.skip_l1dfl_vmentry = 1;// Bit 3
        arch_cap.mds_no = 1;// Bit 5
        arch_cap.if_pschange_mc_no = 1;// Bit 6
        arch_cap.taa_no = 1;// Bit 8
        arch_cap.misc_package_ctls = 1;// Bit 10
        arch_cap.energy_filtering_ctl = 1;// Bit 11
        arch_cap.doitm = 1;// Bit 12
        arch_cap.sbdr_ssdp_no = 1;// Bit 13
        arch_cap.fbsdp_no = 1;// Bit 14
        arch_cap.psdp_no = 1;// Bit 15
        arch_cap.xapic_disable_status = 1;// Bit 21
		
		edx = arch_cap.raw >> 32;
		eax = arch_cap.raw & R32_BITS;
	}
	else if(msr_idx == IA32_XAPIC_DISABLE_STATUS_MSR_ADDR){
		ia32_xapic_disable_status_t xapic_dis;
		xapic_dis.raw = 0;

		xapic_dis.legacy_xapic_disabled = 1;

		edx = xapic_dis.raw >> 32;
		eax = xapic_dis.raw & R32_BITS;
	}
	else if(msr_idx == IA32_MISC_PACKAGE_CTLS_MSR_ADDR){
		ia32_misc_package_ctls_t misc_pkg;
		misc_pkg.raw = 0;

		misc_pkg.energy_filtering_enable = 1;

		edx = misc_pkg.raw >> 32;
		eax = misc_pkg.raw & R32_BITS;
	}
	else if(msr_idx == IA32_PERF_CAPABILITIES_MSR_ADDR){
		ia32_perf_capabilities_t perf_cap;
		perf_cap.raw = 0;

		perf_cap.full_write = 1;

		edx = perf_cap.raw >> 32;
		eax = perf_cap.raw & R32_BITS;
	}
	else if(msr_idx == IA32_TSC_ADJ_MSR_ADDR){
		/*From intel manual: 
		THREAD_ADJUST
		Local offset value of the IA32_TSC for a logical processor. Reset value is
		zero. A write to IA32_TSC will modify the local offset in
		IA32_TSC_ADJUST and the content of IA32_TSC, but does not affect the
		internal invariant TSC hardware
		
		From tdx module code:
        Time Stamp Counter
		Sample IA32_TSC_ADJUST
		This MSR should read the same value on all LP on TDSYSINITLP and during
		TDX-SEAM operation on TDHVPENTER and other flows that rely on rdtsc.

		for the moment, we return msr value as 0. */
		eax = edx = 0;
	}
	else if(msr_idx == IA32_SEAMRR_BASE_MSR_ADDR){
		edx = SEAM_RANGE_START_PA >> 32;
		eax = SEAM_RANGE_START_PA & R32_BITS;
	}
	else if(msr_idx == IA32_SEAMRR_MASK_MSR_ADDR){
		edx = SEAM_RANGE_SIZE >> 32;
		eax = SEAM_RANGE_SIZE & R32_BITS;
	}
	else if(msr_idx == IA32_MISC_ENABLES_MSR_ADDR){
		ia32_misc_enable_t misc_enab;
		misc_enab.raw = 0;
		misc_enab.boot_nt4 = 0;
		edx = misc_enab.raw >> 32;
		eax = misc_enab.raw & R32_BITS;
	}
	else if(msr_idx == IA32_TME_CAPABILITY_MSR_ADDR){
		ia32_tme_capability_t ia32_tme_capability;
 
 		ia32_tme_capability.raw = 0;
		ia32_tme_capability.aes_xts_128 = 1;
		ia32_tme_capability.aes_xts_128_with_integrity = 1;
		ia32_tme_capability.aes_xts_256 = 0;
		ia32_tme_capability.aes_xts_256_with_integrity = 0;
		ia32_tme_capability.tme_enc_bypass_supported = 0;
		ia32_tme_capability.mk_tme_max_keyid_bits = MAX_KEY_ID_BITS;
		ia32_tme_capability.mk_tme_max_keys = 63; /*max possible with 6 bits excluding keyid 0*/

		edx = ia32_tme_capability.raw >> 32;
		eax = ia32_tme_capability.raw & R32_BITS;
	}
	else if(msr_idx == IA32_TME_ACTIVATE_MSR_ADDR){
		ia32_tme_activate_t ia32_tme_activate;

		ia32_tme_activate.raw = 0;
		ia32_tme_activate.lock = 1; /*Lock means, the MSR is setup and ready to be read for TDX*/
		ia32_tme_activate.tme_enable = 1; 
		/*valid policies 
		0000 – AES-XTS-128.
        0001 – AES-XTS-128 with integrity.
        0010 – AES-XTS-256*/
		ia32_tme_activate.tme_policy = 1; /*AES-XTS-128 with integrity*/
		ia32_tme_activate.mk_tme_keyid_bits = 6;
		ia32_tme_activate.tdx_reserved_keyid_bits = 1;
		/*check if all 3 of the following algos are needed ?*/
		ia32_tme_activate.mk_tme_crypto_algs_aes_xts_128 = 1;
		ia32_tme_activate.mk_tme_crypto_algs_aes_xts_128_with_integrity = 1;
		ia32_tme_activate.mk_tme_crypto_algs_aes_xts_256 = 0;

		edx = ia32_tme_activate.raw >> 32;
		eax = ia32_tme_activate.raw & R32_BITS;
	}
	else if(msr_idx == IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR){
		ia32_tme_keyid_partitioning_t ia32_tme_keyid_partitioning;

		ia32_tme_keyid_partitioning.raw = 0;
		/*as per intel manual, the keyid 0 is not used,
		does keyid 0 mean no MKTME ?
		Anyhow, because of that, and as per below IA32_TME_ACTIVATE_MSR_ADDR setup,
		we consider only 2 bits for shared keyids, so valid keyids are: 1, 2, 3*/
		ia32_tme_keyid_partitioning.num_mktme_kids = 31;
		/*as per below IA32_TME_ACTIVATE_MSR_ADDR setup, with 6 bits we can have 60
		distinct keyids*/
		ia32_tme_keyid_partitioning.num_tdx_priv_kids = 32;

		edx = ia32_tme_keyid_partitioning.raw >> 32;
		eax = ia32_tme_keyid_partitioning.raw & R32_BITS;
	}
	else if (msr_idx == IA32_WBINVDP_MSR_ADDR){
		edx = 0;
		eax = 16;
	}
	else if (msr_idx == IA32_WBNOINVDP_MSR_ADDR){
		edx = 0;
		eax = 16;
	}
	else if (msr_idx == IA32_DS_AREA_MSR_ADDR){

		/*As per intel manual, "DS Save Area (R/W) If( CPUID.01H:EDX.DS[21] = 1
		Points to the linear address of the first byte of the DS buffer management area, which is used to
		manage the BTS and PEBS buffers. See Section 20.6.3.4, “Debug Store (DS) Mechanism.”
		for the moment, we return msr value as 0. */
		eax = edx = 0;	
	}
	else if(msr_idx == IA32_VMX_EPT_VPID_CAP_MSR_ADDR){
		ia32_vmx_ept_vpid_cap_t vpid_cap;
		vpid_cap.raw = 0;

		/*for the moment we only need to support the following fields*/
		vpid_cap.pml4_supported = 1;
		vpid_cap.pml5_supported = 1;

		edx = vpid_cap.raw >> 32;
		eax = vpid_cap.raw & R32_BITS;
	}
	else if(msr_idx == IA32_INTR_PENDING_MSR_ADDR){
		/*TDH_MEM_PAGE_DEMOTE to suceed, this msr must be 0
		used in is_interrupt_pending_host_side()*/
		eax = edx = 0; 
	}
	else if(msr_idx == IA32_UARCH_MISC_CTL_MSR_ADDR){
		eax = edx = 0; /*value 0 seen on host*/
	}
	else if((msr_idx == IA32_STAR_MSR_ADDR) || 
			(msr_idx == IA32_LSTAR_MSR_ADDR) ||  
			(msr_idx ==IA32_FMASK_MSR_ADDR) ||
			(msr_idx == IA32_KERNEL_GS_BASE_MSR_ADDR) ||
			(msr_idx == IA32_TSC_AUX_MSR_ADDR)){
		eax = edx = 0; /*since we do not run a real TD*/		
	}
	else if(msr_idx == IA32_XSS_MSR_ADDR){
		eax = 0x8000; /*value seen on host*/
	}
	else{
		/*unhandled MSR*/
		DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_MSR);
		/*we don't' come back here, seam manager will terminate*/
		return;
	}

	*(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RDX_OFFSET) = edx;
	*(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RAX_OFFSET) = eax;
}

/*Read MSR specified by ECX into EDX:EAX*/
void handle_pseamldr_rdmsr(){
	uint64_t edx, eax;
	uint64_t msr_idx;

	msr_idx = *(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RCX_OFFSET) & R32_BITS;

	/*If a switch contains more than five items, it's implemented using a lookup table or a hash list.
	So we resort to if-else ladder here*/
	if(msr_idx == IA32_SEAMRR_BASE_MSR_ADDR){
		edx = SEAM_RANGE_START_PA >> 32;
		eax = SEAM_RANGE_START_PA & R32_BITS;
	}
	else if(msr_idx == IA32_SEAMRR_MASK_MSR_ADDR){
		edx = SEAM_RANGE_SIZE >> 32;
		eax = SEAM_RANGE_SIZE & R32_BITS;
	}
	else if(msr_idx == IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR){
		ia32_tme_keyid_partitioning_t ia32_tme_keyid_partitioning;

		ia32_tme_keyid_partitioning.raw = 0;
		/*as per intel manual, the keyid 0 is not used,
		does keyid 0 mean no MKTME ?
		Anyhow, because of that, and as per below IA32_TME_ACTIVATE_MSR_ADDR setup,
		we consider only 2 bits for shared keyids, so valid keyids are: 1, 2, 3*/
		ia32_tme_keyid_partitioning.num_mktme_kids = 31;
		/*as per below IA32_TME_ACTIVATE_MSR_ADDR setup, with 6 bits we can have 60
		distinct keyids*/
		ia32_tme_keyid_partitioning.num_tdx_priv_kids = 32;

		edx = ia32_tme_keyid_partitioning.raw >> 32;
		eax = ia32_tme_keyid_partitioning.raw & R32_BITS;
	}
	else if(msr_idx == IA32_TME_ACTIVATE_MSR_ADDR){
		ia32_tme_activate_t ia32_tme_activate;

		ia32_tme_activate.raw = 0;
		ia32_tme_activate.lock = 1; /*Lock means, the MSR is setup and ready to be read for TDX*/
		ia32_tme_activate.tme_enable = 1; 
		/*valid policies 
		0000 – AES-XTS-128.
        0001 – AES-XTS-128 with integrity.
        0010 – AES-XTS-256*/
		ia32_tme_activate.tme_policy = 1; /*AES-XTS-128 with integrity*/
		ia32_tme_activate.mk_tme_keyid_bits = 6;
		ia32_tme_activate.tdx_reserved_keyid_bits = 1;
		/*check if all 3 of the following algos are needed ?*/
		ia32_tme_activate.mk_tme_crypto_algs_aes_xts_128 = 1;
		ia32_tme_activate.mk_tme_crypto_algs_aes_xts_128_with_integrity = 1;
		ia32_tme_activate.mk_tme_crypto_algs_aes_xts_256 = 0;

		edx = ia32_tme_activate.raw >> 32;
		eax = ia32_tme_activate.raw & R32_BITS;
	}
	/*in pseamldr, setup_seam_vmcs() uses 9 msr values. Howevr, since we do not have 
	the tdx hardware, and since we do not use this vmcs, we just emulate a 0 return value
	TODO: when tdxmodule encounters,  we may have to emulate with different values*/
	else if(msr_idx == IA32_VMX_BASIC_MSR_ADDR ||
			msr_idx == IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR ||
			msr_idx == IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR || 
			msr_idx == IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR ||
			msr_idx == IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR ||
			msr_idx == IA32_VMX_CR0_FIXED0_MSR_ADDR ||
			msr_idx == IA32_VMX_CR0_FIXED1_MSR_ADDR || 
			msr_idx == IA32_VMX_CR4_FIXED0_MSR_ADDR ||
			msr_idx == IA32_VMX_CR4_FIXED1_MSR_ADDR )
	{
			
			eax = 0x0;
			edx = 0x0;
	}
	else{
		/*unhandled MSR*/
		DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_MSR);
		/*we don't' come back here, seam manager will terminate*/
		return;
	}

	*(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RDX_OFFSET) = edx;
	*(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RAX_OFFSET) = eax;
}

void handle_rdmsr(){
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	if(com->current_sw == SEAM_SW_TDXMODULE){
		handle_tdxmodule_rdmsr();
	}
	else {
		handle_pseamldr_rdmsr();
	}
}

/*Write the value in EDX:EAX to MSR specified by ECX.*/
void handle_wrmsr(){
	uint64_t msr_idx;

	msr_idx = *(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RCX_OFFSET) & R32_BITS;

	if(msr_idx == IA32_SEAMEXTEND_MSR_ADDR){
		/*do nothing. None of the SEAM software seem to read this. 
		so as of now we do not maintain this MSR by writing.*/
		return;
	}
	else if(msr_idx == IA32_SPEC_CTRL_MSR_ADDR){
		/*do nothing,
		the tdx module just reads this, saves and wrmsr a different value. Later restores the old valie,
		Therefore, we do not need to save the value as a software maintained msr*/
	}
	else if(msr_idx == IA32_PRED_CMD_MSR_ADDR){
		/*This is to add a "Indirect Branch Prediction Barrier (IBPB)".
		do nothing for the moment*/
	}
	else if(msr_idx == IA32_XSS_MSR_ADDR){

	}
	else if(msr_idx == IA32_FMASK_MSR_ADDR){

	}
	else if(msr_idx == IA32_TSX_CTRL_MSR_ADDR){

	}
	else{
		/*unhandled MSR*/
		DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_MSR);
		/*we don't' come back here, seam manager will terminate*/
		return;
	}

}

void handle_rdfsbase(uint64_t insdata_idx){

	REGS_64 op0_reg;
	uint64_t reg_stack_offset;
	struct insData *idata;
	uint64_t fsbase;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	if(com->current_sw == SEAM_SW_PSEAMLDR){
		idata = (struct insData *)com->pseamldr_ins;
		fsbase = com->pseamldr_state.fsbase;
	}
	else{
		idata = (struct insData *)com->tdxmodule_ins;
		// fsbase = com->seamcall_vmcs[com->current_lp].fsbase;
		fsbase = com->tdxmod_state.fsbase;
	}

	if(idata[insdata_idx].operands_extracted != true){
		/*operands have not been extracted*/
		asm ("movq $0xdeade002, %rax \n");
		hlt();
	}
	op0_reg = idata[insdata_idx].op0.reg;
	reg_stack_offset = com->int3_stack_offsets[op0_reg];
	/*now update saved reg in stack*/
	*(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset) = fsbase;
}

void handle_rdgsbase(uint64_t insdata_idx){
	
	REGS_64 op0_reg;
	uint64_t reg_stack_offset;
	struct insData *idata;
	uint64_t gsbase;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	if(com->current_sw == SEAM_SW_PSEAMLDR){
		idata = (struct insData *)com->pseamldr_ins;
		gsbase = com->pseamldr_state.gsbase;
	}
	else{
		idata = (struct insData *)com->tdxmodule_ins;
		// gsbase = com->tdxmod_state.gsbase;
		gsbase = com->seamcall_vmcs[com->current_lp].gsbase;
	}

	if(idata[insdata_idx].operands_extracted != true){
		/*operands have not been extracted*/
		asm ("movq $0xdeade003, %rax \n");
		hlt();
	}
	op0_reg = idata[insdata_idx].op0.reg;
	/*now update saved reg in stack*/
	reg_stack_offset = com->int3_stack_offsets[op0_reg];
	*(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset) = gsbase;
}

BOOL handle_vmread(uint64_t insdata_idx){

	uint64_t op0, op1, *ptr_to_saved_reg_val, op1_value;
	REGS_64 reg0, reg1;
	struct insData *idata;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	struct tdx_vmcs *tdx_vmcs;

	if(com->current_sw == SEAM_SW_PSEAMLDR){
		idata = (struct insData *)com->pseamldr_ins;
	}
	else{
		idata = (struct insData *)com->tdxmodule_ins;
	}

	if(idata[insdata_idx].operands_extracted != true){
		DO_HCALL(HCALL_SEAM_ERROR, CODE_OPERANDS_NOT_EXTRACTED);
	}
	reg0 = idata[insdata_idx].op0.reg; /*op0 allways a reg*/
	op0 = get_saved_reg_value(reg0);
	// op0 = *(uint64_t *)(SAVED_TARGET_CPU_STATE - com->int3_stack_offsets[reg0]);

	if(op0 == VMX_VM_EXIT_REASON_ENCODE){
		// op1_value = com->seamvmcs.vm_exit_reason;
		
		/*We only come here from TDXmodule and PSEAMldr does not ask for vmexit reason*/
		tdx_vmcs = vmcs_pa_to_vmcs(com->current_tdx_vmcs_pa);
		op1_value = tdx_vmcs->vm_exit_reason;

	}
	else if(op0 == VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE){
		/*we might have to reviit this emulation*/
		op1_value = 0;
	}
	else if(op0 == VMX_VM_EXIT_QUALIFICATION_ENCODE){
		/*we might have to reviit this emulation*/
		tdx_vmcs = vmcs_pa_to_vmcs(com->current_tdx_vmcs_pa);
		op1_value = tdx_vmcs->vm_exit_qualification;
	}
	else if(op0 ==  VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE){
		/*we might have to reviit this emulation*/
		op1_value = 0x0;
	}
	else if(op0 == VMX_GUEST_RIP_ENCODE){
		/*we might have to revisit this emulation to give the TDX module an illution of the TD being executed*/
		
		/*FIXME: check com->current_tdx_vmcs_pa becomes 0 in TDG_SYS_RD.*/
		if(com->current_tdx_vmcs_pa){
			tdx_vmcs = vmcs_pa_to_vmcs(com->current_tdx_vmcs_pa);
			op1_value == tdx_vmcs->rip;
		}
		else{
			op1_value = TD_START_RIP;
		}
	}
	else if(op0 == VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE){
		/*we might have to reviit this emulation*/
		op1_value = 0;
	}
	else if(op0 == VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE){
		/*we might have to reviit this emulation*/
		op1_value = 0;
	}
	else if(op0 == VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE){
		/*we might have to reviit this emulation*/
		op1_value = 0;
	}
	else if(op0 == VMX_GUEST_IA32_EFER_FULL_ENCODE){
		ia32_efer_t efer;
		efer.raw = 0;

		efer.lma = 1;
		op1_value = efer.raw;
	}
	else if(op0 == VMX_GUEST_CS_ARBYTE_ENCODE){
		seg_arbyte_t cs_ar;
		cs_ar.raw = 0;

		cs_ar.l = 1;
		op1_value = cs_ar.raw;
	}
	else if(op0 == VMX_VM_ENTRY_INTR_INFO_ENCODE){
		op1_value = 0;
	}
	else if(op0 == VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE){
		op1_value = 1;
	}
	else if(op0 == VMX_GUEST_INTERRUPTIBILITY_ENCODE){
		op1_value = 0;
	}
	else if(op0 == VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE){
		op1_value = 0;
	}
	else if(op0 == VMX_GUEST_RFLAGS_ENCODE){
		op1_value = 2 | (1UL << 9) ; /*default val?*/
	}
	else if(op0 == VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE){
		/*do nothing for now*/
	}
	else{
		/*unhandled vmread field, we return false so emulate_ins() can terminate by issuing a HCALL*/
		return false;
	}

	/*now check the destination operand and update
	op1 can be memor reg, 
	if mem, we expect that to be in the form of an offset to a reg value: eg: $0x10(%rsp)
	either case get the register number and find where it is saved.
	if op1 is a mem operand, add the offset*/
	reg1 = idata[insdata_idx].op1.reg;
	ptr_to_saved_reg_val = get_saved_reg_adr(reg1);
	if(idata[insdata_idx].op1.is_addr == true){ 
		op1 = *ptr_to_saved_reg_val + idata[insdata_idx].op1.offset;
		/*tmp1 = idata[insdata_idx].op1.offset;
		*(uint64_t *)op1 = op1_value;
		asm volatile("movq %0, %%rax; \n\t"
					"movq %1, %%rbx; \n\t"
					"movq %2, %%rcx; \n\t"
					::"m"(op1_value), "m"(tmp1), "m"(op1):"%rax", "%rbx", "%rcx");
		hlt();*/
	}
	else{
		op1 = *ptr_to_saved_reg_val;
	}
	*(uint64_t *)op1 = op1_value;

	/*ulong tmp = target_rsp[4];
	tmp += 0x10;
	ulong val = *(ulong *)tmp;
	asm volatile("movq %0, %%rax; \n\t"
				"movq %1, %%rbx; \n\t"
				"movq %2, %%rcx; \n\t"
				"movq %3, %%rdx; \n\t"
				::"m"(target_rsp[4]), "m"(tmp), "m"(val), "m"(target_rsp):"%rax", "%rbx", "%rcx", "%rdx");
	hlt();*/

	/*update eflags as per: intel manual -> sec VMX ins -> conventions
	to notify the vmread success*/
	vmsucceed_rflags_update();

	return true;
}

void handle_seamops(){
	uint64_t leaf;

	leaf = *(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RAX_OFFSET);
	if(leaf == 0){ /*seamops capabilities*/
		/*we assume to have all 6 capabilities
		the capabilities are expected in the form of a bitmap. bit0 cap1, bit1 cap2 ans so on*/
		update_saved_reg64(RAX, 0x3f); /*0b00111111*/
	}
	if(leaf == 4){
		/*we need to find out the functionality of SEAMOPS instructions to support emulation
		for the moment just return success*/
		update_saved_reg64(RAX, 0);
	}
	else{

	}
}

void emulate_ins(struct insInfo *ins_info){
	
	uint64_t reg_stack_offset;
	REGS_64 op0_reg, op1_reg;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	ulong *target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));
	ia32_rflags_t saved_rflsgs;
	INS in;

	com->emulated_ins_count++;

	com->int3_adr = ins_info->int3_adr;
	com->int3_ins = ins_info->in;
	// DO_HCALL(HCALL_LOG, CODE_LOG_INT3_TRIGGERED);
	com->int3_adr = 0x0;
	com->int3_ins = START_INS;

	in = ins_info->in;
	/*If a switch contains more than five items, it's implemented using a lookup table or a hash list.
	So we resort to if-else ladder here*/
	if(in == RDGSBASE){
		handle_rdgsbase(ins_info->insdata_idx);
	}
	else if(in == RDFSBASE){
		handle_rdfsbase(ins_info->insdata_idx);
	}
#ifdef EMULATE_MOVDIR64B
	else if(in == MOVDIR64B){
		struct insData *idata;
		uint64_t src_adr;
		uint64_t dst_adr;

		if(com->current_sw == SEAM_SW_PSEAMLDR){
			idata = (struct insData *)com->pseamldr_ins;
		}
		else{
			idata = (struct insData *)com->tdxmodule_ins;
		}

		if(idata[ins_info->insdata_idx].operands_extracted != true){
			/*operands have not been extracted*/
			asm ("movq $0xdeade004, %rax \n");
			hlt();
		}

		op0_reg = idata[ins_info->insdata_idx].op0.reg;
		reg_stack_offset = com->int3_stack_offsets[op0_reg];
		src_adr = *(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset);
		op1_reg = idata[ins_info->insdata_idx].op1.reg;
		reg_stack_offset = com->int3_stack_offsets[op1_reg];

		/*while the disassembly of the libtdx shows as movdir64b (%rdi),%rsi, it should actually be 
		movdir64b (%rdi),es:%rsi So, the destination is also a memory address, not a register.
		movdir64b definition: Move 64-bytes as direct-store with guaranteed 64-byte write atomicity from 
		the source memory operand address to destination memory address specified as offset to ES segment 
		in the register operand.*/
		dst_adr = *(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset);
		int copy_round = 0;
		while(copy_round < 8){
			*(uint64_t *)dst_adr = *(uint64_t *)src_adr;
			// lfence();
			// asm volatile ("mfence; \n");

			copy_round++;
			dst_adr += 8;
			src_adr += 8;
		}
	}
#endif /*EMULATE_MOVDIR64B*/
	else if(in == RDRAND){
		struct insData *idata;
		uint64_t rand_val;

		if(com->current_sw == SEAM_SW_PSEAMLDR){
			idata = (struct insData *)com->pseamldr_ins;
			rand_val = PSEAMLDR_RDRAND_VAL;
		}
		else{
			idata = (struct insData *)com->tdxmodule_ins;
			rand_val = TDXMODULE_RDRAND_VAL;
		}

		if(idata[ins_info->insdata_idx].operands_extracted != true){
			/*operands have not been extracted*/
			asm ("movq $0xdeade005, %rax \n");
			hlt();
		}
		op0_reg = idata[ins_info->insdata_idx].op0.reg;
		reg_stack_offset = com->int3_stack_offsets[op0_reg];

		*(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset) = rand_val;

		/*set CF = 1 to indicate rdrand's success, this is checked by pseamldr/tdxmodule
		also set OF, SF, ZF, AF, and PF flags to 0*/
		saved_rflsgs.raw = target_rsp[3];
		saved_rflsgs.cf = 1;
		saved_rflsgs.of = 0;
		saved_rflsgs.sf = 0;
		saved_rflsgs.zf = 0;
		saved_rflsgs.af = 0;
		saved_rflsgs.pf = 0;
		target_rsp[3] = saved_rflsgs.raw; 
	}
	else if(in == RDSEED){
		struct insData *idata;
		uint64_t seed_val;

		if(com->current_sw == SEAM_SW_PSEAMLDR){
			/*pseamldr does not have rdseed ins*/
			asm ("movq $0xdeade006, %rax \n");
			hlt();
		}
		else{
			idata = (struct insData *)com->tdxmodule_ins;
			seed_val = com->current_seed;
			com->current_seed++;
		}	

		if(idata[ins_info->insdata_idx].operands_extracted != true){
			/*operands have not been extracted*/
			asm ("movq $0xdeade007, %rax \n");
			hlt();
		}
		op0_reg = idata[ins_info->insdata_idx].op0.reg;
		reg_stack_offset = com->int3_stack_offsets[op0_reg];	

		*(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset) = seed_val;

		/*set CF = 1 to indicate rdseed's success,
		also set OF, SF, ZF, AF, and PF flags to 0*/
		saved_rflsgs.raw = target_rsp[3];
		saved_rflsgs.cf = 1;
		saved_rflsgs.of = 0;
		saved_rflsgs.sf = 0;
		saved_rflsgs.zf = 0;
		saved_rflsgs.af = 0;
		saved_rflsgs.pf = 0;
		target_rsp[3] = saved_rflsgs.raw; 				
	}
	else if(in == VMWRITE){
		/*TODO: No need to pass VMWRITEs to SEAM manager for amulation as of now. Port the functionality 
		in to SEAM agent*/
		
		/*See emulation support from SEAM manager.*/
		set_int3_ins_info((struct insInfo *)&com->int3_ins_info, ins_info);
		//DO_HCALL(HCALL_EMULATE_PSEAMLDR_INS, CODE_NONE);
		clear_int3_ins_info((struct insInfo *)&com->int3_ins_info);

		/*set CF = zf = 0 to indicate vmwrite's success, this is checked by pseamldr/trdmodule
		also set the remaining flags to 0*/
		saved_rflsgs.raw = target_rsp[3];
		saved_rflsgs.cf = 0;
		saved_rflsgs.of = 0;
		saved_rflsgs.sf = 0;
		saved_rflsgs.zf = 0;
		saved_rflsgs.af = 0;
		saved_rflsgs.pf = 0;
		target_rsp[3] = saved_rflsgs.raw; 
	}
	else if(in == VMREAD){
		if(handle_vmread(ins_info->insdata_idx) == false){
			set_int3_ins_info((struct insInfo *)&com->int3_ins_info, ins_info);
			DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_VMREAD_FIELD);
			/*we do not come back here*/
		}
	}
	else if(in == VMCLEAR){ /*needs fixing*/
		/*Do nothing for the moment as we do not run the real TD*/
	}
	else if(in == VMPTRLD){

		struct insData *idata;
		uint64_t src_adr, ofst, mem_val, reg_val, vmcs_pa;

		if(com->current_sw == SEAM_SW_PSEAMLDR){
			asm ("movq $0xdeade008, %rax \n");
			hlt();
		}
		else{
			idata = (struct insData *)com->tdxmodule_ins;
		}
		if(idata[ins_info->insdata_idx].operands_extracted == false){
			asm ("movq $0xdeade009, %rax \n");
			hlt();
		}
		op0_reg = idata[ins_info->insdata_idx].op0.reg;
		ulong reg = (unsigned long)op0_reg;
		
		reg_val = get_saved_reg_value(op0_reg);
		if(reg_val == 0){
			asm ("movq $0xdeade010, %rax \n");
			hlt();
		}
		ofst = idata[ins_info->insdata_idx].op0.offset;
		src_adr = reg_val + ofst;
		mem_val = *(uint64_t *)src_adr;
		vmcs_pa = mem_val & ~(HKID_MASK); /*Detatch HKID*/
		com->current_tdx_vmcs_pa = vmcs_pa;
		/*asm ("movq %0, %%rax \n"
			 "movq %1, %%rbx \n"
			 "hlt; \n"
		::"m"(mem_val), "m"(vmcs_pa):"%rax", "%rbx");*/

		/*set CF = zf = 0 to indicate vmptrld's success, this is checked by pseamldr/trdmodule
		also set the remaining flags to 0*/
		saved_rflsgs.raw = target_rsp[3];
		saved_rflsgs.cf = 0;
		saved_rflsgs.of = 0;
		saved_rflsgs.sf = 0;
		saved_rflsgs.zf = 0;
		saved_rflsgs.af = 0;
		saved_rflsgs.pf = 0;
		target_rsp[3] = saved_rflsgs.raw; 
	}
	else if(in == RDMSR){
		handle_rdmsr();		
	}
	else if(in == CPUID){
		handle_cpuid();
	}
	else if(in == SEAMRET){
		DO_HCALL(HCALL_SEAMRET, CODE_NONE);
		/*we don't expect to come back here. next seam manager will do a new SEAMCALL*/
	}
	else if(in == VMLAUNCH){
		DO_HCALL(HCALL_VMLAUNCH, CODE_NONE);
		/*we don't expect to come back here. next seam manager will do a new tdxcall*/
	}
	else if(in == VMRESUME){
		DO_HCALL(HCALL_VMRESUME, CODE_NONE);
		/*we don't expect to come back here. next seam manager will do a new tdxcall*/
	}
	else if(in == WRMSR){
		handle_wrmsr();
	}
	else if(in == SEAMOPS){
		handle_seamops();
	}
	else if(in == INVEPT){
		/*we do not actually do any invalidation at the moment.
		set CF = zf = 0 to indicate vmwrite's success, this is checked by pseamldr/trdmodule
		also set the remaining flags to 0*/
		saved_rflsgs.raw = target_rsp[3];
		saved_rflsgs.cf = 0;
		saved_rflsgs.of = 0;
		saved_rflsgs.sf = 0;
		saved_rflsgs.zf = 0;
		saved_rflsgs.af = 0;
		saved_rflsgs.pf = 0;
		target_rsp[3] = saved_rflsgs.raw; 
	}
	else if(in == PCONFIG){
		/*we do not do a real job of pconfig, just set the return values as per the intel manual*/
		saved_rflsgs.raw = target_rsp[3];
		saved_rflsgs.zf = 0;
		target_rsp[3] = saved_rflsgs.raw;
		*(uint64_t *)(SAVED_TARGET_CPU_STATE - AGENT_STACK_RAX_OFFSET) = 0;
	}
#ifdef EMULATE_XGETBV
	else if(in == XGETBV){
		/*do nothing for the moment
		If emulating, implement operands extraction in instrument.c*/
	}
#endif /*EMULATE_XGETBV*/
	else{
		DO_HCALL(HCALL_SEAM_ERROR, CODE_UNHANDLED_INS);
	}

}

void serve_interpreter(){
	
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	void *seam_adr = com->sreq.seam_va; 

	if(com->sreq.req == SERVREQ_READ_MEM){
		com->sreq.data = 0;
		if(com->sreq.data_size == 1){
			com->sreq.data = *(char *)seam_adr;
		}
		else if(com->sreq.data_size == 2){
			com->sreq.data = *(short *)seam_adr;
		}
		else if(com->sreq.data_size == 4){
			com->sreq.data = *(int *)seam_adr;
		}
		else if(com->sreq.data_size == 8){
			com->sreq.data = *(long *)seam_adr;
		}
		else {
			asm ("movq $0xdeade0011, %rax \n");
			hlt();
		}
	}
	else if(com->sreq.req == SERVREQ_WRITE_MEM){
		if(com->sreq.data_size == 1){
			*(char *)seam_adr = (char *)com->sreq.data;
		}
		else if(com->sreq.data_size == 2){
			*(short *)seam_adr = (short *)com->sreq.data;
		}
		else if(com->sreq.data_size == 4){
			*(int *)seam_adr = (int *)com->sreq.data;
		}
		else if(com->sreq.data_size == 8){
			*(long *)seam_adr = (long *)com->sreq.data;
		}
		else {
			asm ("movq $0xdeade012, %rax \n");
			hlt();
		}
	}
	else if(com->sreq.req == SERVREQ_BACKUP_PAGE){
		unsigned long pagePool4K = ((ulong)&com->sreq.pg_pool + 0xfff);
    	pagePool4K = ((ulong)pagePool4K + 0xfff) & VA_TO_PG_VA_MASK;
		memcpy((uint8_t *)(pagePool4K + _4K*com->sreq.bkp_pg_count), (uint8_t *)com->sreq.seam_pg_va, _4K);
	}
	else if(com->sreq.req == SERVREQ_RESTORE_PAGE){
		unsigned long pagePool4K = ((ulong)&com->sreq.pg_pool + 0xfff);
    	pagePool4K = ((ulong)pagePool4K + 0xfff) & VA_TO_PG_VA_MASK;
		memcpy((uint8_t *)com->sreq.seam_pg_va, (uint8_t *)(pagePool4K + _4K*com->sreq.bkp_pg_count), _4K);
	}
	else if(com->sreq.req == SERVREQ_READ_PAGE){
		memcpy((uint8_t *)(com->sreq.page_data), (uint8_t *)com->sreq.seam_pg_va, _4K);
	} 
	else {
		asm ("movq $0xdeade013, %rax \n");
		hlt();
	}

}

void se_dispatcher(){

	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	com->sreq.req_owner = SERVREQ_OWNER_INTERPRETER;
	com->se.target_owner = TARGET_OWNER_INTERPRETER;
	while(com->se.target_owner == TARGET_OWNER_INTERPRETER){
		asm volatile ("mfence; \n");

		if(com->sreq.terminate == 1){
			DO_HCALL(HCALL_END_OF_ANALYSIS, CODE_NONE);
		}
		while(com->sreq.req_owner == SERVREQ_OWNER_S_AGENT){ /*a service request from KRover*/
			serve_interpreter();
			com->sreq.req_owner = SERVREQ_OWNER_INTERPRETER;
			lfence();
			asm volatile ("mfence; \n");

		}
	}
}

void __attribute__ ((noinline)) int3_handler(){

	volatile struct insInfo ins_info;
	REGS_64 op0_reg;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	volatile ulong *target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));

	if(com->current_sw == SEAM_SW_TDXMODULE && com->seam_state == SE_START_SEAM_STATE){

		while(true){
			se_dispatcher();

			ins_info.int3_adr = target_rsp[1];
			ins_info.in = START_INS;
			ins_info.insdata_idx = 0;

			if(int3_adr_to_ins(&ins_info) == false){
				/*if the instruction is to be natively executed, let it run*/
				return;
			}
			ins_info.emu_req_from_interpreter = true;
			emulate_ins(&ins_info);
			target_rsp[1] = target_rsp[1] + com->tdxmodule_ins[ins_info.insdata_idx].size;
		}
	}
	else if(com->current_sw == SEAM_SW_TDXMODULE && com->seam_state != SE_START_SEAM_STATE){
		ins_info.int3_adr = target_rsp[1] - 1;
		ins_info.in = START_INS;
		ins_info.insdata_idx = 0;

		if(int3_adr_to_ins(&ins_info) == false){
		/*int3 is not triggered at a special instruction*/
		#ifdef INSTRUCTION_TRACER_ON
				com->int3_adr = ins_info.int3_adr;
				com->regular_ins_count++;
				DO_HCALL(HCALL_TRACE_INS, CODE_NONE);
				return;
		#endif
		}
		ins_info.emu_req_from_interpreter = false;
		emulate_ins(&ins_info);

		target_rsp[1] = target_rsp[1] - 1 + com->tdxmodule_ins[ins_info.insdata_idx].size;
	}
	else {

		ins_info.int3_adr = target_rsp[1] - 1;
		ins_info.in = START_INS;
		ins_info.insdata_idx = 0;
		if(int3_adr_to_ins(&ins_info) == false){
		/*int3 is not triggered at a special instruction*/
		#ifdef INSTRUCTION_TRACER_ON
				com->int3_adr = ins_info.int3_adr;
				com->regular_ins_count++;
				DO_HCALL(HCALL_TRACE_INS, CODE_NONE);
				return;
		#endif
		}
		ins_info.emu_req_from_interpreter = false;
		emulate_ins(&ins_info);

		target_rsp[1] = target_rsp[1] - 1 + com->pseamldr_ins[ins_info.insdata_idx].size;

	}

}

void __attribute__ ((noinline)) de_handler(){

	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	volatile ulong *target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));
	ulong de_rip = target_rsp[1];
	ulong dr_num;

	//remove the bp,
	ulong dr6, dr7;
	asm ("movq %%dr6, %%rax\n"
		 "movq %%rax, %0\n"
		 "movq %%dr7, %%rbx\n"
		 "movq %%rbx, %1\n"
		     :"=m"(dr6), "=m"(dr7):: "%rax", "%rbx");
	
	//check if single step of DR bp
	if(dr6 & DR6_SINGLE_STEP_MASK){
		int3_handler();
	}
	else if(dr6 & DR6_CUR_BP_MASK){                        /*dr0-dr3 bp trigger*/

		dr_num = max_bit_in_4bits(dr6 & DR6_CUR_BP_MASK);
		if(dr_num > 0x3){
			asm ("movq $0xdeade014, %rax \n");
			hlt();                                         /*invalid dr*/
		}

		/*remove the debug bp now*/
		dr7 &= ~(1UL << dr_num*2);
		asm ("movq %0, %%rax\n"
		 	 "movq %%rax, %%dr7\n"
		     ::"m"(dr7): "%rax");

		/*enable single step. We're starting SE now and all native exec-NE ins must single step now*/
		target_rsp[3] |= (1UL << 8);  /*trap flag is bit 8 of EFLAGS*/
		com->single_step_on = true;   /*mark as enabled for the use if there are subsequent SEAMCALLs.*/
		/*enable SE now*/
		com->seam_state = SEAM_STATE_TEMP;
		int3_handler();
	}
	else{
		asm ("movq $0xdbdbdead, %rax");
		hlt();
	}
	return;
}

void MktmeError(){

	asm("ud2; \n");
}

void __attribute__ ((noinline)) validateMktme(ulong pte){

	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	ulong td = com->td_owner_for_next_tdxcall;
	ulong executing_td_context;
	
	ulong page_pa = (pte & PTE_TO_PA_MASK);
	ulong pfn = page_pa >> 12;
	ulong secure_page_idx = pfn - (TDX_TDMR0_START_PA >> 12);
	ulong hkid = (pte & HKID_MASK) >> HKID_START_BIT;

	securePage *sp = (securePage *)&com->sreq.secPages[secure_page_idx];
	ulong a = sp->raw;
	ulong b = sp->mdata.hkid;
	ulong c = sp->mdata.base_pa;
	com->khole_data.last_khole_edit_pte =  pte;

	if(page_pa < TDX_PAMT0_START_PA){ /*If not a PAMT page, i.e. this is a TD page*/

		/*check if the hkid has a configured key on the platform*/
		if((hkid < TDX_GLOBAL_PRIVATE_HKID) || (hkid >= com->next_td_hkid)){
			MktmeError();
			DO_HCALL(HCALL_MKTME_ERROR, CODE_HKID_UNCONFIGURED);
		}
		/*check if the hkid used is the valid hkid for the page*/
		else if(sp->mdata.hkid != hkid){
			MktmeError();
			DO_HCALL(HCALL_MKTME_ERROR, CODE_HKID_INVALID_FOR_PAGE);
		}
		/*check if the hkid used is valid in the current TD context*/
		else if(sp->mdata.td != com->sreq.td_owner_for_next_tdxcall){
			MktmeError();
			DO_HCALL(HCALL_MKTME_ERROR, CODE_HKID_INVALID_TD_CONTEXT);
		}
	}
	else{ /*This is a PAMT page, not a TD page*/
		if(hkid != TDX_GLOBAL_PRIVATE_HKID){
			DO_HCALL(HCALL_MKTME_ERROR, CODE_HKID_INVALID_FOR_PAGE);
		}
	}

	return true;
}


/*keyhole edit happnes as follows. The mov instruction writes a PTE value
and the mov instruction is in the following format.
	0f 01 cb             	stac   
	4a 89 14 f1          	mov    %rdx,(%rcx,%r14,8)
 	0f 01 ca             	clac */
void emulate_khole_edit(ulong rip, ulong pfadr, ulong *saved_rip){
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	int idx;
	ulong src, dst_adr, reg_val1, reg_val2, reg_stack_offset, hkid;

	if(rip == com->khole_data.idata[0].va){
		idx = 0;
	}
	else if(rip == com->khole_data.idata[1].va){
		idx = 1;
	}
	else {
		asm ("movq $0xdeade015, %rax \n");
		hlt();
	}

	reg_stack_offset = com->int3_stack_offsets[com->khole_data.idata[idx].reg0];
	src = *(uint64_t *)(SAVED_TARGET_CPU_STATE - reg_stack_offset);

	com->khole_data.last_khole_edit_pte =  src;
	com->khole_data.last_khole_edit_pte_adr = pfadr;
	com->sreq.last_khole_pte = src;
	com->sreq.last_keyhole_edit_va = pfadr;

	/*DO_HCALL(HCALL_INSPECT_KHOLES, CODE_NONE);*/

	if(src & PTE_PRESENT){
		com->khole_data.khole_map_count++;
	}
	else{
		com->khole_data.khole_free_count++;
	}

#ifdef ENABLE_MKTME_EMULATION
	src &= ~(PTE_PRESENT);  /*mark the PTE as not present to catch the first access*/
#else
	src &= ~(HKID_MASK); 	/*detatch the hkid from  the pa in PTE*/
#endif

	/*We do not need to derive the destination address, it is the pf adr. In TDX mod's pml4, 
	we have dissabled writes to khole edit to detect the writes. However, in seam'agent's pml4, 
	there is no such restriction. Hence we can emulate the write.*/
	*(uint64_t *)pfadr = src;

	/*now update the rip*/
	*saved_rip = *saved_rip + 4;
	/*after iret, the instruction after pf ins is executed in SEAM env.
	If Interpreter is running, it does not se this instruction.*/

}

BOOL is_pf_in_khole_edit(ulong pfadr){

	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	if((pfadr >= com->khole_data.khole_edit_rgn_base) && 
		(pfadr < (com->khole_data.khole_edit_rgn_base + com->khole_data.khole_edit_rgn_size))){
		return true;
	}

	return false;
}

BOOL is_pf_in_khole(ulong pfadr){
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	if((pfadr >= com->khole_data.khole_rgn_base) && 
		(pfadr < (com->khole_data.khole_rgn_base + com->khole_data.khole_rgn_size))){
		return true;
	}

	return false;

}

ulong *va_to_key_hole_pte(ulong va){

	ulong global_key_hole_idx = 0;
	ulong max_key_hole_idx = (EFFECTIVE_NUM_ADDRESSIBLE_LPS)*128;
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	global_key_hole_idx = ((va & PAGE_ADR_MASK) - com->khole_data.khole_rgn_base) >> 12; /*shift is to divide by 4K page size to get idx*/

	if(global_key_hole_idx >= max_key_hole_idx){
		asm ("movq $0xdead102, %rax \n");
		hlt();
	}
	return (ulong *)(com->khole_data.khole_edit_rgn_base + 8*global_key_hole_idx);
}

emulate_mktme(ulong pfadr, ulong errcode){
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);

	ulong *pte_p = va_to_key_hole_pte(pfadr);
	ulong pte = *pte_p;
	ulong hkid;
	ulong page_pa = (pte & PTE_TO_PA_MASK);
	ulong pfn = page_pa >> 12;
	ulong secure_page_idx = pfn - (TDX_TDMR0_START_PA >> 12);

	securePage *sp = (securePage *)&com->sreq.secPages[secure_page_idx];

	// pte &= ~(1UL << (PF_GEN_PTE_BIT)); /*detatch the reserved bit set to get a PF*/
	// pte &= (PTE_PRESENT);
	hkid = (pte & HKID_MASK) >> HKID_START_BIT;

	/*if write*/
	if(errcode & 0x2){

		/*update the page associated keyid with the keyID in the mapping*/
		sp->mdata.hkid = hkid;
	}
	else{ /*if read*/

		/*check whether the present keyid in use matches the page’s associated keyID*/
		if(hkid != sp->mdata.hkid){
			//error
			DO_HCALL(HCALL_MKTME_ERROR, CODE_HKID_INVALID_FOR_PAGE);
		}
	}

	/*now handle PF by marking the PTE as present, also detatch HKID*/
	pte &= ~(HKID_MASK); 	/*detatch the hkid from the pa in PTE*/
	pte |= PTE_PRESENT;  /*mark the PTE as present to stop further PFs*/
	*pte_p = pte; /*write the updated pte to keyhole PTE*/
}

void __attribute__ ((noinline)) pf_handler(){
	
	struct comArea *com = (struct comArea *)(SEAM_AGENT_MGR_SHARED_AREA);
	volatile ulong *target_rsp = (ulong *)(*(ulong *)(SAVED_TARGET_CPU_STATE - 0x8));
	volatile ulong pfadr;
	volatile ulong errcode;
	volatile ulong pfrip;

	errcode = target_rsp[1];
	pfrip = target_rsp[2];
	asm ("movq %%cr2, %%rax \n"
		"movq %%rax, %0 \n"
		:"=m"(pfadr)::"%rax");

	if(is_pf_in_khole_edit(pfadr)){

		/*to check if any read to kholeEditRgn*/
		/*com->pf_adr = pfadr;
		com->pf_rip = pfrip;
		com->pf_errcode = errcode;
		DO_HCALL(HCALL_LOG, CODE_KHOLE_EDIT_ACCESS);*/
		if(errcode != 0x2){
			asm ("movq $0xdead1, %%rax \n"
				"movq %0, %%rbx \n"
				"movq %1, %%rcx \n"
				::"m"(pfrip), "m"(errcode): "%rax", "%rbx", "%rcx");
			hlt();
		}
		
		emulate_khole_edit(pfrip, pfadr, &target_rsp[2]);
	}
	else if(is_pf_in_khole(pfadr)){

		/*We expect PTE not present PFs from KeyHoles, This flag is zero if PTE P flag is 0*/
		if((errcode & 0x1) != 0){ 
			asm ("movq $0xdeade011, %rax \n");
			hlt();
		}
		emulate_mktme(pfadr, errcode);
	}
	else{
		asm ("movq $0xdead2, %%rax \n"
			 "movq %0, %%rbx \n"
			 "movq %1, %%rcx \n"
			 "movq %2, %%rdx \n"
		     ::"m"(pfrip), "m"(errcode), "m"(pfadr): "%rax", "%rbx", "%rcx", "%rdx");
		hlt();
	}

}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

/*int3 and de handler start ------------------------------------------*/
	asm ("pushq %r15"); /*backup %r15 in target stack*/
	asm ("movq %rsp, %r15 \n");
	asm ("pushq %r14"); /*backup %r14 in target stack*/
	/*hardware saved state in target stack
				+40: saced ss
				+32: saved rsp
				+24: saved rflags
				+16: saved cs
				+8 : saved rip
	%r15 -->	0 : pushed r15 (HW did not push this, we did)
				8 : pushed r14 (HW did not push this, we did)*/
	asm ("movq %0, %%rsp \n"
		::"i"(SEAM_EXCEPTION_STACK):);	/*switch to dedicated exception stack*/
	/*copy interrupt stack frame to dedicated exception stack*/
	asm ("movq 0x28(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x20(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x18(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x10(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x8(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x0(%r15), %r14 \n");
	asm ("pushq %r14 \n");	

	asm ("movq -0x8(%r15), %r14"); /*restore saved %r14*/
	asm ("movq %rsp, %r15 \n"); 
	asm ("movq %0, %%rsp \n"
		::"i"(SAVED_TARGET_CPU_STATE):);	/*switch to agent's stack*/

	/*next save target rsp in agent stack followed by the remaining regs
	IMPORTANT !!! DO NOT change the ORDER of the OFFSETs from SAVED_TARGET_CPU_STATE
	if changed, update constants in emulator.h*/
	asm ("pushq %r15 \n");	/*SEAM_AGENT_STACK -0x8  	AGENT_STACK_MINUS_0x8*/
	asm ("pushq %rax \n");	/*SEAM_AGENT_STACK -0x10	AGENT_STACK_MINUS_0x10*/
	asm ("pushq %rbx \n");	/*SEAM_AGENT_STACK -0x18	AGENT_STACK_MINUS_0x18*/
	asm ("pushq %rcx \n");	/*SEAM_AGENT_STACK -0x20	AGENT_STACK_MINUS_0x20*/
	asm ("pushq %rdx \n");	/*SEAM_AGENT_STACK -0x28	AGENT_STACK_MINUS_0x28*/
	asm ("pushq %rdi \n");	/*SEAM_AGENT_STACK -0x30	AGENT_STACK_MINUS_0x30*/
	asm ("pushq %rsi \n");	/*SEAM_AGENT_STACK -0x38	AGENT_STACK_MINUS_0x38*/
	asm ("pushq %rbp \n");	/*SEAM_AGENT_STACK -0x40	AGENT_STACK_MINUS_0x40*/
	asm ("pushq %r8 \n");	/*SEAM_AGENT_STACK -0x48	AGENT_STACK_MINUS_0x48*/
	asm ("pushq %r9 \n");	/*SEAM_AGENT_STACK -0x50	AGENT_STACK_MINUS_0x50*/
	asm ("pushq %r10 \n");	/*SEAM_AGENT_STACK -0x58	AGENT_STACK_MINUS_0x58*/
	asm ("pushq %r11 \n");	/*SEAM_AGENT_STACK -0x60	AGENT_STACK_MINUS_0x60*/
	asm ("pushq %r12 \n");	/*SEAM_AGENT_STACK -0x68	AGENT_STACK_MINUS_0x68*/
	asm ("pushq %r13 \n");	/*SEAM_AGENT_STACK -0x70	AGENT_STACK_MINUS_0x70*/
	asm ("pushq %r14 \n");	/*SEAM_AGENT_STACK -0x78	AGENT_STACK_MINUS_0x78*/
	/*no point in pushing the rflags as the int3 has already pushed it on to target stack*/

	asm ("movq %cr3, %rax \n");
	asm ("pushq %rax \n");
	asm ("movq %0, %%rbx \n"
		"movq %%rbx, %%cr3 \n"
		::"i"(SEAM_AGENT_PT_BASE_PA):);
	
	asm ("movq %rsp, %r15 \n"); 
	asm ("movq %0, %%rsp \n"
		::"i"(SEAM_EMULATOR_STACK):);	/*switch to emulator's stack*/
	asm ("pushq %r15 \n");              
	/*Above push makes the stack 16-byte aligned, bacause SEAM_EMULATOR_STACK = <some page boundary> -0x8 */

	asm ("callq int3_handler \n");

	asm ("popq %r15 \n");				/*restore agent's rsp into r15*/
	asm ("movq %r15, %rsp \n"); 

	asm ("popq %rax \n");
	asm ("movq %rax, %cr3 \n");

	asm ("popq %r14 \n");
	asm ("popq %r13 \n");
	asm ("popq %r12 \n");
	asm ("popq %r11 \n");
	asm ("popq %r10 \n");
	asm ("popq %r9 \n");
	asm ("popq %r8 \n");
	asm ("popq %rbp \n");
	asm ("popq %rsi \n");
	asm ("popq %rdi \n");
	asm ("popq %rdx \n");
	asm ("popq %rcx \n");
	asm ("popq %rbx \n");
	asm ("popq %rax \n");
	asm ("popq %r15 \n");		/*restore top of exception stack frame into r15*/
	asm ("movq %r15, %rsp \n"); /*switch back to excption stack frame*/
	asm ("popq %r15 \n");
	asm ("iretq \n");
/*int3 and de handler end ------------------------------------------*/

	/*we need to have a fixed offset, 0x200 for the start of the pf handler.
	therefore, we pad the int3 handler code with nop upto offset 0x200*/
	asm (".align 0x200");

/*pf handler start -------------------------------------------------*/
	asm ("pushq %r15"); /*backup %r15 in target stack*/
	asm ("movq %rsp, %r15 \n");
	asm ("pushq %r14"); /*backup %r14 in target stack*/
	/*hardware saved state in target stack
				+48: saced ss
				+40: saved rsp
				+32: saved rflags
				+24: saved cs
				+16 : saved rip
				+8 : error code
	%r15 -->	0 : pushed r15 (HW did not push this, we did)
				8 : pushed r14 (HW did not push this, we did)*/
	asm ("movq %0, %%rsp \n"
		::"i"(SEAM_EXCEPTION_STACK):);	/*switch to dedicated exception stack*/
	/*copy interrupt stack frame to dedicated exception stack*/
	asm ("movq 0x30(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x28(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x20(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x18(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x10(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x8(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x0(%r15), %r14 \n");
	asm ("pushq %r14 \n");	

	asm ("movq -0x8(%r15), %r14"); /*restore saved %r14*/
	asm ("movq %rsp, %r15 \n"); 
	asm ("movq %0, %%rsp \n"
		::"i"(SAVED_TARGET_CPU_STATE):);	/*switch to agent's stack*/

	/*next save target rsp in agent stack followed by the remaining regs
	IMPORTANT !!! DO NOT change the ORDER of the OFFSETs from SAVED_TARGET_CPU_STATE
	if changed, update constants in emulator.h*/
	asm ("pushq %r15 \n");	/*SEAM_AGENT_STACK -0x8  	AGENT_STACK_MINUS_0x8*/
	asm ("pushq %rax \n");	/*SEAM_AGENT_STACK -0x10	AGENT_STACK_MINUS_0x10*/
	asm ("pushq %rbx \n");	/*SEAM_AGENT_STACK -0x18	AGENT_STACK_MINUS_0x18*/
	asm ("pushq %rcx \n");	/*SEAM_AGENT_STACK -0x20	AGENT_STACK_MINUS_0x20*/
	asm ("pushq %rdx \n");	/*SEAM_AGENT_STACK -0x28	AGENT_STACK_MINUS_0x28*/
	asm ("pushq %rdi \n");	/*SEAM_AGENT_STACK -0x30	AGENT_STACK_MINUS_0x30*/
	asm ("pushq %rsi \n");	/*SEAM_AGENT_STACK -0x38	AGENT_STACK_MINUS_0x38*/
	asm ("pushq %rbp \n");	/*SEAM_AGENT_STACK -0x40	AGENT_STACK_MINUS_0x40*/
	asm ("pushq %r8 \n");	/*SEAM_AGENT_STACK -0x48	AGENT_STACK_MINUS_0x48*/
	asm ("pushq %r9 \n");	/*SEAM_AGENT_STACK -0x50	AGENT_STACK_MINUS_0x50*/
	asm ("pushq %r10 \n");	/*SEAM_AGENT_STACK -0x58	AGENT_STACK_MINUS_0x58*/
	asm ("pushq %r11 \n");	/*SEAM_AGENT_STACK -0x60	AGENT_STACK_MINUS_0x60*/
	asm ("pushq %r12 \n");	/*SEAM_AGENT_STACK -0x68	AGENT_STACK_MINUS_0x68*/
	asm ("pushq %r13 \n");	/*SEAM_AGENT_STACK -0x70	AGENT_STACK_MINUS_0x70*/
	asm ("pushq %r14 \n");	/*SEAM_AGENT_STACK -0x78	AGENT_STACK_MINUS_0x78*/
	/*no point in pushing the rflags as the int3 has already pushed it on to target stack*/

	asm ("movq %cr3, %rax \n");
	asm ("pushq %rax \n");
	asm ("movq %0, %%rbx \n"
		"movq %%rbx, %%cr3 \n"
		::"i"(SEAM_AGENT_PT_BASE_PA):);
	
	asm ("movq %rsp, %r15 \n"); 
	asm ("movq %0, %%rsp \n"
		::"i"(SEAM_EMULATOR_STACK):);	/*switch to emulator's stack*/
	asm ("pushq %r15 \n");              
	/*Above push makes the stack 16-byte aligned, bacause SEAM_EMULATOR_STACK = <some page boundary> -0x8 */

	asm ("callq pf_handler \n");

	asm ("popq %r15 \n");				/*restore agent's rsp into r15*/
	asm ("movq %r15, %rsp \n"); 

	asm ("popq %rax \n");
	asm ("movq %rax, %cr3 \n");

	asm ("popq %r14 \n");
	asm ("popq %r13 \n");
	asm ("popq %r12 \n");
	asm ("popq %r11 \n");
	asm ("popq %r10 \n");
	asm ("popq %r9 \n");
	asm ("popq %r8 \n");
	asm ("popq %rbp \n");
	asm ("popq %rsi \n");
	asm ("popq %rdi \n");
	asm ("popq %rdx \n");
	asm ("popq %rcx \n");
	asm ("popq %rbx \n");
	asm ("popq %rax \n");
	asm ("popq %r15 \n");		/*restore top of exception stack frame into r15*/
	asm ("movq %r15, %rsp \n"); /*switch back to excption stack frame*/
	asm ("popq %r15 \n");
	/*pf exception stack top additionally has the error code, 
	we further modify the rsp to point to saved rip as expected by hw*/
	asm ("addq $0x8, %rsp"); 
	asm ("iretq \n");
/*pf handler end -------------------------------------------------*/
	
	/*we need to have a fixed offset, 0x200 for the start of the pf handler.
	therefore, we pad the int3 handler code with nop upto offset 0x200*/
	asm (".align 0x400");

/*de handler start ------------------------------------------*/
	asm ("pushq %r15"); /*backup %r15 in target stack*/
	asm ("movq %rsp, %r15 \n");
	asm ("pushq %r14"); /*backup %r14 in target stack*/
	/*hardware saved state in target stack
				+40: saced ss
				+32: saved rsp
				+24: saved rflags
				+16: saved cs
				+8 : saved rip
	%r15 -->	0 : pushed r15 (HW did not push this, we did)
				8 : pushed r14 (HW did not push this, we did)*/
	asm ("movq %0, %%rsp \n"
		::"i"(SEAM_EXCEPTION_STACK):);	/*switch to dedicated exception stack*/
	/*copy interrupt stack frame to dedicated exception stack*/
	asm ("movq 0x28(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x20(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x18(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x10(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x8(%r15), %r14 \n");
	asm ("pushq %r14 \n");	
	asm ("movq 0x0(%r15), %r14 \n");
	asm ("pushq %r14 \n");	

	asm ("movq -0x8(%r15), %r14"); /*restore saved %r14*/
	asm ("movq %rsp, %r15 \n"); 
	asm ("movq %0, %%rsp \n"
		::"i"(SAVED_TARGET_CPU_STATE):);	/*switch to agent's stack*/

	/*next save target rsp in agent stack followed by the remaining regs
	IMPORTANT !!! DO NOT change the ORDER of the OFFSETs from SAVED_TARGET_CPU_STATE
	if changed, update constants in emulator.h*/
	asm ("pushq %r15 \n");	/*SEAM_AGENT_STACK -0x8  	AGENT_STACK_MINUS_0x8*/
	asm ("pushq %rax \n");	/*SEAM_AGENT_STACK -0x10	AGENT_STACK_MINUS_0x10*/
	asm ("pushq %rbx \n");	/*SEAM_AGENT_STACK -0x18	AGENT_STACK_MINUS_0x18*/
	asm ("pushq %rcx \n");	/*SEAM_AGENT_STACK -0x20	AGENT_STACK_MINUS_0x20*/
	asm ("pushq %rdx \n");	/*SEAM_AGENT_STACK -0x28	AGENT_STACK_MINUS_0x28*/
	asm ("pushq %rdi \n");	/*SEAM_AGENT_STACK -0x30	AGENT_STACK_MINUS_0x30*/
	asm ("pushq %rsi \n");	/*SEAM_AGENT_STACK -0x38	AGENT_STACK_MINUS_0x38*/
	asm ("pushq %rbp \n");	/*SEAM_AGENT_STACK -0x40	AGENT_STACK_MINUS_0x40*/
	asm ("pushq %r8 \n");	/*SEAM_AGENT_STACK -0x48	AGENT_STACK_MINUS_0x48*/
	asm ("pushq %r9 \n");	/*SEAM_AGENT_STACK -0x50	AGENT_STACK_MINUS_0x50*/
	asm ("pushq %r10 \n");	/*SEAM_AGENT_STACK -0x58	AGENT_STACK_MINUS_0x58*/
	asm ("pushq %r11 \n");	/*SEAM_AGENT_STACK -0x60	AGENT_STACK_MINUS_0x60*/
	asm ("pushq %r12 \n");	/*SEAM_AGENT_STACK -0x68	AGENT_STACK_MINUS_0x68*/
	asm ("pushq %r13 \n");	/*SEAM_AGENT_STACK -0x70	AGENT_STACK_MINUS_0x70*/
	asm ("pushq %r14 \n");	/*SEAM_AGENT_STACK -0x78	AGENT_STACK_MINUS_0x78*/
	/*no point in pushing the rflags as the int3 has already pushed it on to target stack*/

	asm ("movq %cr3, %rax \n");
	asm ("pushq %rax \n");
	asm ("movq %0, %%rbx \n"
		"movq %%rbx, %%cr3 \n"
		::"i"(SEAM_AGENT_PT_BASE_PA):);
	
	asm ("movq %rsp, %r15 \n"); 
	asm ("movq %0, %%rsp \n"
		::"i"(SEAM_EMULATOR_STACK):);	/*switch to emulator's stack*/
	asm ("pushq %r15 \n");              
	/*Above push makes the stack 16-byte aligned, bacause SEAM_EMULATOR_STACK = <some page boundary> -0x8 */

	asm ("callq de_handler \n");

	asm ("popq %r15 \n");				/*restore agent's rsp into r15*/
	asm ("movq %r15, %rsp \n"); 

	asm ("popq %rax \n");
	asm ("movq %rax, %cr3 \n");

	asm ("popq %r14 \n");
	asm ("popq %r13 \n");
	asm ("popq %r12 \n");
	asm ("popq %r11 \n");
	asm ("popq %r10 \n");
	asm ("popq %r9 \n");
	asm ("popq %r8 \n");
	asm ("popq %rbp \n");
	asm ("popq %rsi \n");
	asm ("popq %rdi \n");
	asm ("popq %rdx \n");
	asm ("popq %rcx \n");
	asm ("popq %rbx \n");
	asm ("popq %rax \n");
	asm ("popq %r15 \n");		/*restore top of exception stack frame into r15*/
	asm ("movq %r15, %rsp \n"); /*switch back to excption stack frame*/
	asm ("popq %r15 \n");
	asm ("iretq \n");

/*de handler end ------------------------------------------*/

	/*To isolate the agent's code from tdx software, we only share the first code page 
	of the agent with them. So we add the following to make sure the rest of the current code
	page is unused(becomes nop)*/
	asm (".align 0x1000");

	while(1);
}