#include <linux/kvm.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "defs.h"
#include "seam.h"
#include "common.h"
#include "state_defs.h"
#include "np_loader.h"
#include "pseamldr_api.h"
#include "configs.h"
#include "defs.h"
#include "assert.h"

void setup_regs(struct kvm_regs *regs);
int setup_sregs(struct kvm_sregs *sregs); 
int emulate_ins(struct insInfo *ins_info);
int switch_to_pseamldr_context(uint64_t seamcall);
ulong get_region_base_pa(REGION region);
int switch_to_tdx_module_context(TDXCALL_TYPE call_type);
void setup_tdx_module_global_data();
void switch_to_module_context(TDXCALL_TYPE call_type, struct kvm_regs *regs);
void enable_single_step();
extern ulong copy_tdx_module(ulong adr);
extern ulong get_offset(OFFSET_TYPE type);
extern void setup_tdh_sys_config_args(struct kvm_regs *regs);
extern void setup_tdh_mng_init_args(struct kvm_regs *regs);
extern void setup_tdg_servtd_bind_args(struct kvm_regs *regs);
void setup_tdg_servtd_prebind_args(struct kvm_regs *regs);
ulong get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner);
void backup_tdxcall_args();

extern const uint8_t seam_emulator_bin[];
extern struct comArea *com;
struct desc_struct *seam_gdt;
struct gate_struct *seam_idt;
struct x86_hw_tss  *seam_tss;
extern struct vm *vm;
extern struct vcpu *vcpu;
extern SEAMRR_PT_CTX SeamrrPtCtx;

ulong	seam_int3_handler;
ulong	seam_de_handler;
ulong   seam_pf_handler;
ulong	tdx_module_entry_point;

struct tdx_vmcs* vmcs_pa_to_vmcs(ulong vmcs_pa){
	
	int idx;

	/*Check among per lp seamcall vmcs*/
	idx = 0;
	while(idx < NUM_ADDRESSIBLE_LPS){
		if(com->seamcall_vmcs[idx].vmcs_pa == vmcs_pa)
			return &com->seamcall_vmcs[idx];
		idx++;
	}

	/*Check among tdcall vmcs. Untill the TD/s are created or being created, checking 
	in tdcall vmcs is of 	no use. But tdcall vmcs initial values are 0, so no issue/harm.*/
	idx = 0;
	while(idx < MAX_TDS){
		if(com->tdcall_vmcs[idx].vmcs_pa == vmcs_pa)
			return &com->tdcall_vmcs[idx];
		idx++;
	}

	LOG("Unable to find vmcs form vmcs pa\n");
}

ulong get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner){

	securePage sp;
	long page_idx = (com->tdmr_next_avl_pa >> 12) - (TDX_TDMR0_START_PA >> 12);
	assert(page_idx < SECURE_PAGE_COUNT);
	assert(hkid <= 0b111111); /*limitted to 6 bits*/
	assert(td < 0b111111); /*limitted to 6 bits*/
	assert(hkid_owner < 0b111111); /*limitted to 6 bits*/

	sp.mdata.base_pa = com->tdmr_next_avl_pa >> 12;
	// sp.mdata.hkid = hkid;
	sp.mdata.hkid = 0;
	sp.mdata.hkid_owner = hkid_owner;
	sp.mdata.td = td;
	com->sreq.secPages[page_idx].raw = sp.raw;
	/*LOG("com->tdmr_next_avl_p pa:0x%lx\n", com->tdmr_next_avl_pa);
	LOG("%lu com->sreq.secPages[page_idx].raw: 0x%lx\n", page_idx, com->sreq.secPages[page_idx].raw);
	LOG("Address 0x%lx\n", (unsigned long)&com->sreq.secPages[page_idx]);*/

	return com->tdmr_next_avl_pa;
}

ulong reserve_and_get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner){
	ulong pa;
	
	pa = get_tdmr_next_avl_pa(td, hkid, hkid_owner);
	com->tdmr_next_avl_pa += _4K;

	return pa;
}

ulong reserve_and_get_next_available_hkid(){

	ulong hkid = com->next_td_hkid;
	com->next_td_hkid += 1;

	return hkid;
}

ulong get_region_base_pa(REGION region){
	ulong code_rgn_start_pa, pa;
	sysinfo_table_t* sysinfo_table = (sysinfo_table_t*)(vm->mem + SEAM_RANGE_START_PA);
	ulong module_range_mx_pa = SEAM_RANGE_START_PA + MODULE_RANGE_SIZE;
	
	switch (region)
	{
	case RGN_CODE:
	{
	  	pa = module_range_mx_pa - SEAMRR_MODULE_CODE_REGION_SIZE; /*code region is the upper most 2M*/
	} break;
	case RGN_STACK:
	{
		code_rgn_start_pa = module_range_mx_pa - SEAMRR_MODULE_CODE_REGION_SIZE;
		pa = code_rgn_start_pa - sysinfo_table->stack_rgn_size;
	} break;
	case RGN_PML4:
	{
		code_rgn_start_pa = module_range_mx_pa - SEAMRR_MODULE_CODE_REGION_SIZE;
		pa = code_rgn_start_pa - sysinfo_table->stack_rgn_size - _4K; /*tdx module pml4 is adjacent to its stack region base pa*/
	} break;
	default:
		LOG("unhandled region : %d\n", region);
		exit(0);
		break;
	}

	if((pa < SEAM_RANGE_START_PA) || (pa > (SEAM_RANGE_START_PA + MODULE_RANGE_SIZE)))
	{
		LOG("get_region_base_pa error, pa outside module range\n");
		exit(0);
	}
	return pa;
}

int handle_vmwrite(uint64_t value, uint64_t vmcs_encoding){

	struct kvm_msrs seam_msrs, check_msr;
	struct tdx_vmcs *tdx_vmcs;

	LOG("vmcs_encoding:0x%lx value:0x%lx\n", vmcs_encoding, value);

	switch (vmcs_encoding)
	{
		case VMX_HOST_FS_BASE_ENCODE:
		{
			// seam_msrs.entries[0].index = 0xc0000100; /*MSR_FS_BASE*/
			// seam_msrs.entries[0].data = value;
			// seam_msrs.nmsrs = 1;
			// if (ioctl(vcpu->fd, KVM_SET_MSRS, &seam_msrs) != 1) {
			// 	LOG("KVM_SET_MSRS failed\n");
			// 	exit(1);
			// }
			/*update the com area with fsgsbase info*/
			if(com->current_sw == SEAM_SW_PSEAMLDR){
				com->pseamldr_state.fsbase = value;
			}
			else{
				// com->tdxmod_state.fsbase = value;
				com->seamcall_vmcs[com->current_lp].fsbase = value;
			}

			// check_msr.entries[0].index = 0xc0000100;
			// check_msr.nmsrs = 1;

			// if (ioctl(vcpu->fd, KVM_GET_MSRS, &check_msr) != 1) {
			// 	LOG("KVM_GET_MSRS failed\n");
			// 	exit(1);
			// }
			// LOG("fsbase from KVM_GET_MSRS:0x%lx \n",(ulong)check_msr.entries[0].data);
		}	break;
		case VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE:
		{
			tdx_vmcs = vmcs_pa_to_vmcs(com->current_tdx_vmcs_pa);
			/*We do not have to update the SEAM env vmcs. At the moment, we do not know if saving this value is usefull 
			for future execution. So we do save it, just in case.*/
			tdx_vmcs->proc_based_vm_exc_control = value;
		} break;
		case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
		{
			tdx_vmcs = vmcs_pa_to_vmcs(com->current_tdx_vmcs_pa);
			/*We do not have to update the SEAM env vmcs. At the moment, we do not know if saving this value is usefull 
			for future execution. So we do save it, just in case.*/
			tdx_vmcs->ia32_dbgctrl_msr = value;
		} break;
		case VMX_IA32_SPEC_CTRL_SHADOW:
		{
			/*Do nothing for the moment*/
			/*TODO: If not doing enything, no pointi n exiting from SEAM env, stop HCALL in furture.*/
		} break;
		default:
		{
			LOG("unhandled vmcs encoding\n");
			exit(0);
		}
			break;
	}
	return 0;
}

int emulate_ins(struct insInfo *ins_info){
	int status;
	uint64_t op0, op1;
	REGS_64 reg0, reg1;
	struct insData *idata;

	if(com->current_sw == SEAM_SW_PSEAMLDR){
		LOG("SEAM manager emulating pseamldr_ins: %d\n", (int)ins_info->in);
		idata = (struct insData *)com->pseamldr_ins;
	}
	else{
		LOG("SEAM manager emulating tdxmodule_ins: %d\n", (int)ins_info->in);
		idata = (struct insData *)com->tdxmodule_ins;
	}

	switch (ins_info->in)
	{
		case VMWRITE:
		{
			if(idata[ins_info->insdata_idx].operands_extracted != true){
				LOG("ERR: operands have not been extracted\n");
				exit(0);
			}
			if(idata[ins_info->insdata_idx].op0.is_addr != true){
				/*get values from int3 handler's stack*/
				reg0 = idata[ins_info->insdata_idx].op0.reg;
				//LOG("reg0:%d\n", reg0);
				op0 = *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - com->int3_stack_offsets[reg0]);
			}
			else{
				/*this is when the source operand is a memory address
				TODO:*/
				LOG("FIXME");
				exit(0);
			}
			reg1 = idata[ins_info->insdata_idx].op1.reg; /*always a reg*/
			//LOG("reg1:%d\n", reg1);
			op1 = *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - com->int3_stack_offsets[reg1]);
			handle_vmwrite(op0, op1);

		}	break;
		
		default:
		{
			LOG("unhandled instruction\n");
		}	break;
	}

	return 0;
}

/*inputs
RAX = 0x80000000.00000001
RCX = A 64-bit physical address of an input buffer of type SEAMLDR_PARAMS. 
	This address must satisfy the following rules:
	— No reserved bits.
	— No TDX-private Key ID.
	— No overlap with SEAM range.
	— Aligned on 4K-byte boundar*/
ulong setup_pseamcall_install(){
	seamldr_params_t *seamlder_params;  /*object size 4096*/
	seam_sigstruct_t *seam_sigstruct; 	/*obje size 2048*/
	ulong seamlder_params_pa, seam_sigstruct_pa;
	ulong tdx_mod_start, mod_size, tdx_mod_start_pa, mod_pages;
	ulong count;


	seamlder_params_pa = SEAM_AGENT_SEAMCALL_DATA_PA;
	seam_sigstruct_pa = SEAM_AGENT_SEAMCALL_DATA_PA + _4K;
	seamlder_params = (seamldr_params_t *)(vm->mem + seamlder_params_pa);
	seam_sigstruct = (seam_sigstruct_t *)(vm->mem + seam_sigstruct_pa);

	if(((seamlder_params_pa % _4K) != 0) | ((seam_sigstruct_pa % _4K) != 0)){
		LOG("seamlder_params_pa or seam_sigstruct_pa is not a page boundaty\n");
		exit(0);
	}

/*fill seamldr_params*/
	memset((void *)seamlder_params, 0, sizeof(seamldr_params_t));
	seamlder_params->version = 0;
	seamlder_params->scenario = 0; /*0 load tdx mod, 1 update tdx mod*/
	seamlder_params->sigstruct_pa = seam_sigstruct_pa; /*4KB ligned*/
	
	tdx_mod_start_pa = seam_sigstruct_pa + _4K;
	tdx_mod_start = (ulong)seam_sigstruct + _4K;
	mod_size = copy_tdx_module(tdx_mod_start);
	if(mod_size == 0){
		LOG("copy_tdx_module error\n");
		exit(0);
	}
	mod_pages = mod_size/_4K;
	if(((mod_size % _4K) != 0) || (mod_pages > SEAMLDR_PARAMS_MAX_MODULE_PAGES)){
		LOG("libtdx.so size is too large or not a multiple of 4KB\n");
		exit(0);
	}

	seamlder_params->num_module_pages = mod_pages;
	/*LOG("Mod size: 0x%lx, mod_pages:0x%lx\n", mod_size, mod_pages);*/
	count = 0;
	while(count < mod_pages){
		seamlder_params->mod_pages_pa_list[count] = tdx_mod_start_pa + _4K*count;
		count++;
	}

/*fill seam_sigstruct*/
	memset((void *)seam_sigstruct, 0, sizeof(seam_sigstruct_t));
	/*signature structure header*/
	seam_sigstruct->header_type = SEAM_SIGSTRUCT_HEADER_TYPE_GENERIC_FW;
	seam_sigstruct->header_length = SEAM_SIGSTRUCT_HEADER_LENGTH_DWORDS;
	seam_sigstruct->header_version = SEAM_SIGSTRUCT_HEADER_VERSION;
	seam_sigstruct->module_type.raw = 0; /*0 prod, if debug:change*/
	seam_sigstruct->module_vendor = SEAM_SIGSTRUCT_INTEL_MODULE_VENDOR;
	seam_sigstruct->date = TDX_MODULE_BUILD_DATE;
	seam_sigstruct->size = SEAM_SIGSTRUCT_SIZE_DWORDS;
	seam_sigstruct->key_size = SEAM_SIGSTRUCT_KEY_SIZE_DWORDS;
	seam_sigstruct->modulus_size = SEAM_SIGSTRUCT_MODULUS_SIZE_DWORDS;
	seam_sigstruct->exponent_size = SEAM_SIGSTRUCT_EXPONENT_SIZE_DWORDS;
	
	/*moduluous and signature*/
	/*//we have dissabled the hash verification in pseamldr,
	so, moduluous, exponent and signature are not required*/
	// seam_sigstruct->modulus = 
	seam_sigstruct->exponent = SEAM_SIGSTRUCT_RSA_EXPONENT;
	// seam_sigstruct->signature = 

	/*Intel TDX module configuration parameters*/
	// seam_sigstruct->seamhash[] //we have dissabled the hash verification in pseamldr, so...

	/*could not find any documentation on populating the svn
	we are using version 1.5.0, so we assume standard versionning convention*/
	seam_sigstruct->seamsvn.seam_major_svn = 1; /*major version is 1*/
	seam_sigstruct->seamsvn.seam_minor_svn = 5; /*and the monor version is 5*/

	seam_sigstruct->attributes = 0;
	// seam_sigstruct->rip_offset = 
	seam_sigstruct->num_stack_pages = TDX_MODULE_STACK_PAGES;
	seam_sigstruct->num_tls_pages = TDX_MODULE_TLS_PAGES;
	seam_sigstruct->num_keyhole_pages = TDX_MODULE_KEYHOLE_PAGES;
	seam_sigstruct->num_global_data_pages = TDX_MODULE_GLOBAL_DATA_PAGES;
	seam_sigstruct->max_tdmrs = 0; /*0: 64 TDMRs, N((>0): N TDMRs*/
	// seam_sigstruct->max_rsvd_per_tdmr = 
	// seam_sigstruct->pamt_entry_size_4k = 
	// seam_sigstruct->pamt_entry_size_2m = 
	// seam_sigstruct->pamt_entry_size_1g = 
	// seam_sigstruct->module_hv = 
	// seam_sigstruct->no_downgrade = 0; /*downgrade allowed, doesn't matter as we do not plan to*/

	/*since the major svn is != 0, num_handoff_pages are considered by pseamldr when setting up the data regions*/
	seam_sigstruct->num_handoff_pages = TDX_MODULE_HANDOFF_DATA_PAGES; /*required for the current svn*/

	seam_sigstruct->cpuid_table_size = NUM_ADDRESSIBLE_LPS;
	count = 0;
	while(count < NUM_ADDRESSIBLE_LPS){
		seam_sigstruct->cpuid_table[count] = count;
		count++;
	}

	return seamlder_params_pa; 
}

void setup_pseamldr_seamcall_state(uint64_t seamcall, struct kvm_regs *regs){

	ulong adr;

	memset((void *)&com->last_seamcall, 0, sizeof(struct tdxCall));

	com->last_seamcall.tdxcall = seamcall;
	com->last_seamcall.state = STATE_DO_SEAMCALL;
	regs->rax = seamcall;
	switch (seamcall)
	{
	case PSEAMLDR_SEAMCALL_SEAMLDR_INFO:
	{		
		/*RCX = A 64-bit physical address of an output buffer of type SEAMLDR_INFO. This address must satisfy the
		following rules:
		— No reserved bits.
		— No TDX-private Key ID.
		— No overlap with SEAM range defined by SEAMRR.
		— Aligned to a 256-byte boundary*/
		regs->rcx = SEAM_AGENT_SEAMCALL_DATA_PA;
		memset((void *)((ulong)vm->mem + regs->rcx) , 0, sizeof(seamldr_info_t));
		
		com->last_seamcall.rax = regs->rax;
		com->last_seamcall.rcx = regs->rcx;
	} break;
	
	case PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL:
	{
		/*LOG("setup args for PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL\n");*/
		adr = setup_pseamcall_install();
		regs->rcx = adr;

		com->last_seamcall.rax = regs->rax;
		com->last_seamcall.rcx = regs->rcx;
	} break;

	case PSEAMLDR_SEAMCALL_SEAMLDR_SHUTDOWN:
	{
		LOG("seamcall: unhandled as of now\n");
		exit(0);
	} break;

	case PSEAMLDR_SEAMCALL_SEAMLDR_SEAMINFO:
	{
		LOG("setup args for PSEAMLDR_SEAMCALL_SEAMLDR_SEAMINFO\n");

		/*RCX = A 64-bit physical address of an output buffer of type SEAMLDR_SEAMINFO. This address must satisfy
		the following rules:
		— No reserved bits.
		— No TDX-private Key ID.
		— No overlap with SEAM range defined by SEAMRR.
		— Aligned to a 2K-byte boundary.*/
		regs->rcx = SEAM_AGENT_SEAMCALL_DATA_PA;
		if((regs->rcx % _2K) != 0){
			LOG("PA must be 2K aligned\n");
			exit(0);
		}
		memset((void *)((ulong)vm->mem + regs->rcx), 0, sizeof(p_sysinfo_table_t));
		regs->rcx = 0x3;
		com->last_seamcall.rax = regs->rax;
		com->last_seamcall.rcx = regs->rcx;
	} break;
	
	default:
	{
		LOG("ERR: invalid seamcall\n");
		exit(0);
	}
		break;
	}
}

int switch_to_pseamldr_context(uint64_t seamcall){

	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_msrs seam_msrs, check_msr;
	int status;

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	/*setup sregs here
	do not mem set as we have setup some of sregs previously*/
	sregs.cr3 = SeamrrPtCtx.PtBaseAddrPa;  /*pseamldr cr3*/
	/*LOG("pseamldr cr3:0x%lx\n", (ulong)sregs.cr3);*/

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}
	
	seam_msrs.entries[0].index = 0xc0000100; /*MSR_FS_BASE*/
	seam_msrs.entries[0].data = (ulong)(C_SYS_INFO_TABLE_BASE | SeamldrData.AslrRand);
	seam_msrs.entries[1].index = 0xc0000101; /* MSR_GS_BASE*/
	seam_msrs.entries[1].data = SeamldrData.PSysInfoTable->DataRgn.Base;
	seam_msrs.nmsrs = 2;
    if (ioctl(vcpu->fd, KVM_SET_MSRS, &seam_msrs) != 2) {
		LOG("KVM_SET_MSRS failed\n");
		exit(1);
	}
	/*update the com area with fsgsbase info*/
	com->pseamldr_state.fsbase = (ulong)(C_SYS_INFO_TABLE_BASE | SeamldrData.AslrRand);
	com->pseamldr_state.gsbase = SeamldrData.PSysInfoTable->DataRgn.Base;

	check_msr.entries[0].index = 0xc0000100;
	check_msr.entries[1].index = 0xc0000101;
	check_msr.nmsrs = 2;
	if (ioctl(vcpu->fd, KVM_GET_MSRS, &check_msr) != 2) {
		LOG("KVM_GET_MSRS failed\n");
		exit(1);
	}
	/*LOG("fsbase:0x%lx gsbase:0x%lx\n",(ulong)check_msr.entries[0].data, (ulong)check_msr.entries[1].data);*/

	/*setup regs here
	its ok to memset as we need a fresh GPR state*/
	memset(&regs, 0, sizeof(regs));
	regs.rip = SeamldrData.PSysInfoTable->CodeRgn.Base + SeamldrData.PSeamldrConsts->CEntryPointOffset; //0x1a0; 
	regs.rsp = SeamldrData.PSysInfoTable->StackRgn.Base + SeamldrData.PSeamldrConsts->CDataStackSize - 0x8;
	regs.rflags = 2;
	setup_pseamldr_seamcall_state(seamcall, &regs);

	/*LOG("pseamldr entry rip:0x%lx rsp:0x%lx\n", (ulong)regs.rip, (ulong)regs.rsp);*/
	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	return 0;
}

void backup_tdxcall_args(){
	
	struct kvm_regs regs;

	if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}
	memset((void *)&com->sreq.tdxcall_args, 0, sizeof(struct tdx_call_args));

	com->sreq.tdxcall_args.rax = regs.rax;
	com->sreq.tdxcall_args.rbx = regs.rbx;
	com->sreq.tdxcall_args.rcx = regs.rcx;
	com->sreq.tdxcall_args.rdx = regs.rdx;
	com->sreq.tdxcall_args.r8 = regs.r8;
	com->sreq.tdxcall_args.r9 = regs.r9;
	com->sreq.tdxcall_args.r10 = regs.r10;
}

void setup_tdx_module_global_data() {
}

int switch_to_tdx_module_context(TDXCALL_TYPE call_type){

	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_msrs seam_msrs, check_msr;
	int status;
	ulong data_rgn_base, gs_base, handoff_data_size, rip_offset, lp_data_stack_size, lp_tot_stack_size;
	sysinfo_table_t* sysinfo_table = (sysinfo_table_t*)(vm->mem + SEAM_RANGE_START_PA);
	ulong lp_id = com->current_lp;

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	/*setup sregs here, we do not memset*/
	sregs.cr3 = get_region_base_pa(RGN_PML4);
	/*LOG("tdx module cr3:0x%lx\n", (ulong)sregs.cr3);*/

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}
	
	/*We save the initial fsbase at SEAMCALL start in com area to support rdfsbase emulation. VMWRITE for fsbase 
	will be separately saved in com->seamcall_vmcs[lp_id].fsbase for the next SEAMCALL*/
	com->tdxmod_state.fsbase = com->seamcall_vmcs[lp_id].fsbase;
	seam_msrs.entries[0].index = 0xc0000100; /*MSR_FS_BASE*/
	seam_msrs.entries[0].data = com->seamcall_vmcs[lp_id].fsbase;

	com->tdxmod_state.gsbase = com->seamcall_vmcs[lp_id].gsbase;
	seam_msrs.entries[1].index = 0xc0000101; /* MSR_GS_BASE*/
	seam_msrs.entries[1].data = com->seamcall_vmcs[lp_id].gsbase;

	seam_msrs.nmsrs = 2;
    if (ioctl(vcpu->fd, KVM_SET_MSRS, &seam_msrs) != 2) {
		LOG("KVM_SET_MSRS failed\n");
		exit(1);
	}

	/* Check msr updates 
	check_msr.entries[0].index = 0xc0000100;
	check_msr.entries[1].index = 0xc0000101;
	check_msr.nmsrs = 2;
	if (ioctl(vcpu->fd, KVM_GET_MSRS, &check_msr) != 2) {
		LOG("KVM_GET_MSRS failed\n");
		exit(1);
	}
	LOG("fsbase:0x%lx gsbase:0x%lx\n",(ulong)check_msr.entries[0].data, (ulong)check_msr.entries[1].data);*/

	/*setup regs here
	its ok to memset as we need a fresh GPR state*/
	memset(&regs, 0, sizeof(regs));
	if(call_type == TDXCALL_TYPE_SEAMCALL)
		regs.rip = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + com->tdxmod_seamcall_entry_offset; 
	else
		regs.rip = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + com->tdxmod_tdcall_entry_offset;  

	regs.rsp = com->seamcall_vmcs[lp_id].rsp;
	regs.rflags = 2;

	/*Enabling Trap Flag for seamcalls - this allows us single step*/
#ifdef SINGLE_STEP_TDX_MOD
	if(com->single_step_on)
		regs.rflags |= (1UL << 8);  //trap flag is bit 8 of EFLAGS
#endif

	/*LOG("tdxmodule entry rip:0x%lx rsp:0x%lx\n", (ulong)regs.rip, (ulong)regs.rsp);*/
	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	return 0;
}

void enable_single_step(){
	struct kvm_regs regs;

#ifdef SINGLE_STEP_TDX_MOD
    if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}
	
	regs.rflags |= (1UL << 8);  /*trap flag is bit 8 if EFLAGS*/
	
	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}
#else
	printf("Expected SINGLE_STEP_TDX_MOD to be turned on\n");
#endif
}

int setup_sregs(struct kvm_sregs *sregs){

	struct kvm_msrs check_msr;
	uint64_t apic_base;
	struct tss_dsec_struct tss_desc_gdt;

	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 0x8,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed ??*/
	seg.selector = 0x10;
	sregs->ds = sregs->es = sregs->ss = seg;

	seg.selector = 0x18;
	seg.base = 0;
	sregs->fs = sregs->gs = seg;

	sregs->cr3 = SEAM_AGENT_PT_BASE_PA;
	sregs->cr4 = 	CR4_PAE; /* | CR4_OSXSAVE; OSXSAVE is needed for some TD calls, revisit*/
	sregs->cr0 = 	CR0_PE | /*used by PSEAMLDR*/
					CR0_MP | /*WAIT instruction generates a device-not-available exception*/
					CR0_ET | /*used by PSEAMLDR*/
					CR0_NE | /*used by PSEAMLDR*/
					CR0_WP | /*used by PSEAMLDR*/
					CR0_AM | /*Enables automatic alignment checking when set*/
					CR0_PG;	 /*used by PSEAMLDR*/
	sregs->efer = 	EFER_LME | /*used by PSEAMLDR*/
					EFER_LMA |  /*used by PSEAMLDR*/
					EFER_NXE; /*used by PSEAMLDR, added because of that*/

	/*LOG("GDT base:%lx lim:0x%x\n", sregs->gdt.base, sregs->gdt.limit);*/

    seam_gdt = (struct desc_struct *)(vm->mem + SEAM_ENV_GDT_PA);
	if(SEAM_GDT_ENTRIES*(sizeof(struct desc_struct)) > SEAM_ENV_GDT_SZ)
		{
			LOG("GDT size too big\n");
			return -1;
		}
    memset((void*)seam_gdt, 0, SEAM_GDT_ENTRIES*(sizeof(struct desc_struct)));
    /*LOG("struct desc_struct sz: %lu\n", sizeof(struct desc_struct));*/
    sregs->gdt.base = (ulong)SEAM_ENV_GDT;
    sregs->gdt.limit = (SEAM_GDT_ENTRIES*sizeof(struct desc_struct)) - 1;
	
	/*LOG("seam_gdt:0x%lx, &seam_gdt[1]:0x%lx, &seam_gdt[2]:0x%lx\n", (ulong)seam_gdt, (ulong)&seam_gdt[1], (ulong)&seam_gdt[2]);*/
	/*cs: selector = 0x8*/
	seam_gdt[1].base0 = 0;
	seam_gdt[1].limit0 = 0xffff;
	seam_gdt[1].limit1 = 0xf;
	seam_gdt[1].type = 11; /* Data: read/write, accessed */
	seam_gdt[1].s = 1;
	seam_gdt[1].dpl = 0;
	seam_gdt[1].p = 1;
	seam_gdt[1].l = 1;
	seam_gdt[1].g = 1; /* 4KB granularity */
	seam_gdt[1].d = 0;

	/*ds,es,fs,gs,ss: selector = 0x10*/
	seam_gdt[2].base0 = 0;
	seam_gdt[2].limit0 = 0xffff;
	seam_gdt[2].limit1 = 0xf;
	seam_gdt[2].type = 3; /* Code: execute, read, accessed */
	seam_gdt[2].s = 1;
	seam_gdt[2].dpl = 0;
	seam_gdt[2].p = 1;
	seam_gdt[2].l = 1;
	seam_gdt[2].g = 1; /* 4KB granularity */
	seam_gdt[2].d = 0;

	/*fs and gs uses selector 0x18*/
	seam_gdt[3].base0 = 0;
	seam_gdt[3].limit0 = 0xffff;
	seam_gdt[3].limit1 = 0xf;
	seam_gdt[3].type = 11; /* Data: read/write, accessed */
	seam_gdt[3].s = 1;
	seam_gdt[3].dpl = 0;
	seam_gdt[3].p = 1;
	seam_gdt[3].l = 1;
	seam_gdt[3].g = 1; /* 4KB granularity */
	seam_gdt[3].d = 0;


	/*setup tss selector 0x20*/
	/*tss descriptor takes up 16 bytes, i.e. seam_gdt[4] and seam_gdt[5] */
	/*
	memset((void *)&tss_desc_gdt, 0, 0x10);
	tss_desc_gdt.limit0 = sizeof(struct x86_hw_tss) - 1;
	tss_desc_gdt.base0 = (uint16_t)(SEAM_ENV_TSS_PA & 0xFFFF);
	tss_desc_gdt.base1 = ((SEAM_ENV_TSS_PA) >> 16) & 0xFF;
	tss_desc_gdt.type = 0xe; //chk vol3 T3.2 ?
	tss_desc_gdt.s = 0;  //descriptor type system
	tss_desc_gdt.dpl = 0;
	tss_desc_gdt.p = 1;
	tss_desc_gdt.limit1 = 0;
	tss_desc_gdt.avl = 0;
	tss_desc_gdt.l = 0;
	tss_desc_gdt.d = 0;
	tss_desc_gdt.g = 0; //if g is clear, segment size is in bytes
	tss_desc_gdt.base2 = ((SEAM_ENV_TSS_PA) >> 24) & 0xFF;
	tss_desc_gdt.base3 = ((SEAM_ENV_TSS_PA) >> 32) & 0xFFFFFFFF;
	memcpy((void *)&seam_gdt[4], (void *)&tss_desc_gdt, 0x10);

	//setup tss cntd
	seam_tss = (struct x86_hw_tss *)(vm->mem + SEAM_ENV_TSS_PA);
	memset((void *)seam_tss, 0, sizeof(struct x86_hw_tss));
	seam_tss->ist[0] = SEAM_EXCEPTION_STACK;
	seam_tss->ist[1] = SEAM_EXCEPTION_STACK;
	seam_tss->sp0 = SEAM_EXCEPTION_STACK;

	memset((void *)&seg, 0, sizeof(struct kvm_segment));
	seg.base = SEAM_ENV_TSS_PA;
	seg.limit =  sizeof(struct x86_hw_tss) - 1;
	seg.selector = 0x20;
	seg.type = 0xe; //chk vol3 T3.2
	seg.s = 0; //descriptor type system
	seg.dpl = 0;
	seg.present = 1;
	seg.avl = 0;
	seg.l = 0;
	seg.db = 0; 
	seg.g = 0; 

	memcpy((void *)&sregs->tr, (void *)&seg, sizeof(struct kvm_segment));*/

	/*LOG("GDT[0]:0x%lx, GDT[1]:0x%lx, GDT[2]:0x%lx\n", *(ulong*)&seam_gdt[0], *(ulong*)&seam_gdt[1], *(ulong*)&seam_gdt[2]);
	LOG("seam_gdt setup ok\n");*/

	seam_idt = (struct gate_struct *)(vm->mem + SEAM_ENV_IDT_PA);
	memset((void*)seam_idt, 0, SEAM_IDT_ENTRIES*(sizeof(struct gate_struct)));
    /*LOG("struct gate_struct sz: %lu\n", sizeof(struct gate_struct));*/
	sregs->idt.base = (ulong)SEAM_ENV_IDT;
	sregs->idt.limit = (SEAM_IDT_ENTRIES*sizeof(struct gate_struct)) - 1;
	/*LOG("seam_idt:0x%lx, &seam_idt[2]:0x%lx, &seam_idt[3]:0x%lx\n", (ulong)seam_idt, (ulong)&seam_idt[2], (ulong)&seam_idt[3]);*/

	/*setup idt for int3*/
	/*LOG("seam_emulator_bin:0x%lx\n", SEAM_AGENT_CODE);*/
	/*The int3 handler is placed at the offset 0x0 in the seam agent*/
	seam_int3_handler = SEAM_AGENT_CODE; //SEAM_AGENT_CODE + 0xcf;
	seam_idt[3].offset_low = seam_int3_handler & 0xffff;
	seam_idt[3].offset_middle = (seam_int3_handler >> 16) & 0xffff;
	seam_idt[3].offset_high = (seam_int3_handler >> 32) & 0xffffffff;
	seam_idt[3].segment = 1 << 3;
	seam_idt[3].bits.ist = 0;
	seam_idt[3].bits.type = 0xe; /*chk vol3 T3.2*/
	seam_idt[3].bits.dpl = 0;
	seam_idt[3].bits.p = 1;

	/*setup idt for single stepping ; a handler for debug exceptions
	As of now, we share the same handler used for int3*/
#ifdef SINGLE_STEP_TDX_MOD
	/*LOG("seam_emulator_bin:0x%lx\n", SEAM_AGENT_CODE);*/
	/*de shares the int3 handler*/
	seam_de_handler = SEAM_AGENT_CODE + 0x400; //SEAM_AGENT_CODE + 0xcf;
	seam_idt[1].offset_low = seam_de_handler & 0xffff;
	seam_idt[1].offset_middle = (seam_de_handler >> 16) & 0xffff;
	seam_idt[1].offset_high = (seam_de_handler >> 32) & 0xffffffff;
	seam_idt[1].segment = 1 << 3;
	seam_idt[1].bits.ist = 0;
	seam_idt[1].bits.type = 0xe; /*chk vol3 T3.2*/
	seam_idt[1].bits.dpl = 0;
	seam_idt[1].bits.p = 1;
#endif

#ifdef SINGLE_STEP_TDX_MOD
	/*LOG("seam_emulator_bin:0x%lx\n", SEAM_AGENT_CODE);*/
	/*we have placed the pf handler at an offset of 0x200 in the seam agent*/
	seam_pf_handler = SEAM_AGENT_CODE + 0x200; //0xab;
	seam_idt[14].offset_low = seam_pf_handler & 0xffff;
	seam_idt[14].offset_middle = (seam_pf_handler >> 16) & 0xffff;
	seam_idt[14].offset_high = (seam_pf_handler >> 32) & 0xffffffff;
	seam_idt[14].segment = 1 << 3;
	seam_idt[14].bits.ist = 0;
	seam_idt[14].bits.type = 0xe; /*chk vol3 T3.2*/
	seam_idt[14].bits.dpl = 0;
	seam_idt[14].bits.p = 1;
#endif

	/*check APIC base
	check_msr.entries[0].index = 0x1B;
	check_msr.nmsrs = 1;
	if (ioctl(vcpu->fd, KVM_GET_MSRS, &check_msr) != 1) {
		LOG("KVM_GET_MSRS failed\n");
		exit(1);
	}
	LOG("apic base read:0x%lx\n",(ulong)check_msr.entries[0].data);

	//Update x2APIC base
	int ret = ioctl(vm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_X2APIC_API);
	if (ret < 0) {
		perror("ioctl(KVM_CHECK_EXTENSION) failed");
	}

	if (ret == 1) {
		printf("KVM supports the x2APIC API (KVM_CAP_X2APIC_API)\n");
	} else {
		printf("KVM does not support the x2APIC API (KVM_CAP_X2APIC_API)\n");
	}

	apic_base = 0UL;
	apic_base = SEAM_ENV_APIC_BASE | X2APIC_ENABLE; 
	LOG("apic base to set:0x%lx\n",(ulong)apic_base);
	
	check_msr.entries[0].index = 0x1B;
	check_msr.nmsrs = 1;
	check_msr.entries[0].data = apic_base;
	int aa =ioctl(vcpu->fd, KVM_SET_MSRS, &check_msr);
	LOG("aa:%d\n", aa); exit(0);
	if (ioctl(vcpu->fd, KVM_SET_MSRS, &check_msr) != 1) {
		LOG("KVM_SET_MSRS failed\n");
		exit(1);
	}	*/

	return 0;
}

void setup_regs(struct kvm_regs *regs){

	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs->rflags = 2 ;//| 0x0200;
	regs->rip = SEAM_AGENT_CODE; //0;
	/* Create stack at top of 2 MB page and grow down. */
	regs->rsp = SEAM_AGENT_STACK; //2 << 20;
	/*LOG("RSP:0x%lx\n", (ulong)regs->rsp);*/
}

void switch_to_module_context(TDXCALL_TYPE call_type, struct kvm_regs *regs){

	struct kvm_sregs sregs;
	struct kvm_msrs seam_msrs, check_msr;
	int status;
	ulong data_rgn_base, gs_base, handoff_data_size, rip_offset, lp_data_stack_size, lp_tot_stack_size;
	sysinfo_table_t* sysinfo_table = (sysinfo_table_t*)(vm->mem + SEAM_RANGE_START_PA);
	ulong lp_id = com->current_lp;

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	/*setup sregs here, we do not memset*/
	sregs.cr3 = get_region_base_pa(RGN_PML4);
	/*LOG("tdx module cr3:0x%lx\n", (ulong)sregs.cr3);*/

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}
	
	/*We save the initial fsbase at SEAMCALL start in com area to support rdfsbase emulation. VMWRITE for fsbase 
	will be separately saved in com->seamcall_vmcs[lp_id].fsbase for the next SEAMCALL*/
	com->tdxmod_state.fsbase = com->seamcall_vmcs[lp_id].fsbase;
	seam_msrs.entries[0].index = 0xc0000100; /*MSR_FS_BASE*/
	seam_msrs.entries[0].data = com->seamcall_vmcs[lp_id].fsbase;

	com->tdxmod_state.gsbase = com->seamcall_vmcs[lp_id].gsbase;
	seam_msrs.entries[1].index = 0xc0000101; /* MSR_GS_BASE*/
	seam_msrs.entries[1].data = com->seamcall_vmcs[lp_id].gsbase;

	seam_msrs.nmsrs = 2;
    if (ioctl(vcpu->fd, KVM_SET_MSRS, &seam_msrs) != 2) {
		LOG("KVM_SET_MSRS failed\n");
		exit(1);
	}

	if(call_type == TDXCALL_TYPE_SEAMCALL)
		regs->rip = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + com->tdxmod_seamcall_entry_offset; 
	else
		regs->rip = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + com->tdxmod_tdcall_entry_offset;  

	regs->rsp = com->seamcall_vmcs[lp_id].rsp;
	regs->rflags = 2;

	/*Enabling Trap Flag for seamcalls - this allows us single step*/
#ifdef SINGLE_STEP_TDX_MOD
	if(com->single_step_on)
		regs->rflags |= (1UL << 8);  //trap flag is bit 8 of EFLAGS
#endif

	/*LOG("tdxmodule entry rip:0x%lx rsp:0x%lx\n", (ulong)regs.rip, (ulong)regs.rsp);*/
	if (ioctl(vcpu->fd, KVM_SET_REGS, regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}
}

void prep_tdh_sys_config_args(struct kvm_regs *regs){
	
	return setup_tdh_sys_config_args(regs);
}

void prep_tdh_mng_init_args(struct kvm_regs *regs){
	
	return setup_tdh_mng_init_args(regs);
}

void prep_tdh_servtd_bind_args(struct kvm_regs *regs){

	return setup_tdg_servtd_bind_args(regs);
}

void prep_tdh_servtd_prebind_args(struct kvm_regs *regs){

	return setup_tdg_servtd_prebind_args(regs);
}
