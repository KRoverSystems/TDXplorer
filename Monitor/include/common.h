#ifndef __COMMON_H_
#define __COMMON_H_

#include "seam.h"
#include "x64bin.h"
#include "common_idata.h"
#include "com.h"

typedef unsigned long   ulong;

typedef enum{
	CODE_NONE,
	/*error codes*/
	CODE_UNHANDLED_MSR,
	CODE_UNHANDLED_INS,
	CODE_NOT_A_SPECIAL_INS,
	CODE_UNHANDLED_CPUID,
	CODE_UNHANDLED_CPUID_SUBLEAF,
	CODE_UNHANDLED_SEAMOPS_LEAF,
	CODE_OPERANDS_NOT_EXTRACTED,
	CODE_UNHANDLED_VMREAD_FIELD,
	CODE_UNABLE_TO_FIND_VMCS,
	CODE_HKID_UNCONFIGURED,
	CODE_HKID_INVALID_FOR_PAGE,
	CODE_HKID_INVALID_TD_CONTEXT,
	/*log msgs*/
	CODE_LOG_INT3_TRIGGERED,
	CODE_KHOLE_EDIT_ACCESS,

	CODE_MAX
} CODE;

typedef enum {
  false,
  true
} BOOL;

typedef enum {
	TDXCALL_TYPE_SEAMCALL,
	TDXCALL_TYPE_TDCALL
} TDXCALL_TYPE;

typedef enum {
	NO_HST_MSG,
	OPS_END,
	SEAM_ACK_RCVD
} HOST_TO_SEAM;

typedef enum {
	NO_SEAM_MSG,
	OPS_END_ACK,
	LOG_REQST
} SEAM_TO_HOST;

typedef enum {
	LOG_EMPTY_TYPE,
	LOG_INT3_TRIGGERED,
	LOG_SEAM_ENV_READY,
	LOG_INT3_RETURNED
} SEAM_LOG_TYPE;

typedef enum {
	SEAM_SW_NONE,
	SEAM_SW_PSEAMLDR,
	SEAM_SW_TDXMODULE
} SEAM_SW;

typedef enum {
	MODULE_STATE_NONE,
	MODULE_STATE_INIT_DONE
} MODULE_STATE;

typedef enum {
	SEAM_STATE_NONE,
	SEAM_STATE_MOD_INIT_DONE,
	SEAM_STATE_TD0_TDH_MNG_ADDCX_DONE,
	SEAM_STATE_TDH_SYS_INFO_DONE,
	SEAM_STATE_TDH_MNG_INIT_DONE,
	SEAM_STATE_TDH_VP_CREATE_DONE,
	SEAM_STATE_TDH_VP_ADDCX_DONE,
	SEAM_STATE_TEMP
} SEAM_STATE;

typedef enum {
	NO_HCALL,
	HCALL_EMULATE_PSEAMLDR_INS,
	HCALL_SEAM_ERROR,
	HCALL_SEAMRET,
	HCALL_VMLAUNCH,
	HCALL_VMRESUME,
	HCALL_TRACE_INS,
	HCALL_LOG,
	HCALL_INSPECT_KHOLES,
	HCALL_MKTME_ERROR,
	HCALL_END_OF_ANALYSIS,
	HCALL_MAX
} HCALL;

/*enums for types of file access for extracting offsets*/
typedef enum{
    OFFSET_TYPE_TDX_MOD_ENTRY_SEAMCALL,
    OFFSET_TYPE_IPP_CRYPTO_START,
	OFFSET_TYPE_TDX_MOD_ENTRY_TDCALL,
	OFFSET_TYPE_TDH_MEM_PAGE_AUG_LEAF,
	OFFSET_TYPE_TDH_MEM_SEPT_ADD_LEAF,
	OFFSET_TYPE_TDH_SERVTD_BIND_LEAF,
	OFFSET_TYPE_TDG_MEM_PAGE_ATTR_RD_LEAF,
} OFFSET_TYPE;


struct insInfo {
    INS in;    
    uint64_t insdata_idx;
    uint64_t int3_adr;
	BOOL emu_req_from_interpreter;
};

struct oparand{
	REGS_64		reg;
	BOOL		is_addr;
	uint64_t	offset;
};
typedef struct oparand OP;

struct insData {
	uint64_t 	va;
	uint64_t 	offset;
	INS			in;
	uint32_t	size;
	OP			op0;
	OP			op1;
	BOOL		operands_extracted;
	uint8_t		first_byte;
} __attribute__((packed)) ;

struct insData2 {
	uint64_t	va;
	uint64_t 	offset;
	REGS_64		reg0;
	REGS_64		reg1;
	REGS_64		reg2;
	uint32_t	cnst;
} __attribute__((packed)) ;
/*-------------------------------------------------------------------*/

struct targState {
	uint64_t fsbase;
	uint64_t gsbase;
};

struct seamVMCS {
	vm_exit_basic_reason_e vm_exit_reason;
};

typedef enum{
	TARGET_OWNER_NONE,
	TARGET_OWNER_S_AGENT,
	TARGET_OWNER_INTERPRETER
} TARGET_OWNER;

typedef enum{
	STATE_NONE,
	STATE_DO_SEAMCALL,
	STATE_DO_TDCALL,
	STATE_ISSUED,
	STATE_SEAMRET_DONE,
	STATE_VMLAUNCH_DONE,
	STATE_VMRESUME_DONE
} TDXCALL_STATE;


struct tdxCall {
	ulong tdxcall;
	TDXCALL_STATE state;

	/*seamcall input args*/
	ulong rax;
	ulong rcx;

	/*seamcall output args*/
	ulong return_status;
};

struct se_dispatch {
	TARGET_OWNER target_owner;
	BOOL interpreter_pt_updates_done;

	/*	1: natively execute in SEAM Env at currfent rip
		0: emulate the special instruction	*/
	uint8_t cur_ins_to_native; 
};

struct key_hole_mgt {
	ulong khole_edit_rgn_base; /*tdx mod va*/
	ulong khole_edit_rgn_size;
	ulong khole_rgn_base; /*tdx mod va*/
	ulong khole_rgn_size;
	uint64_t *khole_edit_pml4_pte;
	struct insData2 idata[2];
	ulong khole_map_count;
	ulong khole_free_count;
	ulong last_khole_edit_pte;
	ulong last_khole_edit_pte_adr;
};

struct lp_key_hole_state {
	ulong khole_edit_rgn_pa;
	ulong khole_edit_rgn_mgr_base; /*seam manager's va*/
	void *khole_state;
	void *khole_state_seam_va;
	ulong khole_map_count;
	ulong khole_free_count;
};

/*This vmcs is purely for the use of the SEAMmanager
Used for both seamcall vmcs and tdcall vmcs*/
struct tdx_vmcs {
	ulong vmcs_pa;

	/*Host area: i.e. TDX Module*/
	ulong fsbase;
	ulong gsbase;
	ulong rsp; /*used for VMCS setup before a seamcall*/
	ulong rip;

	/*msr*/
	ulong ia32_dbgctrl_msr;

	ulong vm_exit_reason;
	ulong vm_exit_qualification;
	ulong proc_based_vm_exc_control; /*To be updated when tdx mod sends a vmwrite*/
};

// struct td_tdxmod_vmcs {
// 	ulong vmcs_pa;
// 	ulong vm_exit_reason;
// 	ulong vm_exit_qualification;
// };

struct servtd_role {
	ulong binding_handle;
	ulong targtd_uuid_0_63;
	ulong targtd_uuid_64_127;
	ulong targtd_uuid_128_191;
	ulong targtd_uuid_192_255;
};

struct trust_domain {
	ulong id;
	BOOL is_created;
	BOOL is_running; /*TD is created, it's occuping the LP it was launched on*/
	BOOL is_served_by_tdxmod; /*TD is not occupiing the LP. tdx module is currently serving this TD*/
	ulong current_lp; /*only applicable if active*/
	ulong hkid;
	ulong tdr;
	ulong tdcs_base;
	ulong tdcs_eptp_root;
	ulong tdvpr;
	ulong initial_gpa_max;
	ulong next_4k_pg_gpa_to_add;
	ulong next_gpa_to_allocate_in_sept;
	ulong vcpu_associated_lp;
	struct servtd_role servtd;
};

struct td_sept_configs {
	ulong sept_add_leaf_version; /*0 or 1 only*/
	ulong allow_existing; /*0 or 1 only, allow sept_add to succeed if an ept page is already available*/
	ulong septe_level; /*sept level to add next sept page*/
	ulong start_gpa; /*hpa of the next sept page to add*/
};

struct td_mem_configs {
	ulong next_td_page_gpa;
	ulong next_source_page_hpa;
	ulong next_chunk_to_measure_gpa;
};

/*com and shared memory between seam manager and seam agent----------*/
struct comArea {
/*IMPORTANT !!! - make everyting inside this volatile*/

	/*seam manager to seam agent com*/
	volatile BOOL	seam_env_ready;
	volatile HOST_TO_SEAM host_to_seam_msg;
	volatile SEAM_TO_HOST seam_to_host_msg;
	volatile SEAM_LOG_TYPE log_type;
	volatile uint8_t *msg;
	volatile int flag;

	/*int3 handling related*/
	volatile ulong 	int3_adr;
	volatile INS	int3_ins;
	volatile uint64_t int3_stack_offsets[MAX_REGS_64];

	/*pf logging related*/
	volatile ulong pf_rip;
	volatile ulong pf_adr;
	volatile ulong pf_errcode;

	/*for instrumentation*/
	volatile struct insData pseamldr_ins[PSEAMLDR_SPECIAL_INS_COUNT];
	volatile struct insData tdxmodule_ins[TDXMODULE_SPECIAL_INS_COUNT];
	volatile struct iData tdx_ins[TDXMODULE_SPECIAL_INS_COUNT];

	/*for tracing ins*/
	volatile struct insData pseamldr_total_ins[PSEAMLDR_TOTAL_INS_COUNT];
	volatile ulong regular_ins_count;
	volatile ulong emulated_ins_count;
	volatile struct insData tdxmodule_total_ins[TDXMODULE_TOTAL_INS_COUNT];
	volatile ulong tdxmodule_regular_ins_count;
	volatile ulong tdxmodule_emulated_ins_count;

	/*for hypercalls*/
	HCALL hcall_no;
	CODE hcall_code;
	/*for emulation requests to host*/
	volatile struct insInfo int3_ins_info;

	/*for TDXCALLS*/
	volatile SEAM_SW current_sw;

	/*for SEAMCALLS*/
	volatile struct tdxCall last_seamcall;
	volatile MODULE_STATE mod_state;
	volatile SEAM_STATE seam_state;
	volatile ulong tdmr_next_avl_pa;
	volatile ulong global_hkid;

	/*for TDCALLS*/
	volatile struct tdxCall last_tdcall;

	/*for tdx module entry*/
	volatile ulong tdxmod_seamcall_entry_offset;
	volatile ulong tdxmod_tdcall_entry_offset;

	/*for TD0*/
	volatile ulong td0_tdr;
	volatile ulong td0_hkid;
	volatile ulong td0_tdvpr;

	/*for TDs*/
	volatile ulong current_td_being_setup;
	volatile ulong td_owner_for_next_tdxcall; /*seamcall or tdcall*/
	volatile ulong serv_td_owenr_being_setup;
	volatile struct trust_domain td[MAX_TDS];

	/*hkids*/
	volatile ulong next_td_hkid;
	/*shared memory for SE dispatch*/
	volatile struct se_dispatch se;

	/*for SEPT add*/
	volatile struct td_sept_configs sept;
	volatile struct td_mem_configs td_mem;

	/*For emulation*/
	volatile ulong current_seed;

	/*key hole mgt*/
	volatile struct key_hole_mgt khole_data; /*commom data*/
	volatile struct lp_key_hole_state lp_khole_state[NUM_ADDRESSIBLE_LPS]; /*per lp state*/

	/*for LP management*/
	volatile ulong current_lp;
	volatile ulong is_tdcall;
	volatile ulong current_tdx_vmcs_pa;
	volatile ulong fs_base;
	volatile struct tdx_vmcs seamcall_vmcs[NUM_ADDRESSIBLE_LPS]; /*per LP vmcs*/
	volatile struct tdx_vmcs tdcall_vmcs[MAX_TDS];
	volatile struct targState pseamldr_state;
	volatile struct targState tdxmod_state;
	volatile struct seamVMCS seamvmcs;

	/*for single step*/
	volatile BOOL single_step_on;

	/*area for Interpreter seam agent coms*/
	volatile struct servReq sreq;

	/*cpuinfo*/
	volatile ulong max_pa_bit_below_hkid;

	volatile ulong is_last_api_call;

	volatile BOOL request_to_read_seam;
	volatile ulong seam_va;
	volatile ulong seam_data;

/*IMPORTANT !!! - make everyting inside this volatile*/
}__attribute__((packed));
/*-------------------------------------------------------------------*/

struct pt_data {
	ulong seam_agent_pdpt_pa;
	int  seam_agent_pdpt_count;
};

struct file_data{
	int fd;
	ulong size;
	uint8_t *fname;
};

struct vm {
	int sys_fd;
	int fd;
	char *mem;
	char *mem2;
	unsigned long next_pt_pa;
};

struct vcpu {
	int fd;
	struct kvm_run *kvm_run;
};

#endif