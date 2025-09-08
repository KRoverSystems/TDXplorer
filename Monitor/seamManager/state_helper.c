#include <linux/kvm.h>

#include "tdx_mod_api.h"
#include "seam.h"
#include "common.h"
#include "defs.h"

void setup_tdh_sys_config_args(struct kvm_regs *regs);
void setup_tdh_mng_init_args(struct kvm_regs *regs);
void setup_tdg_servtd_bind_args(struct kvm_regs *regs);
void setup_tdg_servtd_prebind_args(struct kvm_regs *regs);

extern struct vm *vm;
extern struct comArea *com;

/*tdmr_info_entry_t*/
void setup_tdh_sys_config_args(struct kvm_regs *regs) {

    uint64_t *array_pa = (uint64_t *)(vm->mem + SEAM_AGENT_SEAMCALL_DATA_PA); /*the corresponding GPA must be 512B aligned*/
    memset((void *)array_pa, 0, _4K);
    
    /*the corresponding GPA of tdmr_info_obj must be 512B aligned*/
    tdmr_info_entry_t *tdmr_info_obj = (struct tdmr_info_entry_t *)(vm->mem + SEAM_AGENT_SEAMCALL_DATA_PA + _4K); 
    memset((void *)tdmr_info_obj, 0, sizeof(tdmr_info_entry_t));

    *array_pa = SEAM_AGENT_SEAMCALL_DATA_PA + _4K; /*holds the pa of the TDMR_INFO object*/

    tdmr_info_obj->tdmr_base = TDX_TDMR0_START_PA;
    tdmr_info_obj->tdmr_size = TDX_TDMR0_FULL_SIZE;
    tdmr_info_obj->pamt_1g_base = TDX_PAMT0_START_PA;
    tdmr_info_obj->pamt_1g_size = TDX_PAMT0_1G_SIZE;
    tdmr_info_obj->pamt_2m_base = TDX_PAMT0_2M_BASE_PA;
    tdmr_info_obj->pamt_2m_size = TDX_PAMT0_2M_SIZE;
    tdmr_info_obj->pamt_4k_base = TDX_PAMT0_4K_BASE_PA;
    tdmr_info_obj->pamt_4k_size = TDX_PAMT0_4K_SIZE;
    tdmr_info_obj->rsvd_areas[0].offset = TDX_TDMR0_RESERVED_START_PA - TDX_TDMR0_START_PA;
    tdmr_info_obj->rsvd_areas[0].size = TDX_TDMR0_RESERVED_SIZE;

    /*
    RCX : The physical address of an array of pointers, each containing the physical address of a single
          TDMR_INFO entry. The pointer array must be sorted such that TDMR base addresses (TDMR_INFO.TDMR_BASE) are
          sorted from the lowest to the highest base address, and TDMRs do not overlap with each other.*/
    regs->rcx = SEAM_AGENT_SEAMCALL_DATA_PA;
    
    /*
    RDX : The number of pointers in the above array, between 1 and 64
    In our case, we have only one pointer in the array*/
    regs->rdx = 1;

    /*
    R8  : Bits     Name         Description
          15:0     HKID         Intel TDX global private HKID value
          63:16    Reserved     Reserved: must be 0 
          
    For HKID we have reserved 6 bits as part of MSR emulation.
    <4 bits for private hkid><2 bits for shared hkid>
    We use the first available private hkid: 000100 = 4 for TDX GLOBAL PRIVATE HKID*/
    regs->r8 = TDX_GLOBAL_PRIVATE_HKID;
    com->global_hkid = regs->r8;
}

void setup_tdh_mng_init_args(struct kvm_regs *regs){
      
      td_sys_info_t *td_sys_inf;
      td_params_t *td_parm;


      // regs->rcx = com->td0_tdr; 
      regs->rcx = com->td[com->current_td_being_setup].tdr; /*The physical address of a TDR page (HKID bits must be 0)*/

      /*rdx: The physical address (including HKID bits) of an input TD_PARAMS_STRUCT.
      The first pages of the space reserved for SEAMCALL input data were used by previous 
      TDH_SYS_INFO to return the output (td_sys_info_t struct and CMR info)*/
      regs->rdx = SEAM_AGENT_SEAMCALL_DATA_PA + _4K*2;
      
      /*now we populate TD_PARAMS_STRUCT*/
      td_sys_inf = (td_sys_info_t *)(vm->mem + SEAM_AGENT_SEAMCALL_DATA_PA);
      td_parm = (td_params_t *)(vm->mem + SEAM_AGENT_SEAMCALL_DATA_PA + _4K*2);
      memset((void *)td_parm, 0, sizeof(td_params_t));

      td_parm->attributes.raw = td_sys_inf->attributes_fixed1;
      td_parm->attributes.migratable = 0;
      td_parm->attributes.debug = 1;

      /*No need to include xfam_fixed0, td_parm->xfam is already zero initially*/
      td_parm->xfam = td_sys_inf->xfam_fixed1;
      td_parm->max_vcpus = 16;

      /*May be between 0 and 3. A value of 0 indicates no TD Partitioning is supported.*/
      td_parm->num_l2_vms = 0;

      td_parm->msr_config_ctls.ia32_arch_cap = 0;
      td_parm->eptp_controls.ept_ps_mt = 0b110;
      td_parm->eptp_controls.ept_pwl = TDX_SEPT_LEVELS; /*5 level EPT page walk through*/

      /*0: GPA.SHARED bit is GPA[47]. A value of 1 can only be specified if EPTP_CONTROLS[5:3] 
      is specified as 4 (i.e., 5-level EPT)*/
      td_parm->config_flags.gpaw = 1;
      /*Controls the guest TD’s ability to change the PENDING page access behavior
      from its default value:*/
      td_parm->config_flags.flexible_pending_ve = 0;
      /*TD-scope virtual TSC frequency in units of 25MHz – must be between 4 and 400.*/
      td_parm->tsc_frequency = 100;

      /*Software-defined ID for non-owner-defined configuration of the guest TD*/
      td_parm->mr_config_id.qwords[0] = 0x001; 
      /*Software-defined ID for the guest TD’s owner*/
      td_parm->mr_owner.qwords[0] = 0x001;
      /*Software-defined ID for owner-defined configuration of the guest TD*/
      td_parm->mr_owner_config.qwords[0] = 0x001;

      td_parm->ia32_arch_capabilities_config = 0;
      
      /*At the moment, we do not provide cpuid configs*/

}

void setup_tdg_servtd_bind_args(struct kvm_regs *regs){

      servtd_attributes_t servtd_atr;

      regs->rcx = com->td[com->current_td_being_setup].tdr;
      regs->rdx = com->td[com->serv_td_owenr_being_setup].tdr;
      regs->r8 = 0;
      regs->r9 = 0; /*SERVTD_TYPE:0 = migration td*/
      
      servtd_atr.raw = 0;
      servtd_atr.instance_binding = 1;
      servtd_atr.ignore_tdinfo.attributes = 1;
      servtd_atr.ignore_tdinfo.xfam = 1;
      servtd_atr.ignore_tdinfo.mrtd = 1;
      servtd_atr.ignore_tdinfo.mrconfig = 1;
      servtd_atr.ignore_tdinfo.mrowner = 1;
      servtd_atr.ignore_tdinfo.mrownerconfig = 1;
      servtd_atr.ignore_tdinfo.rtmr = 0b1111;
      servtd_atr.ignore_tdinfo.servtd_hash = 1;

      regs->r10 = servtd_atr.raw;
}

void setup_tdg_servtd_prebind_args(struct kvm_regs *regs){

      servtd_attributes_t servtd_atr;

      regs->rcx = com->td[com->current_td_being_setup].tdr;
      regs->rdx = SEAM_AGENT_SEAMCALL_DATA_PA + _4K*3;
      regs->r8 = 0;
      regs->r9 = 0; /*SERVTD_TYPE:0 = migration td*/
      
      servtd_atr.raw = 0;
      servtd_atr.instance_binding = 1;
      servtd_atr.ignore_tdinfo.attributes = 1;
      servtd_atr.ignore_tdinfo.xfam = 1;
      servtd_atr.ignore_tdinfo.mrtd = 1;
      servtd_atr.ignore_tdinfo.mrconfig = 1;
      servtd_atr.ignore_tdinfo.mrowner = 1;
      servtd_atr.ignore_tdinfo.mrownerconfig = 1;
      servtd_atr.ignore_tdinfo.rtmr = 0b1111;
      servtd_atr.ignore_tdinfo.servtd_hash = 1;

      regs->r10 = servtd_atr.raw;
}
