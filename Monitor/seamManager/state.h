#ifndef _STATE_H
#define _STATE_H

#include "common.h"

void switch_to_module_context(TDXCALL_TYPE call_type, struct kvm_regs *regs);

void prep_tdh_sys_config_args(struct kvm_regs *regs);
void prep_tdh_mng_init_args(struct kvm_regs *regs);
void prep_tdh_servtd_bind_args(struct kvm_regs *regs);
void prep_tdh_servtd_prebind_args(struct kvm_regs *regs);

ulong reserve_and_get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner);
ulong reserve_and_get_next_available_hkid();

#endif