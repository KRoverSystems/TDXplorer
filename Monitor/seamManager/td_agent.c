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
#include "td_agent.h"
#include "state.h"

extern ulong do_tdxcall(ulong seamcall);
extern void backup_tdxcall_args();

#define TDCALL(...) do_tdxcall(__VA_ARGS__)

extern struct comArea *com;

void set_common_tdcall_state(ulong lp_id, ulong tcall){

    com->is_tdcall = 1;
    com->current_lp = lp_id;
    com->tdcall_vmcs[lp_id].vm_exit_reason = VMEXIT_REASON_TDCALL;
    com->current_tdx_vmcs_pa = com->tdcall_vmcs[lp_id].vmcs_pa;
  	memset((void *)&com->last_tdcall, 0, sizeof(struct tdxCall));
	com->last_tdcall.tdxcall = tcall;
	com->last_tdcall.state = STATE_DO_TDCALL;
}

ulong tdg_vm_wr(ulong lp_id, ulong field_id, ulong data, ulong write_mask){

    struct kvm_regs regs;
	ulong rcx = 0; /*must be 0*/

	set_common_tdcall_state(lp_id, TDG_VM_WR);

	regs.rax = TDG_VM_WR;
	regs.rcx = rcx;
	regs.rdx = field_id;
	regs.r8 = data;
	regs.r9 = write_mask;
	switch_to_module_context(TDXCALL_TYPE_TDCALL, &regs);
	
	return TDCALL(TDG_VM_WR);
}

ulong tdg_vp_vmcall(ulong lp_id, struct kvm_regs *regs){

    set_common_tdcall_state(lp_id, TDG_VP_VMCALL);
    regs->rax = TDG_VP_VMCALL;
    switch_to_module_context(TDXCALL_TYPE_TDCALL, regs);

    return TDCALL(TDG_VP_VMCALL);
}

ulong do_tdcall(ulong lp_id, struct kvm_regs *regs){

    set_common_tdcall_state(lp_id, regs->rax & 0xffff);
    switch_to_module_context(TDXCALL_TYPE_TDCALL, regs);

    return TDCALL(regs->rax);
}