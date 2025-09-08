#include "common.h"

ulong do_tdcall(ulong lp_id, struct kvm_regs *regs);
ulong tdg_vp_vmcall(ulong lp_id, struct kvm_regs *regs);
ulong tdg_vm_wr(ulong lp_id, ulong field_id, ulong data, ulong write_mask);
