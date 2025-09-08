#include "common.h"

void init_tdx_module();
void create_td(ulong td_id, ulong lp_id, ulong initial_gpa_max, ulong initial_pages_to_add);
void run_td(ulong td_id, ulong lp);
void start_se();

ulong do_seamcall(ulong lp_id, struct kvm_regs *regs);
ulong tdh_sys_config(ulong lp_id, ulong tdmrinfo_pa, ulong num_ptrs, ulong global_hkid);
ulong tdh_sys_lp_init(ulong lp_id);
ulong tdh_sys_key_config(ulong lp_id);
ulong tdh_sys_tdmr_init(ulong lp_id);
ulong tdh_mng_create(ulong lp_id, ulong tdr, ulong hkid);
ulong tdh_mng_key_config(ulong lp_id, ulong tdr);
ulong tdh_mng_addcx(ulong lp_id, ulong tdr, ulong page_pa);
ulong tdh_sys_info(ulong lp_id, ulong tdsysinfo_page_pa, ulong tdsysinfo_page_size, ulong cmrinfo_ary_pa, ulong num_cmrinfo_entries);
ulong tdh_mng_init(ulong lp_id, ulong tdr, ulong tdparams_pa);
ulong tdh_vp_create(ulong lp_id, ulong tdr, ulong tdvps_pa);
ulong tdh_vp_addcx(ulong lp_id, ulong tdvpr, ulong tdcx_pa);
ulong tdh_vp_init(ulong lp_id, ulong tdvpr, ulong initial_rcx);
ulong tdh_mem_sept_add(ulong lp_id, ulong gpa, ulong level, ulong tdr, ulong new_sept_pa);
ulong tdh_mem_page_add(ulong lp_id, ulong gpa, ulong level, ulong tdr, ulong target_page, ulong source_page);
ulong tdh_mr_extend(ulong lp_id, ulong gpa, ulong tdr);
ulong tdh_mr_finalize(ulong lp_id, ulong tdr);
ulong tdh_vp_enter(ulong lp_id, ulong tdvpr);


