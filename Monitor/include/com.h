#ifndef _COM_H
#define _COM_H

#define PAGE_POOL_4K_PGS            64
#define TDX_TDMR0_AVAILABLE_SIZE    0x2000000UL  /*32M*/

#define SECURE_PAGE_COUNT           (TDX_TDMR0_AVAILABLE_SIZE*2)/0x1000
#define TDX_TDMR0_START_PA          _1G
#define AGENT_CR_INS_COUNT          16UL

typedef enum {
    SERVREQ_NONE,
    SERVREQ_READ_MEM,
    SERVREQ_WRITE_MEM,
    SERVREQ_BACKUP_PAGE,
    SERVREQ_RESTORE_PAGE,
    SERVREQ_READ_PAGE
} SERVREQ;

typedef enum  {
    SERVREQ_OWNER_NONE,
    SERVREQ_OWNER_INTERPRETER,
    SERVREQ_OWNER_S_AGENT
} SERVREQ_OWNER;

struct pg {
    char data[4096];
};

typedef union securePage_u {
    struct {
        unsigned long
            td                 :   6,  // 0-6
            hkid_owner         :   6,  // 6-11
            base_pa            :   34, // 12-45
            hkid               :   6,  // 46-51
            reserved_1         :   12; // 52-63
    } mdata;
    unsigned long raw;
} securePage;

typedef struct kHoleRefAdr_u {
    unsigned long tot_ref_count_adr;
    unsigned long hole_ref_count_adr[128];
} kHoleRefAdr;

struct tdx_call_args {
    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;

    unsigned expected_field_val;
};

struct servReq {
    SERVREQ req;
    SERVREQ_OWNER req_owner;

    /*parameters for service reqs: SERVREQ_READ_MEM, SERVREQ_WRITE_MEM & SERVREQ_READ_PAGE*/
    unsigned long seam_va;
    unsigned long data;
    unsigned long data_size;
    unsigned long khole_start;
    unsigned long khole_size;
    unsigned long page_data[512];
    
    /*parameters for service reqs: SERVREQ_BACKUP_PAGE & SERVREQ_RESTORE_PAGE*/
    struct pg pg_pool[PAGE_POOL_4K_PGS + 1];
    unsigned long bkp_pg_count;
    unsigned long seam_pg_va;

    /*tdx module address regions*/
    unsigned long mod_stack_rgn_start;
    unsigned long mod_code_rgn_start;
    unsigned long mod_data_rgn_start;

    /*general purpose data sharing*/
    unsigned long is_seed_mode;
    
    unsigned long td_epml5_pa;
    unsigned long td_epml4_pa;
    unsigned long td_epdpt_pa;
    unsigned long td_epd_pa;
    unsigned long td_ept_pa;

    unsigned long current_lp;
    unsigned long updated_sept_page; /*updated sept page*/
    unsigned long sept_level;
    unsigned long new_sept_pa;
    unsigned long td_page_pa;

    unsigned long khole_edit_start_seam_va;
    unsigned long khole_start_seam_va;
    unsigned long khole_state_seam_va;

    unsigned long keyhole_edit_ins_adr[2];

    unsigned long tdcs_start_pa;
    unsigned long tdcs_start_seam_va;

    unsigned long tdcs_binding_state_ofst;
    unsigned long tdcs_attributes_offset;
    unsigned long tdcs_op_state_ofst;

    unsigned long tdx_call_handler_start;

    /*td occupied LPs*/
    unsigned long td_num_on_lp[4]; /*EFFECTIVE_NUM_ADDRESSIBLE_LPS*/
    unsigned long td_running;
    unsigned long validate_hkid;

    /*hkid tracking*/
    securePage secPages[SECURE_PAGE_COUNT];
    unsigned long td_owner_for_next_tdxcall; /*seamcall or tdcall*/

    /*cr ins addresses*/
    unsigned long agent_cr_addr[AGENT_CR_INS_COUNT];
    unsigned long agent_code_start;

    /*khole edit ins*/
    unsigned long khole_edit_rip[2];

    /*current TD info*/
    unsigned long cur_td_local_data;
    unsigned long cur_td_tdr_adr_in_local_data;

    /*dr bp adrs*/
    unsigned long dr0_bp_adr;
    unsigned long targt_fn_adr;

    /*keyhole_edit_refcount_adrs*/
    kHoleRefAdr lp_khole_ref_adr;
    unsigned long last_khole_pte;
    unsigned long last_keyhole_edit_va;

    unsigned long idx;

    /*seam/td call end addrs*/
    unsigned long seamret;
    unsigned long vmlaunch;
    unsigned long vmresume;

    unsigned long terminate;

    struct tdx_call_args tdxcall_args;

    /*for seeded se tests*/
    unsigned long is_td_call;
    unsigned long tdx_call_number;
};

#endif /*_COM_H*/