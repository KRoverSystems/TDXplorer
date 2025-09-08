typedef union
{
    struct
    {
        uint64_t lock                                    : 1, //0
                 tme_enable                              : 1, //1
                 key_select                              : 1, //2
                 save_key_for_standby                    : 1, //3
                 tme_policy                              : 4, //4-7
                 sgx_tem_enable                          : 1, //8
                 rsvd                                    : 23, //9-31
                 mk_tme_keyid_bits                       : 4, //32-35
                 tdx_reserved_keyid_bits                 : 4, //36-39
                 rsvd1                                   : 8, //40-47
                 mk_tme_crypto_algs_aes_xts_128          : 1,
                 mk_tme_crypto_algs_aes_xts_128_with_integrity : 1,
                 mk_tme_crypto_algs_aes_xts_256          : 1,
                 mk_tme_crypto_algs_rsvd                 : 13;
    };
    uint64_t raw;
} ia32_tme_activate_t;

typedef union
{
    struct
    {
        uint64_t aes_xts_128 : 1;                // Bit 0
        uint64_t aes_xts_128_with_integrity : 1; // Bit 1
        uint64_t aes_xts_256 : 1;                // Bit 2
        uint64_t aes_xts_256_with_integrity : 1; // Bit 3
        uint64_t rsvd : 27;                      // Bits 30:4
        uint64_t tme_enc_bypass_supported   : 1; // Bit 31
        uint64_t mk_tme_max_keyid_bits : 4;      // Bits 35:32
        uint64_t mk_tme_max_keys : 15;           // Bits 50:36
        uint64_t nm_encryption_disable : 1;      // Bit 51
        uint64_t rsvd2 : 11;                     // Bits 62:52
        uint64_t implicit_bit_mask : 1;          // Bit 63
    };
    uint64_t raw;
} ia32_tme_capability_t;

typedef union
{
    struct
    {
        uint32_t num_mktme_kids;
        uint32_t num_tdx_priv_kids;
    };
    uint64_t raw;
} ia32_tme_keyid_partitioning_t;

typedef union ia32_arch_capabilities_u
{
    struct
    {
        uint64_t rdcl_no              : 1;  // Bit 0
        uint64_t irbs_all             : 1;  // Bit 1
        uint64_t rsba                 : 1;  // Bit 2
        uint64_t skip_l1dfl_vmentry   : 1;  // Bit 3
        uint64_t ssb_no               : 1;  // Bit 4
        uint64_t mds_no               : 1;  // Bit 5
        uint64_t if_pschange_mc_no    : 1;  // Bit 6
        uint64_t tsx_ctrl             : 1;  // Bit 7
        uint64_t taa_no               : 1;  // Bit 8
        uint64_t mcu_ctls             : 1;  // Bit 9
        uint64_t misc_package_ctls    : 1;  // Bit 10
        uint64_t energy_filtering_ctl : 1;  // Bit 11
        uint64_t doitm                : 1;  // Bit 12
        uint64_t sbdr_ssdp_no         : 1;  // Bit 13
        uint64_t fbsdp_no             : 1;  // Bit 14
        uint64_t psdp_no              : 1;  // Bit 15
        uint64_t reserved_1           : 1;  // Bit 16
        uint64_t fb_clear             : 1;  // Bit 17
        uint64_t fb_clear_ctrl        : 1;  // Bit 18
        uint64_t rrsba                : 1;  // Bit 19
        uint64_t bhi_no               : 1;  // Bit 20
        uint64_t xapic_disable_status : 1;  // Bit 21
        uint64_t reserved_2           : 1;  // Bit 22
        uint64_t overclocking_status  : 1;  // Bit 23
        uint64_t pbrsb_no             : 1;  // Bit 24
        uint64_t reserved_3           : 39; // BITS 25:63
    };
    uint64_t raw;
} ia32_arch_capabilities_t;
//tdx_static_assert(sizeof(ia32_arch_capabilities_t) == 8, ia32_arch_capabilities_t);

typedef union ia32_xapic_disable_status_u
{
    struct
    {
        uint64_t legacy_xapic_disabled : 1;   // Bit 0
        uint64_t reserved              : 63;  // Bits 63-1
    };
    uint64_t raw;
} ia32_xapic_disable_status_t;

typedef union ia32_misc_package_ctls_u
{
    struct
    {
        uint64_t energy_filtering_enable   : 1;   // Bit 0
        uint64_t reserved                  : 63;  // Bits 63-1
    };
    uint64_t raw;
} ia32_misc_package_ctls_t;

typedef union
{
    struct
    {
        uint64_t lbr_format                  : 6, //0-5
                 pebs_trap_indicator         : 1, //6
                 pebs_save_arch_regs         : 1, //7
                 pebs_records_encoding       : 4, //8-11
                 freeze_while_smm_supported  : 1, //12
                 full_write                  : 1, //13
                 rsvd1                       : 1, //14
                 perf_metrics_available      : 1, //15
                 pebs_output_pt_avail        : 1, //16
                 rsvd2                       : 47;//17-63
    };
    uint64_t raw;
} ia32_perf_capabilities_t;

typedef union ia32_misc_enable_u
{
    struct
    {
        uint64_t fast_strings           : 1;  // 0
        uint64_t rsvd1                  : 2;  // 1-2
        uint64_t thermal_monitor_enable : 1;  // 3
        uint64_t rsvd2                  : 3;  // 6:4
        uint64_t perfmon_available      : 1;  // 7
        uint64_t rsvd3                  : 3;  // 10:8
        uint64_t bts_unavailable        : 1;  // 11
        uint64_t pebs_unavailable       : 1;  // 12
        uint64_t rsvd4                  : 3;  // 15:13
        uint64_t enable_gv3             : 1;  // 16
        uint64_t rsvd5                  : 1;  // 17
        uint64_t enable_monitor_fsm     : 1;  // 18
        uint64_t rsvd6                  : 3;  // 21:19
        uint64_t boot_nt4               : 1;  // 22
        uint64_t tpr_message_disable    : 1;  // 23
        uint64_t rsvd7                  : 3;  // 26:24
        uint64_t rsvd8                  : 1;  // 27
        uint64_t hlep_disable           : 1;  // 28
        uint64_t rsvd9                  : 9;  // 37:29
        uint64_t turbo_mode_disable     : 1;  // 38
        uint64_t rsvd10                 : 25; // 63:39
    };
    uint64_t raw;
} ia32_misc_enable_t;

typedef union ia32_vmx_ept_vpid_cap_u
{
    struct
    {
        uint64_t exe_only_supported                             : 1;   // bit 0
        uint64_t reserved_1                                     : 5;   // bits 5:1
        uint64_t pml4_supported                                 : 1;   // bit 6
        uint64_t pml5_supported                                 : 1;   // bit 7
        uint64_t uc_supported                                   : 1;   // bit 8
        uint64_t reserved_2                                     : 5;   // bits 13:9
        uint64_t wb_supported                                   : 1;   // bit 14
        uint64_t reserved_3                                     : 1;   // bit 15
        uint64_t ps_2m_supported                                : 1;   // bit 16
        uint64_t ps_1g_supported                                : 1;   // bit 17
        uint64_t reserved_4                                     : 2;   // bits 19:18
        uint64_t invept_supported                               : 1;   // bit 20
        uint64_t ad_supported                                   : 1;   // bit 21
        uint64_t advanced_vmexit_info_supported                 : 1;   // bit 22
        uint64_t sss_support                                    : 1;   // bit 23
        uint64_t reserved_5                                     : 1;   // bit 24
        uint64_t single_context_invept_supported                : 1;   // bit 25
        uint64_t all_context_invept_supported                   : 1;   // bit 26
        uint64_t reserved_6                                     : 5;   // bit 31:27
        uint64_t invvpid_supported                              : 1;   // bit 32
        uint64_t reserved_7                                     : 7;   // bits 39:33
        uint64_t individual_addr_invvpid_supported              : 1;   // bit 40
        uint64_t single_context_invvpid_supported               : 1;   // bit 41
        uint64_t all_context_invvpid_supported                  : 1;   // bit 42
        uint64_t single_contx_retaining_globals_invvpid_supp    : 1;   // bit 43
        uint64_t reserved_8                                     : 4;   // bits 47:44
        uint64_t hlat_prefix_size                               : 6;   // Bits 53:48
        uint64_t reserved_9                                     : 10;  // Bits 63:54
    };
    uint64_t raw;
} ia32_vmx_ept_vpid_cap_t;

typedef union
{
    struct
    {
        uint64_t syscall_enabled :1; // Bit 0
        uint64_t reserved_0 :7;      // Bits 1:7
        uint64_t lme :1;             // Bit 8
        uint64_t reserved_1 :1;      // Bit 9
        uint64_t lma :1;             // Bit 10
        uint64_t nxe :1;             // Bit 11
        uint64_t reserved_2 :52;
    };
    uint64_t raw;
} ia32_efer_t;

typedef union
{
   struct
   {
        uint32_t type   : 4;   // Bits 3:0
        uint32_t s      : 1;   // Bit 4
        uint32_t dpl    : 2;   // Bits 6:5
        uint32_t p      : 1;   // Bit 7
        uint32_t rsv    : 3;   // Bits 10:8
        uint32_t null   : 1;   // Bit 11
        uint32_t avl    : 1;   // Bit 12
        uint32_t l      : 1;   // Bit 13
        uint32_t db     : 1;   // Bit 14
        uint32_t g      : 1;   // Bit 15
        uint32_t usable : 1;   // Bit 16
        uint32_t rsvd   : 15;  // Bits 31:17
    };

    uint32_t raw;
} seg_arbyte_t;