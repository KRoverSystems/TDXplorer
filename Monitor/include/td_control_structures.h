

#include <stdint.h>

#define ALIGN(n) __attribute__ ((aligned(n)))
#define PACKED                  __attribute__((__packed__))

#define tdx_static_assert(e,x) typedef char assertion_##x  [(e)?1:-1]
#define TDX_PAGE_SIZE_IN_BYTES  0x1000
#define MAX_VMS           4
#define XCR0_MAX_VALID_BIT                  18
#define XBUFF_OFFSETS_NUM   (XCR0_MAX_VALID_BIT+1)
#define NUM_RTMRS          4
#define TDCS_MEASUREMEMNT_MRTD_CTX_SIZE         352
#define MAX_SERV_TDS          1
#define MAX_POSSIBLE_CPUID_LOOKUP           80
#define MAX_MIGS   512
#define MAX_F_MIGS 511

typedef union
{
    uint64_t qwords[4];
    uint32_t dwords[8];
    uint8_t bytes[32];
} uint256_t;

typedef uint8_t                  bool_t;
typedef uint256_t key256_t;

typedef union ALIGN(16)
{
    uint64_t  qwords[2];
    uint32_t  dwords[4];
    uint8_t   bytes[16];
} uint128_t;

typedef enum
{
    OP_STATE_UNINITIALIZED = 0,
    OP_STATE_INITIALIZED = 1,
    OP_STATE_RUNNABLE = 2,
    OP_STATE_LIVE_EXPORT = 3,
    OP_STATE_PAUSED_EXPORT = 4,
    OP_STATE_POST_EXPORT = 5,
    OP_STATE_MEMORY_IMPORT = 6,
    OP_STATE_STATE_IMPORT = 7,
    OP_STATE_POST_IMPORT = 8,
    OP_STATE_LIVE_IMPORT = 9,
    OP_STATE_FAILED_IMPORT = 10
} op_state_e;

typedef union ALIGN(2)
{
    struct
    {
        uint16_t exclusive :1;
        uint16_t host_prio :1;
        uint16_t counter   :14;
    };
    uint16_t raw;
} sharex_hp_lock_t;
tdx_static_assert(sizeof(sharex_hp_lock_t) == 2, sharex_hp_lock_t);





/**
 * @struct tdcs_management_fields_t
 *
 * @brief Holds the management fields of TDCS
 */
typedef struct tdcs_management_fields_s
{
    /**
     * The number of VCPUs that are either in TDX non-root mode (TDVPS.STATE == VCPU_ACTIVE)
     * or are ready to run (TDVPS.STATE == VCPU_READY).
     * This includes VCPUs that have been successfully initialized (by TDHVPINIT) and
     * have not since started teardown (due to a Triple Fault
     */
    uint32_t num_vcpus;
    /**
     * The number of VCPUS associated with LPs, i.e., the LPs might hold TLB
     * translations and/or cached TD VMCS
     */
    uint32_t num_assoc_vcpus;

    op_state_e         op_state;
    sharex_hp_lock_t   op_state_lock;
    uint8_t            reserved_0[2];

    // Number of L2 VMs
    uint16_t num_l2_vms;
    uint8_t reserved_1[110];

} tdcs_management_fields_t;
tdx_static_assert(sizeof(op_state_e) == 4, op_state_e);
tdx_static_assert(sizeof(tdcs_management_fields_t) == 128, tdcs_management_fields_t);

/**
 * @struct td_param_attributes_t
 *
 * @brief TD attributes.
 *
 * The value set in this field must comply with ATTRIBUTES_FIXED0 and ATTRIBUTES_FIXED1 enumerated by TDSYSINFO
 */
typedef union td_param_attributes_s {
    struct
    {
        uint64_t debug           : 1;   // Bit 0
        uint64_t reserved_tud    : 7;   // Bits 7:1
        uint64_t reserved_sec    : 20;  // Bits 28:8
        uint64_t sept_ve_disable : 1;   // Bit  28 - disable #VE on pending page access
        uint64_t migratable      : 1;   // Bit 29
        uint64_t pks             : 1;   // Bit 30
        uint64_t kl              : 1;   // Bit 31
        uint64_t reserved_other  : 31;  // Bits 62:32
        uint64_t perfmon         : 1;   // Bit 63
    };
    uint64_t raw;
} td_param_attributes_t;
tdx_static_assert(sizeof(td_param_attributes_t) == 8, td_param_attributes_t);

typedef union ia32e_eptp_u {
    struct {
        uint64_t
            ept_ps_mt          :   3,  // 0-2
            ept_pwl            :   3,  // 3-5
            enable_ad_bits     :   1,  // 6
            enable_sss_control :   1,  // 7
            reserved_0         :   4,  // 8-11
            base_pa            :   40, // 12-51
            reserved_1         :   12; // 52-63
    } fields;
    uint64_t raw;
} ia32e_eptp_t;
tdx_static_assert(sizeof(ia32e_eptp_t) == 8, ia32e_eptp_t);

/**
 * @struct cpuid_flags_t
 *
 * @brief Virtual CPUID flags:  save searching CPUID_VALUES during MSR virtualization and TD entry/exit
 */
typedef struct cpuid_flags_s
{
    bool_t monitor_mwait_supported; // virtual CPUID(0x1).ECX[3] (MONITOR)
    bool_t dca_supported;           // virtual CPUID(0x1).ECX[18]
    bool_t tsc_deadline_supported;  // virtual CPUID(0x1).ECX[24] (TSC Deadline)
    bool_t tsx_supported;           // virtual CPUID(0x7, 0x0).EBX[4] && virtual CPUID(0x7, 0x0).EBX[11]
    bool_t waitpkg_supported;       // virtual CPUID(0x7, 0x0).ECX[5]
    bool_t tme_supported;           // virtual CPUID(0x7, 0x0).ECX[13]
    bool_t mktme_supported;         // virtual CPUID(0x7, 0x0).EDX[18]
    bool_t xfd_supported;           // virtual CPUID(0xD, 0x1).EAX[4]
    bool_t ddpd_supported;          // virtual CPUID(0x7, 0x2).EDX[3]
    bool_t la57_supported;          // virtual CPUID(0x7, 0x0).ECX[16]
    uint8_t reserved[22];
} cpuid_flags_t;
tdx_static_assert(sizeof(cpuid_flags_t) == 32, cpuid_flags_t);

typedef union
{
    struct
    {
        uint64_t  notify_ept_faults : 1; // 0 - notify when zero-step attack is suspected
        uint64_t  reserved_63_1     : 63;
    };
    uint64_t  raw;
} notify_enables_t;
tdx_static_assert(sizeof(notify_enables_t) == 8, notify_enables_t);

typedef union ALIGN(2)
{
    struct
    {
        uint16_t exclusive :1;
        uint16_t counter   :15;
    };
    uint16_t raw;
} sharex_lock_t;
tdx_static_assert(sizeof(sharex_lock_t) == 2, sharex_lock_t);

typedef union
{
    struct
    {
        uint64_t ept_violation_on_l2_sept_walk_failure : 1; // bit 0:  ept violation td exit if a tdcall flow fails l2 ept walk
        uint64_t reserved                              : 63;
    };
    uint64_t  raw;
} vm_ctls_t;
tdx_static_assert(sizeof(vm_ctls_t) == 8, vm_ctls_t);

/**
 * @struct config_flags_t
 *
 * @brief Non-measured TD-scope execution controls.
 *
 * Most fields are copied to each TD VMCS TSC-offset execution control on TDHVPINIT.
 */
typedef union config_flags_s {
    struct
    {
        uint64_t
        gpaw                : 1,  /**< TD-scope Guest Physical Address Width execution control. */
        flexible_pending_ve : 1,  /**< Controls the guest TD’s ability to change the PENDING page access behavior */
        no_rbp_mod          : 1,  /**< Controls whether RBP value can be modified by TDG.VP.VMCALL and TDH.VP.ENTER. */
        reserved            : 61; /**< Must be 0. */
    };
    uint64_t raw;
} config_flags_t;
tdx_static_assert(sizeof(config_flags_t) == 8, config_flags_t);

typedef union
{
    struct
    {
        uint64_t pending_ve_disable : 1; // Bit 0:  Control the way guest TD access to a PENDING page is processed
        uint64_t reserved           : 63;
    };
    uint64_t raw;
} td_ctls_t;
tdx_static_assert(sizeof(td_ctls_t) == 8, td_ctls_t);



/**
 * @struct tdcs_execution_control_fields_t
 *
 * @brief Holds the execution fields of TDCS
 */
typedef struct tdcs_execution_control_fields_s
{
    td_param_attributes_t        attributes; /**< TD attributes */
    /**
     * xfam is Extended Features Available Mask.
     * Indicates the extended user and system features which are available for the TD
     */
    ALIGN(8) uint64_t            xfam;
    ALIGN(4) uint32_t            max_vcpus; /**< Maximum number of VCPUs. In practice, limited to 0xFFFF */
    ALIGN(1) bool_t              gpaw; /**< This bit has the same meaning as the TDCS GPAW execution control */
    /**
     * TD-scope Secure EPT pointer. Format is the same as the VMCS EPTP execution control.
     * Copied to each TD VMCS EPTP on TDVPINIT.
     */
    ALIGN(8) ia32e_eptp_t        eptp;
    ALIGN(2) sharex_lock_t       secure_ept_lock; /**< Protects Secure EPT updates */

    /**
     * TD-scope TSC offset execution control.
     * Copied to each TD VMCS TSC-offset execution control on TDHVPINIT
     */
    ALIGN(8) uint64_t            tsc_offset;

    /**
     * TD-scope TSC multiplier execution control.
     * Copied to each TD VMCS TSC-multiplier execution control on TDHVPINIT
     */
    ALIGN(8) uint64_t            tsc_multiplier;
    ALIGN(2) uint16_t            tsc_frequency;
    ALIGN(1) cpuid_flags_t       cpuid_flags;
    ALIGN(4) uint32_t            xbuff_size;
    ALIGN(8) notify_enables_t    notify_enables;
    ALIGN(8) uint64_t            hp_lock_timeout;
    ALIGN(8) vm_ctls_t           vm_ctls[MAX_VMS]; // vm controls, applicable only for l2 vms
    ALIGN(8) uint64_t            ia32_spec_ctrl_mask;
    ALIGN(8) config_flags_t      config_flags;
    ALIGN(8) td_ctls_t           td_ctls;
    uint8_t                      reserved_1[12];
    uint8_t                      cpuid_valid[80];
    ALIGN(16) uint32_t           xbuff_offsets[XBUFF_OFFSETS_NUM];
    uint8_t                      reserved_2[36];
} tdcs_execution_control_fields_t;
tdx_static_assert(sizeof(tdcs_execution_control_fields_t) == 384, tdcs_execution_control_fields_t);
// Validate that the size of gpaw (bool_t) is 1 byte
tdx_static_assert(sizeof(bool_t) == 1, gpaw);

#define TDX_SIZE_OF_EPOCH_REFCOUNT_RESERVED_IN_BYTES 4
/**
 * @struct epoch_and_refcount_t
 *
 * @brief Holds the epoch and refcount in a 128bit structure
 */
typedef struct epoch_and_refcount_s
{
    union
    {
        struct
        {
            /**
             * The TD epoch counter. This counter is incremented by the host VMM using the TDHMEMTRACK function
             */
            uint64_t       td_epoch;
            /**
             * Each REFCOUNT counts the number of LPs which may have TLB entries created
             * during a specific TD_EPOCH, and that are currently executing in TDX non-root mode
             */
            uint16_t       refcount[2];
            uint8_t        reserved[TDX_SIZE_OF_EPOCH_REFCOUNT_RESERVED_IN_BYTES];
        };
        uint128_t raw;
    };

} epoch_and_refcount_t;
tdx_static_assert(sizeof(epoch_and_refcount_t) == 16, epoch_and_refcount_t);

/**
 * @struct tdcs_epoch_tracking_fields_t
 *
 * @brief Holds the epoch tracking fields of TDCS
 */
typedef struct tdcs_epoch_tracking_fields_s
{
    epoch_and_refcount_t epoch_and_refcount;

    sharex_lock_t epoch_lock; /**< Protects the update of epoch tracking fields above as a critical region */

    uint8_t  reserved[46];

} tdcs_epoch_tracking_fields_t;
tdx_static_assert(sizeof(tdcs_epoch_tracking_fields_t) == 64, tdcs_epoch_tracking_fields_t);

#define SIZE_OF_SHA384_HASH_IN_QWORDS 6
#define SIZE_OF_SHA384_HASH_IN_BYTES (SIZE_OF_SHA384_HASH_IN_QWORDS << 3)
#define SIZE_OF_SHA384_CTX_BUFFER     256

typedef union measurement_u
{
    uint64_t qwords[SIZE_OF_SHA384_HASH_IN_QWORDS];
    uint8_t  bytes[SIZE_OF_SHA384_HASH_IN_BYTES];
} measurement_t;
tdx_static_assert(sizeof(measurement_t) == SIZE_OF_SHA384_HASH_IN_BYTES, measurement_t);

/**
 * @struct sha384_ctx_t
 *
 * @brief Context of an incremental SHA384 process.
 */
typedef struct sha384_ctx_s
{
    uint64_t last_init_seamdb_index;
    uint8_t buffer[SIZE_OF_SHA384_CTX_BUFFER];
} sha384_ctx_t;
tdx_static_assert(sizeof(sha384_ctx_t) == (SIZE_OF_SHA384_CTX_BUFFER + 8), sha384_ctx_t);

/**
 * @struct tdcs_measurement_fields_t
 *
 * @brief Holds TDCSs measurement fields
 */
typedef struct tdcs_measurement_fields_s
{
    measurement_t  mr_td; /**< Measurement of the initial contents of the TD */
    measurement_t  mr_config_id; /**< Software defined ID for additional configuration for the SW in the TD */
    measurement_t  mr_owner; /**< Software defined ID for TD's owner */
    /**
     * Software defined ID for owner-defined configuration of the guest TD,
     * e.g., specific to the workload rather than the runtime or OS.
     */

    measurement_t  mr_owner_config; /**< Software defined ID for TD's owner */
    measurement_t  rtmr [NUM_RTMRS]; /**< Array of NUM_RTMRS runtime extendable measurement registers */

    measurement_t  last_teeinfo_hash;

    sharex_hp_lock_t rtmr_lock; /**< Controls concurrent access to the RTMR array */

    bool_t         last_teeinfo_hash_valid;

    uint8_t        reserved_0[45];
    /**
     * Holds the context of an incremental SHA384 calculation on this TD
     */
    sha384_ctx_t   td_sha_ctx;

    uint8_t        reserved_1[TDCS_MEASUREMEMNT_MRTD_CTX_SIZE - sizeof(sha384_ctx_t)];
} tdcs_measurement_fields_t;
tdx_static_assert(sizeof(tdcs_measurement_fields_t) == 832, tdcs_measurement_fields_t);

/**
 * @struct bepoch_t
 *
 * @brief BEPOCH is part of the PAMT entry.  It is used for either holding BEPOCH for TLB tracking
   or migration epoch for migration tracking.
 */
typedef union bepoch_u
{
    struct
    {
        uint64_t mig_epoch    : 32; // Bits 31:0  : Migration epoch
        uint64_t export_count : 31; // Bits 62:32 : Export counter
        uint64_t mig_flag     : 1;  // Bit 63     : If set, indicates that BEPOCH is used for migration epoch
    };

    uint64_t raw;
} bepoch_t;
tdx_static_assert(sizeof(bepoch_t) == 8, bepoch_t);

/**
 * @struct tdcs_migration_fields_t
 *
 * @brief Holds TDCSs migration fields
 */
typedef struct tdcs_migration_fields_s
{
    bool_t            mig_dec_key_set;
    uint32_t          export_count;
    uint32_t          import_count;
    uint32_t          mig_epoch;
    bepoch_t          bw_epoch;
    uint64_t          total_mb_count;
    key256_t          mig_dec_key;
    key256_t          mig_dec_working_key;
    key256_t          mig_enc_key;
    key256_t          mig_enc_working_key;
    uint16_t          mig_version;
    uint16_t          mig_working_version;
    uint64_t          dirty_count;
    uint64_t          mig_count;
    uint16_t          num_migs;
    uint8_t           reserved_0[2];
    uint32_t          num_migrated_vcpus;
    uint256_t         preimport_uuid;
    sharex_lock_t     mig_lock;

    uint8_t           reserved_1[158];
} tdcs_migration_fields_t;
tdx_static_assert(sizeof(tdcs_migration_fields_t) == 384, tdcs_migration_fields_t);

typedef union
{
    struct
    {
        uint64_t vmcs_revision_id         : 31; // bits 30:0
        uint64_t rsvd0                    : 1;  // bit 31
        uint64_t vmcs_region_size         : 13; // bits 44:32
        uint64_t rsvd1                    : 3;  // bits 47:45
        uint64_t vmxon_pa_width           : 1;  // bit 48 
        uint64_t dual_monitor             : 1;  // bit 49
        uint64_t vmcs_mt                  : 4;  // bits 53:50
        uint64_t vmexit_info_on_ios       : 1;  // bit 54
        uint64_t ia32_vmx_true_available  : 1;  // bit 55
        uint64_t voe_without_err_code     : 1;  // bit 56
        uint64_t rsvd2                    : 7;  // bits 63:57
    };
    uint64_t raw;
} ia32_vmx_basic_t;
tdx_static_assert(sizeof(ia32_vmx_basic_t) == 8, ia32_vmx_basic_t);

typedef union ia32_vmx_misc_u
{
    struct
    {
        uint64_t vmx_preempt_timer_tsc_factor   : 5;   // Bits 4:0
        uint64_t unrestricted_guest             : 1;   // bit 5
        uint64_t activity_hlt                   : 1;   // bit 6
        uint64_t activity_shutdown              : 1;   // bit 7
        uint64_t activity_wait_for_sipi         : 1;   // bit 8
        uint64_t reserved                       : 5;   // bits 13:9
        uint64_t pt_in_vmx                      : 1;   // bit 14
        uint64_t ia32_smbase                    : 1;   // bit 15
        uint64_t max_cr3_targets                : 9;   // bits 24:16
        uint64_t max_msr_list_size              : 3;   // bits 27:25
        uint64_t ia32_smm_monitor_ctl           : 1;   // bit 28
        uint64_t vmwrite_any_vmcs_field         : 1;   // bit 29
        uint64_t voe_with_0_instr_length        : 1;   // bit 30
        uint64_t reserved_1                     : 1;   // bit 31
        uint64_t mseg_rev_id                    : 32;  // bits 63:32
    };
    uint64_t raw;
} ia32_vmx_misc_t;
tdx_static_assert(sizeof(ia32_vmx_misc_t) == 8, ia32_vmx_misc_t);

/**
 * @struct tdcs_virt_msrs_t
 *
 * @brief   Virtual values of VMX enumeration MSRs
 *          These values are calculated on TDH.MNG.INIT and TDH.IMPORT.STATE.IMMUTABLE.
 */
typedef struct tdcs_virt_msrs_s
{
    ia32_vmx_basic_t                virt_ia32_vmx_basic;
    ia32_vmx_misc_t                 virt_ia32_vmx_misc;
    uint64_t                      virt_ia32_vmx_cr0_fixed0;
    uint64_t                      virt_ia32_vmx_cr0_fixed1;
    uint64_t                      virt_ia32_vmx_cr4_fixed0;
    uint64_t                      virt_ia32_vmx_cr4_fixed1;
    uint64_t         virt_ia32_vmx_procbased_ctls2;
    uint64_t         virt_ia32_vmx_ept_vpid_cap;
    uint64_t         virt_ia32_vmx_true_pinbased_ctls;
    uint64_t         virt_ia32_vmx_true_procbased_ctls;
    uint64_t         virt_ia32_vmx_true_exit_ctls;
    uint64_t         virt_ia32_vmx_true_entry_ctls;
    uint64_t                        virt_ia32_vmx_vmfunc;
    uint64_t                        virt_ia32_vmx_procbased_ctls3;
    uint64_t                        virt_ia32_vmx_exit_ctls2;
    uint64_t                        virt_ia32_arch_capabilities;

    uint8_t                         reserved[128];
} tdcs_virt_msrs_t;
tdx_static_assert(sizeof(tdcs_virt_msrs_t) == 256, tdcs_virt_msrs_t);

typedef union
{
    struct
    {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
    };
    struct
    {
        uint64_t low;
        uint64_t high;
    };
    uint32_t values[4];
} cpuid_config_return_values_t;

typedef union ignore_tdinfo_bitmap_u
{
    struct
    {
        uint16_t attributes    : 1;
        uint16_t xfam          : 1;
        uint16_t mrtd          : 1;
        uint16_t mrconfig      : 1;
        uint16_t mrowner       : 1;
        uint16_t mrownerconfig : 1;
        uint16_t rtmr          : 4;
        uint16_t servtd_hash   : 1;
        uint16_t reserved      : 5;

    };
    uint16_t raw;
} ignore_tdinfo_bitmap_t;
tdx_static_assert(sizeof(ignore_tdinfo_bitmap_t) == 2, ignore_tdinfo_bitmap_t);

typedef union servtd_attributes_u
{
    struct
    {
        struct
        {
            uint32_t instance_binding   : 1;  // Bit 0
            uint32_t solicited_binding  : 1;  // Bit 1 (future, must be 0)
            uint32_t platform_binding   : 1;  // Bit 2 (future, must be 0)
            uint32_t migratable_binding : 1;  // Bit 3 (future, must be 0)
            uint32_t reserved0          : 28; // Bits 31:4
        };
        ignore_tdinfo_bitmap_t ignore_tdinfo; // Bits 47:32
        uint16_t               reserved1;     // Bits 63:48
    };
    uint64_t raw;
} servtd_attributes_t;
tdx_static_assert(sizeof(servtd_attributes_t) == 8, servtd_attributes_t);

/**
 * @struct servtd_binding_t
 *
 * @brief Holds SERVTD binding state
 */
typedef struct PACKED servtd_binding_s
{
    uint8_t             state;
    uint8_t             reserved_0;
    uint16_t            type;
    uint32_t            reserved_1;
    servtd_attributes_t attributes;
    uint256_t           uuid;
    measurement_t       info_hash;
    uint8_t             reserved_2[32];
} servtd_binding_t;
tdx_static_assert(sizeof(servtd_binding_t) == 128, servtd_binding_t);

/**
 * @struct tdcs_service_td_fields_t
 *
 * @brief Holds TDCSs service td fields
 */
typedef struct tdcs_service_td_fields_s
{
    measurement_t              servtd_hash;
    uint16_t                   servtd_num;
    ALIGN(2) sharex_hp_lock_t  servtd_bindings_lock;   // Not in the TDR TDCS spreadsheet

    uint8_t                    reserved_0[80];
    /* Service TD Binding Table
       The table is built as a set of arrays to ease metadata definition and access based
       on the TDR_TDCS spreadsheet.
    */
    ALIGN(16) servtd_binding_t servtd_bindings_table[MAX_SERV_TDS];

    uint8_t                    reserved_1[752];
} tdcs_service_td_fields_t;
tdx_static_assert(sizeof(tdcs_service_td_fields_t) == 1024, tdcs_service_td_fields_t);

typedef union migsc_link_u
{
    struct
    {
        uint64_t lock           : 1;   // Bit 0
        uint64_t initialized    : 1;   // Bit 1
        uint64_t reserved_0     : 10;   // Bits 11:2
        uint64_t migsc_hpa      : 40;  // Bits 51:12
        uint64_t reserved_1     : 12;  // Bits 63:52
    };
    uint64_t raw;
} migsc_link_t;
tdx_static_assert(sizeof(migsc_link_t) == 8, migsc_link_t);

typedef struct ALIGN(TDX_PAGE_SIZE_IN_BYTES) tdcs_s
{
    /**
     * TDCX First page - Management structures
     */
    tdcs_management_fields_t               management_fields;
    tdcs_execution_control_fields_t        executions_ctl_fields;

    tdcs_epoch_tracking_fields_t           epoch_tracking;
    tdcs_measurement_fields_t              measurement_fields;

    /**
     * Migration Fields
     */
    tdcs_migration_fields_t                migration_fields;

    tdcs_virt_msrs_t                       virt_msrs;

    /**
     * Values returned by the matching configurable CPUID leaf and sub-leaf.
     */
    cpuid_config_return_values_t           cpuid_config_vals[MAX_POSSIBLE_CPUID_LOOKUP];

    /**
     * Service TD Fields
     */
    tdcs_service_td_fields_t               service_td_fields;

    uint8_t                                reserved_io[1280];

    /**
     * TDCX 3rd page - MSR Bitmaps
     */
    ALIGN(4096) uint8_t MSR_BITMAPS[TDX_PAGE_SIZE_IN_BYTES]; /**< TD-scope RDMSR/WRMSR exit control bitmaps */

    /**
     * TDCX 4th page - Secure EPT Root Page
     */
    uint8_t sept_root_page[TDX_PAGE_SIZE_IN_BYTES];

    /**
     * TDCX 5th page - Zero Page
     */
    uint8_t zero_page[TDX_PAGE_SIZE_IN_BYTES];

    /**
     * TDCX 6th page - MIGSC links page
     */
    union
    {
         uint8_t migsc_links_page[TDX_PAGE_SIZE_IN_BYTES];
         migsc_link_t migsc_links[MAX_MIGS];
         struct {
             migsc_link_t b_migsc_link;
             migsc_link_t f_migsc_links[MAX_F_MIGS];
         };
    };

    /**
     * TDCX 7th-9th page - L2 Secure EPT Root
     */
    uint8_t L2_SEPT_ROOT_1[TDX_PAGE_SIZE_IN_BYTES];
    uint8_t L2_SEPT_ROOT_2[TDX_PAGE_SIZE_IN_BYTES];
    uint8_t L2_SEPT_ROOT_3[TDX_PAGE_SIZE_IN_BYTES];

} tdcs_t;