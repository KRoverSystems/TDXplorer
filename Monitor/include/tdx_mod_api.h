#ifndef __TDX_MOD_API__
#define __TDX_MOD_API__

#include <stdint.h>

#pragma pack(push)
#pragma pack(1)

/*IF IMPORTING DEFS FROM TDX MODULE DOUBLE CHECK ALIGNMENT REQUIREMENTS */

#define MAX_RESERVED_AREAS 16U
/**
 * @struct tdmr_info_entry_t
 *
 * @brief TDMR_INFO provides information about a TDMR and its associated PAMT
 *
 * An array of TDMR_INFO entries is passed as input to SEAMCALL(TDHSYSCONFIG) leaf function.
 *
 * - The TDMRs must be sorted from the lowest base address to the highest base address,
 *   and must not overlap with each other.
 *
 * - Within each TDMR entry, all reserved areas must be sorted from the lowest offset to the highest offset,
 *   and must not overlap with each other.
 *
 * - All TDMRs and PAMTs must be contained within CMRs.
 *
 * - A PAMT area must not overlap with another PAMT area (associated with any TDMR), and must not
 *   overlap with non-reserved areas of any TDMR. PAMT areas may reside within reserved areas of TDMRs. 
 */
typedef struct __attribute__ ((aligned(8)))  __attribute__((__packed__)) tdmr_info_entry_s
{
    uint64_t tdmr_base;    /**< Base address of the TDMR (HKID bits must be 0). 1GB aligned. */
    uint64_t tdmr_size;    /**< Size of the CMR, in bytes. 1GB aligned. */
    uint64_t pamt_1g_base; /**< Base address of the PAMT_1G range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_1g_size; /**< Size of the PAMT_1G range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_2m_base; /**< Base address of the PAMT_2M range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_2m_size; /**< Size of the PAMT_2M range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_4k_base; /**< Base address of the PAMT_4K range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_4k_size; /**< Size of the PAMT_4K range associated with the above TDMR. 4K aligned. */

    struct
    {
        // NOTE: this struct is un-reachable for checking natural alignment, take it under consideration if/when adding more fields to the struct.
        uint64_t offset; /**< Offset of reserved range 0 within the TDMR. 4K aligned. */
        uint64_t size;   /**< Size of reserved range 0 within the TDMR. A size of 0 indicates a null entry. 4K aligned. */
    } rsvd_areas[MAX_RESERVED_AREAS];

} tdmr_info_entry_t;

typedef uint8_t bool_t;

typedef union
{
    struct
    {
        uint32_t rsvd :31, debug_module :1;
    };
    uint32_t raw;
} tdsysinfo_attributes_t;

/**
 * CPUID configurations
 */

typedef union
{
    struct
    {
        uint32_t leaf;     //0..31
        uint32_t subleaf;  //32..63
    };
    uint64_t raw;
} cpuid_config_leaf_subleaf_t;

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

typedef struct
{
    cpuid_config_leaf_subleaf_t leaf_subleaf;
    cpuid_config_return_values_t values;
} cpuid_config_t;
// tdx_static_assert(sizeof(cpuid_config_t) == 24, cpuid_config_t);

#define MAX_NUM_CPUID_CONFIG 12

/**
 * @struct td_sys_info_t
 *
 * @brief TDSYSINFO_STRUCT provides enumeration information about the TDX-SEAM module.
 *
 * It is an output of the SEAMCALL(TDSYSINFO) leaf function.
 *
 */
typedef struct __attribute__((__packed__)) td_sys_info_s
{
    /**
     * TDX Module Info
     */
    tdsysinfo_attributes_t attributes;
    uint32_t vendor_id; /**< 0x8086 for Intel */
    uint32_t build_date;
    uint16_t build_num;
    uint16_t minor_version;
    uint16_t major_version;
    uint8_t  sys_rd;
    uint8_t reserved_0[13]; /**< Must be 0 */

    /**
     * Memory Info
     */
    uint16_t max_tdmrs; /**< The maximum number of TDMRs supported. */
    uint16_t max_reserved_per_tdmr; /**< The maximum number of reserved areas per TDMR. */
    uint16_t pamt_entry_size; /**< The number of bytes that need to be reserved for the three PAMT areas. */
    uint8_t reserved_1[10]; /**< Must be 0 */

    /**
     * Control Struct Info
     */
    uint16_t tdcs_base_size; /**< Base value for the number of bytes required to hold TDCS. */
    uint8_t reserved_2[2]; /**< Must be 0 */
    uint16_t tdvps_base_size; /**< Base value for the number of bytes required to hold TDVPS. */
    /**
     * A value of 1 indicates that additional TDVPS bytes are required to hold extended state,
     * per the TD’s XFAM.
     * The host VMM can calculate the size using CPUID.0D.01.EBX.
     * A value of 0 indicates that TDVPS_BASE_SIZE already includes the maximum supported extended state.
     */
    bool_t tdvps_xfam_dependent_size;
    uint8_t reserved_3[9]; /**< Must be 0 */

    /**
     * TD Capabilities
     */
    uint64_t attributes_fixed0; /**< If bit X is 0 in ATTRIBUTES_FIXED0, it must be 0 in any TD’s ATTRIBUTES. */
    uint64_t attributes_fixed1; /**< If bit X is 1 in ATTRIBUTES_FIXED1, it must be 1 in any TD’s ATTRIBUTES. */
    uint64_t xfam_fixed0; /**< If bit X is 0 in XFAM_FIXED0, it must be 0 in any TD’s XFAM. */
    uint64_t xfam_fixed1; /**< If bit X is 1 in XFAM_FIXED1, it must be 1 in any TD’s XFAM. */

    uint8_t reserved_4[32]; /**< Must be 0 */

    uint32_t num_cpuid_config;
    cpuid_config_t cpuid_config_list[MAX_NUM_CPUID_CONFIG];
    uint8_t reserved_5[892 - (sizeof(cpuid_config_t) * MAX_NUM_CPUID_CONFIG)];
} td_sys_info_t;

#define TD_PARAMS_RESERVED0_SIZE       4
#define TD_PARAMS_RESERVED1_SIZE       38
#define TD_PARAMS_RESERVED2_SIZE       24
#define TD_PARAMS_RESERVED3_SIZE       (768 - (sizeof(cpuid_config_return_values_t) * MAX_NUM_CPUID_CONFIG))

/**
 * @struct eptp_controls_t
 *
 * @brief Control bits of EPTP, copied to each TD VMCS on TDHVPINIT
 */
typedef union eptp_controls_s {
    struct
    {
        uint64_t ept_ps_mt          : 3;   // Bits 0-2
        uint64_t ept_pwl            : 3;   // 1 less than the EPT page-walk length
        uint64_t enable_ad_bits     : 1;
        uint64_t enable_sss_control : 1;
        uint64_t reserved_0         : 4;
        uint64_t base_pa            : 40; // Root Secure-EPT page address
        uint64_t reserved_1         : 12;
    };
    uint64_t raw;
} eptp_controls_t;
// tdx_static_assert(sizeof(eptp_controls_t) == 8, eptp_controls_t);


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
// tdx_static_assert(sizeof(config_flags_t) == 8, config_flags_t);

#define SIZE_OF_SHA384_HASH_IN_QWORDS 6
#define SIZE_OF_SHA384_HASH_IN_BYTES (SIZE_OF_SHA384_HASH_IN_QWORDS << 3)

typedef union measurement_u
{
    uint64_t qwords[SIZE_OF_SHA384_HASH_IN_QWORDS];
    uint8_t  bytes[SIZE_OF_SHA384_HASH_IN_BYTES];
} measurement_t;
// tdx_static_assert(sizeof(measurement_t) == SIZE_OF_SHA384_HASH_IN_BYTES, measurement_t);

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
// tdx_static_assert(sizeof(td_param_attributes_t) == 8, td_param_attributes_t);

/**
 * @struct td_params_t
 *
 * @brief TD_PARAMS is provided as an input to TDHMNGINIT, and some of its fields are included in the TD report.
 *
 * The format of this structure is valid for a specific MAJOR_VERSION of the TDX-SEAM module,
 * as reported by TDSYSINFO.
 */
typedef struct __attribute__((__packed__)) td_params_s
{
    td_param_attributes_t        attributes;
    /**
     * Extended Features Available Mask.
     * Indicates the extended state features allowed for the TD.
     * XFAM’s format is the same as XCR0 and IA32_XSS MSR
     */
    uint64_t                     xfam;
    uint16_t                     max_vcpus; /**< Maximum number of VCPUs */
    uint8_t                      num_l2_vms;

    struct
    {
        uint8_t  ia32_arch_cap : 1;   // Bit 0
        uint8_t  reserved_0    : 7;   // Bits 7:1
    } msr_config_ctls;

    uint8_t                      reserved_0[TD_PARAMS_RESERVED0_SIZE]; /**< Must be 0 */
    eptp_controls_t              eptp_controls;
    config_flags_t              config_flags;


    uint16_t                     tsc_frequency;

    uint8_t                      reserved_1[TD_PARAMS_RESERVED1_SIZE]; /**< Must be 0 */

    /**
     * Software defined ID for additional configuration for the SW in the TD
     */
    measurement_t                mr_config_id;
    /**
     * Software defined ID for TD’s owner
     */
    measurement_t                mr_owner;
    /**
     * Software defined ID for TD’s owner configuration
     */
    measurement_t                mr_owner_config;

    uint64_t                     ia32_arch_capabilities_config;

    uint8_t                      reserved_2[TD_PARAMS_RESERVED2_SIZE]; /**< Must be 0 */

    /**
     * CPUID leaves/sub-leaves configuration.
     * The number and order of entries must be equal to
     * the number and order of configurable CPUID leaves/sub-leaves reported by TDSYSINFO.
     * Note that the leaf and sub-leaf numbers are implicit.
     * Only bits that have been reported as 1 by TDSYSINFO may be set to 1.
     */
    cpuid_config_return_values_t cpuid_config_vals[MAX_NUM_CPUID_CONFIG];

    uint8_t                      reserved_3[TD_PARAMS_RESERVED3_SIZE];
} td_params_t;
// tdx_static_assert(sizeof(td_params_t) == SIZE_OF_TD_PARAMS_IN_BYTES, td_params_t);

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
// tdx_static_assert(sizeof(ignore_tdinfo_bitmap_t) == 2, ignore_tdinfo_bitmap_t);

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
// tdx_static_assert(sizeof(servtd_attributes_t) == 8, servtd_attributes_t);

#pragma pack(pop)

#endif /*__TDX_MOD_API__*/

/*IF IMPORTING DEFS FROM TDX MODULE DOUBLE CHECK ALIGNMENT REQUIREMENTS */

/*IF IMPORTING DEFS FROM TDX MODULE DOUBLE CHECK ALIGNMENT REQUIREMENTS */
