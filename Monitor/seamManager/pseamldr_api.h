#include <stddef.h>
#include "seam.h"

// #define SEAMCALL_SUCCESS                        0
typedef enum
{
    PSEAMLDR_SUCCESS            = 0x0ULL,
    PSEAMLDR_EBADPARAM          = 0x8000000000000000ULL, // Bad input parameter.
    PSEAMLDR_EBADCALL           = 0x8000000000000003ULL, // P-SEAMLDR has already been called.
    PSEAMLDR_EBADHANDOFF        = 0x8000000000000004ULL, // Update failure due to invalid or unsupported handoff data.
    PSEAMLDR_ENOMEM             = 0x8000000000010002ULL, // The new TDX module does not fit within the SEAM range constraints.
    PSEAMLDR_EUNSPECERR         = 0x8000000000010003ULL, // Unspecified platform configuration error.
    PSEAMLDR_EUNSUPCPU          = 0x8000000000010004ULL, // The module does not support one or more CPUs in the platform.
    PSEAMLDR_EBADSIG            = 0x8000000000020000ULL, // Bad TDX module signature (malformed, or signature verification failed).
    PSEAMLDR_EBADHASH           = 0x8000000000020001ULL, // Module image hash verification failed.
    PSEAMLDR_EINTERRUPT         = 0x8000000000030000ULL, // Module image hash verification failed.
    PSEAMLDR_ENOENTROPY         = 0x8000000000030001ULL, // Insufficient entropy for generating random numbers.

} api_error_type;

#define SEAMLDR_PARAMS_MAX_MODULE_PAGES_V0      496
#define SEAMLDR_PARAMS_MAX_MODULE_PAGES         SEAMLDR_PARAMS_MAX_MODULE_PAGES_V0
#define SEAMLDR_PARAMS_SIZE                     _4KB

#define SIGSTRUCT_MODULUS_SIZE                  384
#define SIGSTRUCT_SIGNATURE_SIZE                384
#define SIGSTRUCT_SEAMHASH_SIZE                 48
#define SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE     255
#define MAX_NUM_OF_LPS                          1024
#define MAX_KEYHOLE_PER_LP                      128
#define SIZE_OF_RSA_CTX_BUFFER                  0x2000
#define PSEAMLDR_DATA_CANARY_OFFSET             40

#define TDX_MODULE_BUILD_DATE                   20240410
#define PAGE_SIZE_IN_BYTES                      _4KB
#define MAX_PKGS                                8

#define PACKED                  __attribute__((__packed__))
#define ALIGN(n) __attribute__ ((aligned(n)))
#define pseamldr_static_assert(e,x) typedef char assertion_##x  [(e)?1:-1]


#pragma pack(push) /*-----------------------------------------------------------------------------*/
#pragma pack(1)

typedef uint8_t bool_t;

typedef union seam_svn_u
{
    struct
    {
        uint8_t seam_minor_svn;
        uint8_t seam_major_svn;
    };

    uint16_t raw;
} seam_svn_t;
pseamldr_static_assert(sizeof(seam_svn_t) == 2, seam_svn_t);

typedef union
{
    struct
    {
        uint32_t reserved        : 31;
        uint32_t is_debug_signed : 1;
    };

    uint32_t raw;
} module_type_t;

typedef struct PACKED tee_tcb_snv_s
{
    union
    {
        struct
        {
            uint8_t seam_minor_svn;
            uint8_t seam_major_svn;
        };
        uint16_t current_seam_svn;
    };

    uint8_t  last_patch_se_svn;
    uint8_t  reserved[13];
} tee_tcb_svn_t;

typedef struct seamldr_params_s
{
    uint32_t version;
    uint32_t scenario;
    uint64_t sigstruct_pa;
    uint8_t  reserved[104];
    uint64_t num_module_pages;
    uint64_t mod_pages_pa_list[SEAMLDR_PARAMS_MAX_MODULE_PAGES];
} seamldr_params_t;
pseamldr_static_assert(sizeof(seamldr_params_t) == SEAMLDR_PARAMS_SIZE, seamldr_params_t);


/*seam sigstruct--------------------------------------------------------------------------------------------------*/
#define SIGSTRUCT_MODULUS_SIZE                  384
#define SIGSTRUCT_SIGNATURE_SIZE                384
#define SIGSTRUCT_SEAMHASH_SIZE                 48

#define SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE     255
#define TDX_MODULE_1_0_MAJOR_SVN                0

#define SEAM_SIGSTRUCT_SIZE                     2048
#define SEAM_SIGSTRUCT_HEADER_SIZE              128
#define SEAM_SIGSTRUCT_SIG_OFFSET               SEAM_SIGSTRUCT_HEADER_SIZE
#define SEAM_SIGSTRUCT_SIG_SIZE                 (384+4+384)
#define SEAM_SIGSTRUCT_BODY_OFFSET              (SEAM_SIGSTRUCT_SIG_OFFSET + SEAM_SIGSTRUCT_SIG_SIZE)

#define SEAM_SIGSTRUCT_KEY_SIZE_DWORDS        0x60
#define SEAM_SIGSTRUCT_MODULUS_SIZE_DWORDS    0x60
#define SEAM_SIGSTRUCT_EXPONENT_SIZE_DWORDS   0x1
#define SEAM_SIGSTRUCT_RSA_EXPONENT           0x10001 // (2^16 + 1)
#define SEAM_SIGSTRUCT_HEADER_TYPE_GENERIC_FW 0x6
#define SEAM_SIGSTRUCT_HEADER_LENGTH_DWORDS   0xE1
#define SEAM_SIGSTRUCT_HEADER_VERSION_MINOR   0x0UL
#define SEAM_SIGSTRUCT_HEADER_VERSION_MAJOR   0x1UL
#define SEAM_SIGSTRUCT_HEADER_VERSION         ((SEAM_SIGSTRUCT_HEADER_VERSION_MAJOR << 16) | \
                                                SEAM_SIGSTRUCT_HEADER_VERSION_MINOR)
#define SEAM_SIGSTRUCT_SIZE_DWORDS            0x200
#define SEAM_SIGSTRUCT_INTEL_MODULE_VENDOR    0x8086

// #define SEAM_SIGSTRUCT_BODY_SIZE       (SEAM_SIGSTRUCT_SIZE - SEAM_SIGSTRUCT_HEADER_SIZE - SEAM_SIGSTRUCT_SIG_SIZE)

// #if ((SEAM_SIGSTRUCT_BODY_OFFSET + SEAM_SIGSTRUCT_BODY_SIZE) != SEAM_SIGSTRUCT_SIZE)
// #error "Wrong SEAM SIGSTRUCT size constants!!!"
// #endif

/**
 * @struct keyhole_entry_t
 *
 * @brief Holds physical to linear PTE mappings
 *
 * It implements an LRU list and a hash list entry.
 */
typedef struct PACKED keyhole_entry_s
{
    uint64_t  mapped_pa;  /**< mapped physical address of this keyhole entry */
    /**
     * lru_next and lru_prev present an LRU doubly linked-list.
     */
    uint16_t  lru_next;
    uint16_t  lru_prev;
    uint16_t  hash_list_next;  /**< next element in hash list */
    /**
     * state can be KH_ENTRY_FREE or KH_ENTRY_MAPPED or KH_ENTRY_CAN_BE_REMOVED.
     */
    uint8_t   state;
    bool_t    is_writable;  /**< is PTE set to be Read-only or RW */
    bool_t    is_wb_memtype; /**< is PTE should be with WB or UC memtype */
} keyhole_entry_t;

/**
 * @struct rsa_ctx_t
 *
 * @brief Context of an RSA process.
 */
typedef struct rsa_ctx_s
{
    uint8_t buffer[SIZE_OF_RSA_CTX_BUFFER];
} rsa_ctx_t;

/**
 * @struct keyhole_state_t
 *
 * @brief Holds the state of the keyhole mappings for this lp
 *
 * It implements an LRU list and a hash list.
 */
typedef struct PACKED keyhole_state_s
{
    /**
     * Each index in the keyhole_array presents an offset of the mapped linear address.
     * The array also implement and LRU doubly linked-list.
     */
    keyhole_entry_t keyhole_array[MAX_KEYHOLE_PER_LP];
    /**
     * A hash table, its index represents the index in the keyhole_array
     * that it is mapped to.
     */
    uint16_t  hash_table[MAX_KEYHOLE_PER_LP];
    /**
     * lru_head and lru_tail present the index of the keyhole_array LRU
     * doubly linked-list.
     */
    uint16_t  lru_head;
    uint16_t  lru_tail;
} keyhole_state_t;

/**
 * @struct seamextend_t
 *
 * @brief The processor maintains a platform-scoped register called SEAMEXTEND,
 *
 * Which records the attributes of the current SEAM module, and its basic execution controls.
 * P-SEAMLDR can retrieve and update this register using IA32_SEAMEXTEND command MSR.
 *
 */
typedef struct PACKED seamextend_s
{
    uint64_t      valid;
    tee_tcb_svn_t tee_tcb_svn;
    uint8_t       mrseam[48];
    uint8_t       mrsigner[48];
    uint64_t      attributes;
    uint8_t       seam_ready;
    bool_t        system_under_debug;
    uint8_t       p_seamldr_ready;
    uint8_t       reserved[5];
} seamextend_t;
pseamldr_static_assert(sizeof(seamextend_t) == 136, seamextend_t);

typedef struct PACKED system_info_s
{
    bool_t   initialized;
    uint64_t max_pa;
    uint64_t seamrr_base;
    uint64_t seamrr_size;
    uint64_t hkid_mask;
    uint64_t private_hkid_min;
} system_info_t;

typedef union ia32_spec_ctrl_u
{
    struct
    {
        uint64_t ibrs : 1;
        uint64_t stibp : 1;
        uint64_t ssbd : 1;
        uint64_t reserved : 61;
    };
    uint64_t raw;
} ia32_spec_ctrl_t;

typedef union PACKED gprs_state_u
{
    struct
    {
        uint64_t rax;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rbx;
        uint64_t rsp_placeholder;
        uint64_t rbp;
        uint64_t rsi;
        uint64_t rdi;
        uint64_t r8;
        uint64_t r9;
        uint64_t r10;
        uint64_t r11;
        uint64_t r12;
        uint64_t r13;
        uint64_t r14;
        uint64_t r15;
    };

    uint64_t gprs[16];
} gprs_state_t;

typedef struct
{
    uint32_t header_type;
    uint32_t header_length;
    uint32_t header_version;
    module_type_t module_type;
    uint32_t module_vendor;
    uint32_t date;
    uint32_t size;
    uint32_t key_size;
    uint32_t modulus_size;
    uint32_t exponent_size;
    uint8_t reserved0[88];

    uint8_t modulus[SIGSTRUCT_MODULUS_SIZE];
    uint32_t exponent;
    uint8_t signature[SIGSTRUCT_SIGNATURE_SIZE];

    uint8_t seamhash[SIGSTRUCT_SEAMHASH_SIZE];
    seam_svn_t seamsvn;
    uint64_t attributes;
    uint32_t rip_offset;
    uint8_t num_stack_pages;
    uint8_t num_tls_pages;
    uint16_t num_keyhole_pages;
    uint16_t num_global_data_pages;
    uint16_t max_tdmrs;
    uint16_t max_rsvd_per_tdmr;
    uint16_t pamt_entry_size_4k;
    uint16_t pamt_entry_size_2m;
    uint16_t pamt_entry_size_1g;
    uint8_t  reserved1[6];
    uint16_t module_hv;
    uint16_t min_update_hv;
    bool_t   no_downgrade;
    uint8_t  reserved2[1];
    uint16_t num_handoff_pages;

    uint32_t gdt_idt_offset;
    uint32_t fault_wrapper_offset;
    uint8_t  reserved3[24];

    uint32_t cpuid_table_size;
    uint32_t cpuid_table[SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE];

} seam_sigstruct_t;

/*seamldr info-------------------------------------------------------------------*/

typedef union attributes_s
{
    struct
    {
        uint32_t reserved : 31;
        uint32_t is_debug : 1;
    };
    uint32_t raw;
} attributes_t;
pseamldr_static_assert(sizeof(attributes_t) == 4, attributes_t);

typedef struct seamldr_info_s
{
    uint32_t     version;
    attributes_t attributes;
    uint32_t     vendor_id;
    uint32_t     build_date;
    uint16_t     build_num;
    uint16_t     minor;
    uint16_t     major;
    uint16_t     reserved_0;
    uint32_t     acm_x2apic;
    uint32_t     num_remaining_updates;
    seamextend_t seamextend;
    uint8_t      reserved_2[88];
} seamldr_info_t;
pseamldr_static_assert(sizeof(seamldr_info_t) == 256, seamldr_info_t);

typedef struct pseamldr_data_s
{
    uint8_t               canary_padding[PSEAMLDR_DATA_CANARY_OFFSET];
    uint64_t              canary;
    gprs_state_t          vmm_regs; /**< vmm host saved GPRs */

    ia32_spec_ctrl_t      vmm_spec_ctrl;

    system_info_t         system_info;

    ALIGN(2048) seam_sigstruct_t  seam_sigstruct_snapshot;
    ALIGN(256) seamextend_t seamextend_snapshot;
    ALIGN(256) seamextend_t seamextend_tmp_buf;

    uint8_t               update_bitmap[MAX_NUM_OF_LPS / 8];
    uint32_t              lps_in_update;
    uint8_t               shutdown_bitmap[MAX_NUM_OF_LPS / 8];
    uint32_t              lps_in_shutdown;

    uint32_t              last_interrupted_lp;
    uint32_t              reserved;
    bool_t                module_range_initialized;
    uint32_t              num_remaining_updates;

    keyhole_state_t       keyhole_state;

    void*                 seamldr_data_fast_ref_ptr;
    void*                 psysinfo_fast_ref_ptr;

    rsa_ctx_t             rsa_context;

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    uint32_t              local_dbg_msg_num;
    debug_control_t       debug_control;
    debug_message_t       trace_buffer[TRACE_BUFFER_SIZE];
#endif

} pseamldr_data_t;

#pragma pack(pop)/*-----------------------------------------------------------------------------*/

pseamldr_static_assert(sizeof(seam_sigstruct_t) == SEAM_SIGSTRUCT_SIZE, seam_sigstruct_t);
pseamldr_static_assert(offsetof(seam_sigstruct_t, modulus) == SEAM_SIGSTRUCT_SIG_OFFSET, seam_sigstruct_t);
pseamldr_static_assert(offsetof(seam_sigstruct_t, seamhash) == SEAM_SIGSTRUCT_BODY_OFFSET, seam_sigstruct_t);

typedef union
{
    struct
    {
        uint32_t stepping_id        : 4;
        uint32_t model              : 4;
        uint32_t family             : 4;
        uint32_t processor_type     : 2;
        uint32_t rsvd0              : 2;
        uint32_t extended_model_id   : 4;
        uint32_t extended_family_id : 8;
        uint32_t rsvd1              : 4;
    };
    uint32_t raw;
} fms_info_t; //cpuid_01_eax
pseamldr_static_assert(sizeof(fms_info_t) == 4, fms_info_t);

/**
 * @struct cmr_info_entry_t
 *
 * @brief CMR_INFO provides information about a Convertible Memory Range (CMR).
 *
 * As configured by BIOS and verified and stored securely by MCHECK.
 *
 */
typedef struct PACKED cmr_info_entry_s
{
    /**
     * Base address of the CMR.  Since a CMR is aligned on 4KB, bits 11:0 are always 0.
     */
    uint64_t  cmr_base;
    /**
     * Size of the CMR, in bytes.  Since a CMR is aligned on 4KB, bits 11:0 are always 0.
     * A value of 0 indicates a null entry.
     */
    uint64_t  cmr_size;
} cmr_info_entry_t;
pseamldr_static_assert(sizeof(cmr_info_entry_t) == 16, cmr_info_entry_t);

/**
 * @struct p_sysinfo_table_t
 *
 * @brief This table is located at the last 4KB page of P-SEAMLDR range and is used to handoff information from MCHECK and NP-SEAMLDR to P-SEAMLDR.
 *
 * This structure can be used by P-SEAMLDR as a trusted source for hardware reported information.
 *
 */
typedef struct PACKED p_sysinfo_table_s
{
    // Fields populated by MCHECK
    uint64_t version;               /**< Structure Version – Set to 0 */
    uint32_t tot_num_lps;           /**< Total number of logical processors in platform */
    uint32_t tot_num_sockets;       /**< Total number of sockets in platform */
    fms_info_t socket_cpuid_table[MAX_PKGS]; /**< List of CPUID.leaf_1.EAX values from all sockets */
    uint64_t p_seamldr_range_base;  /**< Physical base address of P_SEAMLDR_RANGE */
    uint64_t p_seamldr_range_size;  /**< Size of P_SEAMLDR_RANGE, in bytes */
    uint8_t skip_smrr2_check;       /**< When set, indicates that the TDX module should not check SMRR2. */
    uint8_t tdx_ac;                 /**< When set, indicates that TDX memory is protected by Access Control only (no memory integrity). */
    uint8_t reserved_0[62];         /**< Reserved */
    cmr_info_entry_t cmr_data[MAX_CMR]; /**< CMR info (base and size) */
    uint8_t reserved_1[1408];       /**< Reserved */

    // Fields populated by NP-SEAMLDR
    uint64_t np_seamldr_mutex;      /**< Mutex used by NP_SEAMLDR to ensure that it’s running on a single package at a time. */
    uint64_t code_rgn_base;         /**< Base address of Code region */
    uint64_t code_rgn_size;         /**< Size of code region in bytes */
    uint64_t data_rgn_base;         /**< Base address of Data region */
    uint64_t data_rgn_size;         /**< Size of data region in bytes */
    uint64_t stack_rgn_base;        /**< Base address of stack region */
    uint64_t stack_rgn_size;        /**< Size of Stack Region in bytes */
    uint64_t keyhole_rgn_base;      /**< Base address of Keyhole region */
    uint64_t keyhole_rgn_size;      /**< Size of the Keyhole region in bytes */
    uint64_t keyhole_edit_rgn_base; /**< Keyhole Edit Region Base */
    uint64_t keyhole_edit_rgn_size; /**< Size of Keyhole Edit Region in bytes */
    uint64_t module_region_base;    /**< Linear base address of SEAM range. */
    uint32_t acm_x2apicid;          /**< The X2APICID of the LP in which the last call to the “shutdown” API should be done (a.k.a. ACM_X2APICID). */
    uint32_t acm_x2apicid_valid;    /**< Whether the ACM_X2APICID field is valid. Must be 1. */
    uint8_t reserved_2[1944];       /**< Reserved */
} p_sysinfo_table_t;
pseamldr_static_assert(sizeof(p_sysinfo_table_t) == PAGE_SIZE_IN_BYTES, p_sysinfo_table_t);

#define STACK_CANARY_OFFSET 0x28

/**
 * @struct sysinfo_table_t
 *
 * @brief Holds a SYSINFO table representation that is filled by the SEAMLDR
 *
 */
typedef struct PACKED sysinfo_table_s
{
    union
    {
        struct
        {
            // Fields populated by MCHECK
            uint64_t version;               /**< Structure Version – Set to 0 */
            uint32_t tot_num_lps;           /**< Total number of logical processors in platform */
            uint32_t tot_num_sockets;       /**< Total number of sockets in platform */
            fms_info_t socket_cpuid_table[MAX_PKGS]; /**< List of CPUID.leaf_1.EAX values from all sockets */
            uint8_t reserved_0[16];         /**< Reserved */
            bool_t smrr2_not_supported;
            bool_t tdx_without_integrity;
            uint8_t reserved_1[62];         /**< Reserved */
        } mcheck_fields;
        struct
        {
            //  SYS_INFO_TABLE information is saved to the last global data page (without corrupting the StackCanary field)
            uint8_t  reserved_1[STACK_CANARY_OFFSET];

            uint64_t canary; // Offset 0x28 of the last data page
        } stack_canary;
    };

    cmr_info_entry_t cmr_data[MAX_CMR]; /**< CMR info (base and size) */
    uint8_t reserved_2[1408];       /**< Reserved */

    // Fields initialized to zero by MCHECK and populated by SEAMLDR ACM
    uint64_t seam_status;           /**< SEAM status */
                                    /**< 0: NOT_LOADED   - module not loaded */
                                    /**< 1: LOADED       - module load complete */
                                    /**< 2: LOAD_IN_PROG - module load in progress */
    uint64_t code_rgn_base;         /**< Base address of Code region */
    uint64_t code_rgn_size;         /**< Size of code region in bytes */
    uint64_t data_rgn_base;         /**< Base address of Data region */
    uint64_t data_rgn_size;         /**< Size of data region in bytes */
    uint64_t stack_rgn_base;        /**< Base address of stack region */
    uint64_t stack_rgn_size;        /**< Size of Stack Region in bytes */
    uint64_t keyhole_rgn_base;      /**< Base address of Keyhole region */
    uint64_t keyhole_rgn_size;      /**< Size of the Keyhole region in bytes */
    uint64_t keyhole_edit_rgn_base; /**< Keyhole Edit Region Base */
    uint64_t keyhole_edit_rgn_size; /**< Size of Keyhole Edit Region in bytes */
    uint64_t num_stack_pages;       /**< Data Stack size per thread unit=(# 4K pages) – 1 */
    uint64_t num_tls_pages;         /**< TLS size per thread - unit=(# 4K pages) – 1 */
    uint16_t module_hv;             /**< The native handoff version that this TDX module should support */
    uint16_t min_update_hv;         /**< The minimum handoff version that this TDX module should support */
    bool_t   no_downgrade;          /**< A boolean flag that indicates whether this TDX module should disallow downgrades */
    uint8_t  reserved_3[1];         /**< Reserved */
    uint16_t num_handoff_pages;     /**< The number of 4KB pages (minus 1) allocated at the beginning of the data region for handoff data. */
    uint8_t  reserved_4[1936];

} sysinfo_table_t;
pseamldr_static_assert(sizeof(sysinfo_table_t) == PAGE_SIZE_IN_BYTES, sysinfo_table_t);
