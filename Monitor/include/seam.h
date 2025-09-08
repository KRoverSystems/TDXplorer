#pragma once

#include <stdint.h>
#include "msize.h"

/*enum : regions in tdx module*/
typedef enum{
    RGN_CODE,
    RGN_STACK,
    RGN_PML4,
    RGN_DATA
}REGION;

#define MAX_CMR                                 32

/*Details about LPs , vCPUs and handling of VMCS...
# At a given time one LP can be considered to be executed in our SEAM environment CPU.
# Either that LP is serving a SEAMCALL or we can consider that one of the vCPU's of a 
  given TD is executing on the LP. 
# In our case we provide only 1 vCPU for a TD.
# However, since the TDs in our case are not actually executed, once the TDX module does
  a VMLAUNCH or a VMRESUME (which results in passing control to SEAM manager via HCALL), 
  we consider the LP to be occupied by the corresponding vCPU of the launched/resumed TD.
# In TDX, VMM<-->TDX-Mod transitions use per LP VMCS in seam-range and TDX-Mod<-->TD 
  transitions use per vCPU VMCS in the TDVPS of a TD maintained in secure memory.
# To support VMX instructions such as VMREAD and VMWRITE, our emulation tracks the active 
  vmcs of the current LP at runtime. Eg: Before seamcall- active vmcs is the per LP vmcs 
  of the LP, before tdcall - active vmcs is the vmcs of the vCPU of the TD. Emulation
  of VMPTRLD will toggle the active vmcs between the above two. This is ofcause assuming, 
  that the TDX module does not change the vmcs ptr to point to another other than the 
  above two as part of the module's execution.*/
#define TOT_NUM_OF_SOCKETS                  1 /*do not change*/
/*if increasing the # of LPs in future, increase the TDXMODULE_MAPPED_PAGE_COUNT 
as well, When # of LPs increase mapped page count in tdxmod increases
6LPs  --> 2000UL
10LPs --> 3500UL*/
#define NUM_ADDRESSIBLE_LPS                 4 /*do not change*/
/*We have defined EFFECTIVE_NUM_ADDRESSIBLE_LPS constant as the TDX module handles the scenarios
where the NUM_ADDRESSIBLE_LPS is odd and makes it even before using the value in execution.
However, since we have fixed the NUM_ADDRESSIBLE_LPS to be 2 in our design, the 
EFFECTIVE_NUM_ADDRESSIBLE_LPS will always be 2.*/
#define EFFECTIVE_NUM_ADDRESSIBLE_LPS       NUM_ADDRESSIBLE_LPS + (NUM_ADDRESSIBLE_LPS % 2)
#define LP_0                                0UL
#define LP_1                                1UL
#define LP_2                                2UL
#define LP_3                                3UL
#define MAX_TDS                             2UL
#define TD_0                                0UL
#define TD_1                                1UL
#define TD_START_RIP                        0XFFFUL
#define TDX_MOD                             16UL

#define SEPT_LVL_0                          0
#define SEPT_LVL_1                          1
#define SEPT_LVL_2                          2
#define SEPT_LVL_3                          3
#define SEPT_LVL_4                          4

#define SEAM_GDT_ENTRIES                    6   /*entry 0, entry 1: cs, entry 2: ds, es, entry 3: fs, gs, entry 4-5: tss*/
#define SEAM_IDT_ENTRIES                    20
#define TDX_MODULE_HANDOFF_DATA_PAGES       31
#define TDX_MODULE_STACK_PAGES              63 /*per thread*/
#define TDX_MODULE_KEYHOLE_PAGES            127 /*per lp*/
#define TDX_MODULE_TLS_PAGES                127 /*per thread*/
#define TDX_MODULE_GLOBAL_DATA_PAGES        31 /*4 pages caused errors, the global data structs were very large*/

#define MAX_KEYHOLE_PER_LP                  128 /*No point in changing, This is the value used by TDX module*/

#define TD_GPA_RANGE                        _2M /*0 to 2M, keep this in multiples of 2M*/
#define TD_GPA_RANGE_MAX                    _1G /*In create_td() we assume the max range to be LESS than 1G*/
#define TD_INITIAL_PAGE_COUNT               4

#define TDX_MODULE_PER_LP_SHDW_STACK_SIZE   _4K
#define SEAMRR_MODULE_CODE_REGION_SIZE      _2M
#define LINEAR_BASE_KEYEDIT_REION           0x0000000100000000
#define LINEAR_BASE_CODE_REGION             0xFFFF800000000000
#define LINEAR_BASE_STACK_REGION            0xFFFF800100000000
#define LINEAR_BASE_KEYHOLE_REGION          0xFFFF800200000000
#define LINEAR_BASE_DATA_REGION             0xFFFF800300000000
#define LINEAR_BASE_SYSINFO_TABLE           0xFFFF8003FFFF0000

#define PAGE_SIZE_4K                        _4K
#define PAGE_SIZE_2M                        _2M

/*SEAM environment parameters*/
#define SEAM_MAX_PA                         _2G
    #define SEAM_PHY_RANGE_1                _128M
    #define SEAM_PHY_RANGE_2                _64M
#define SEAM_ENV_PHY_MEM                    SEAM_PHY_RANGE_1

#define SEAM_RANGE_START_PA                 _64M
#define SEAM_RANGE_SIZE                     _64M
#define MODULE_RANGE_SIZE                   (SEAM_RANGE_SIZE/2)
#define P_SEAMLDR_START_PA                  SEAM_RANGE_START_PA + (SEAM_RANGE_SIZE/2)
#define P_SEAMLDR_SIZE                      (SEAM_RANGE_SIZE/2)
#define SEAM_AGENT_MGR_SHARED_AREA_SZ       _8M

/*for TD creation
We consider onlt one TDMR of 1G with everything except 32M is reserved,
so the actual memory that will be avilable for TD and its meta data is 32M.
We allocate separate 64M Guest physical memory for the vm, to cover these memory
requirements.
the PAMT_1G, PAMT_2M and PAMT_4K areas have been determined based on 1G TDMR size.
We have a single CMR that holds the non-reserved 32M of the TDMR and the PAMT region
Currently we have allocated memory for PAMT region as follows,
pamt_entry_t object size = 16B
PAMT_1G: Require 16B --> allocated 4K
PAMT_2M: Require 8K(i.e. 512x16B) --> alllocated 8K
PAMT_4K: Require 4M(i.e. 512x512x16) --> allocated 4M
All three PAMT_x regions must be 4K aligned.*/

/*#define TDX_TDMR0_START_PA                  _1G moved to com.h*/
#define TDX_TDMR0_FULL_SIZE                 _1G
/*#define TDX_TDMR0_AVAILABLE_SIZE            _32M moved to com.h*/
#define TDX_TDMR0_RESERVED_START_PA         TDX_TDMR0_START_PA + TDX_TDMR0_AVAILABLE_SIZE
#define TDX_TDMR0_RESERVED_SIZE             TDX_TDMR0_FULL_SIZE - TDX_TDMR0_AVAILABLE_SIZE
#define TDX_PAMT0_START_PA                  TDX_TDMR0_RESERVED_START_PA
#define TDX_PAMT0_1G_BASE_PA                TDX_PAMT0_START_PA
#define TDX_PAMT0_1G_SIZE                   _4K
#define TDX_PAMT0_2M_BASE_PA                TDX_PAMT0_1G_BASE_PA + TDX_PAMT0_1G_SIZE
#define TDX_PAMT0_2M_SIZE                   _8K
#define TDX_PAMT0_4K_BASE_PA                TDX_PAMT0_2M_BASE_PA + TDX_PAMT0_2M_SIZE
#define TDX_PAMT0_4K_SIZE                   _4M
#define TDX_PAMT0_SIZE                      TDX_PAMT0_1G_SIZE + TDX_PAMT0_2M_SIZE + TDX_PAMT0_4K_SIZE
#define TDX_CMR0_START_PA                   TDX_TDMR0_START_PA                  
#define TDX_CMR0_SIZE                       TDX_TDMR0_AVAILABLE_SIZE + TDX_PAMT0_SIZE

/*some sseamcalls are issued multiple times, 
the following parameters are used to derive the required number*/
#define TDMR_4K_PAMT_INIT_COUNT             _1K
#define MIN_NUM_TDCS_PAGES                  6
#define MAX_TDVPS_PAGES                     15

#define TDX_SEPT_LEVELS                      4 /*4 : 5 level ept,  3 : 4 level ept*/

/*SEAM Agent linear address layout*/
#define SEAM_AGENT_BASE_VA                  0xffff900000000000
#define SEAM_ENV_DESC_TABLES                SEAM_AGENT_BASE_VA
    #define SEAM_ENV_GDT                    SEAM_ENV_DESC_TABLES
    #define SEAM_ENV_GDT_SZ                 _4KB
    #define SEAM_ENV_TSS                    SEAM_ENV_DESC_TABLES + SEAM_ENV_GDT_SZ
    #define SEAM_ENV_TSS_SZ                 _4KB
    #define SEAM_ENV_IDT                    SEAM_ENV_DESC_TABLES + SEAM_ENV_GDT_SZ + SEAM_ENV_TSS_SZ
#define SEAM_AGENT_CODE                     SEAM_AGENT_BASE_VA + _2M
#define SEAM_AGENT_DATA                     SEAM_AGENT_CODE + _4K

#define SEAM_AGENT_STACK_PAGE_LOW           SEAM_AGENT_BASE_VA + _4M
    #define SEAM_EXCEPTION_STACK            SEAM_AGENT_BASE_VA + _4M + _1K /*first KB is for exeptions stack frame*/
    #define SEAM_EXCEPTION_STACK_PF         SEAM_AGENT_BASE_VA + _4M + _2K /*we use a separate stack to safe state after a PF*/
    #define SEAM_AGENT_STACK_PF             SEAM_AGENT_BASE_VA + _4M + _3K
    #define SEAM_AGENT_STACK                SEAM_AGENT_BASE_VA + _4M + _4K -8
#define SEAM_EMULATOR_STACK                 SEAM_AGENT_BASE_VA + _6M -8
#define SEAM_EMULATOR_STACK_PF              SEAM_AGENT_BASE_VA + _6M + _128K -8

#define SEAM_AGENT_MGR_SHARED_AREA          SEAM_AGENT_BASE_VA + _6M
#define SEAM_AGENT_SEAMCALL_DATA            SEAM_AGENT_BASE_VA + _6M + SEAM_AGENT_MGR_SHARED_AREA_SZ /*used 8M for shared comArea*/

/*SEAM Agent PA layout*/
// #define SEAM_ENV_APIC_BASE               _1M
#define SEAM_AGENT_PT_BASE_PA               _2M
#define SEAM_AGENT_PT_RGN_SZ                _2M
#define SEAM_AGENT_BASE_PA                  SEAM_AGENT_PT_BASE_PA + SEAM_AGENT_PT_RGN_SZ /*0x400000UL*/
#define SEAM_ENV_DESC_TABLES_PA             SEAM_AGENT_BASE_PA
    #define SEAM_ENV_GDT_PA                 SEAM_ENV_DESC_TABLES_PA
    #define SEAM_ENV_TSS_PA                 SEAM_ENV_DESC_TABLES_PA + SEAM_ENV_GDT_SZ
    #define SEAM_ENV_IDT_PA                 SEAM_ENV_DESC_TABLES_PA + SEAM_ENV_GDT_SZ + SEAM_ENV_TSS_SZ
#define SEAM_AGENT_CODE_PA                  SEAM_AGENT_BASE_PA + _2M

#define SEAM_AGENT_STACK_PAGE_LOW_PA        SEAM_AGENT_BASE_PA + _4M
    #define SEAM_EXCEPTION_STACK_PA             SEAM_AGENT_BASE_PA + _4M + _1K /*first KB is for exeptions stack frame*/
    #define SEAM_AGENT_STACK_PA                 SEAM_AGENT_BASE_PA + _4M + _4K -8
#define SEAM_EMULATOR_STACK_PA              SEAM_AGENT_BASE_PA + _6M -8
#define SEAM_AGENT_MGR_SHARED_PA            SEAM_AGENT_BASE_PA + _6M
#define SEAM_AGENT_SEAMCALL_DATA_PA         SEAM_AGENT_BASE_PA + _6M + SEAM_AGENT_MGR_SHARED_AREA_SZ /*used 8M for shared comArea*/
#define SEAM_AGENT_ADR_SPC_SZ               (SEAM_AGENT_SEAMCALL_DATA_PA - SEAM_AGENT_BASE_PA + _2M)

#define NP_SEAMLDR_ASLR_SEED                0x3000
#define PSEAMLDR_RDRAND_VAL                 0x2000
#define TDXMODULE_RDRAND_VAL                0xabcd
#define INITIAL_RDSEED_SEED                 0x2744C73E186EAD5C

#define ASLR_MASK                                   0x7FFC
/*following tdx specs, We add a mask to shift all va regions in the module range
int tdx, this is random. In our's it is fixed.*/
#define TDX_MODULE_ADR_MASK                 (ulong)(PSEAMLDR_RDRAND_VAL & ASLR_MASK) << 32

/*offset of keyhole_state_t struct in per lp local data (tdx_module_local_t) struct*/
#define KHOLE_STATE_OFFSET_IN_LOCAL_DATA    0x1e2

/*for MKTME HKID*/

#define BIT(n)               (uint64_t)(1ULL<<(n))
#define BITS(high,low)       ((BIT(high) - BIT(low) + BIT(high)))
#define MAX_PA_CONSIDERED_BY_TDXMOD         52
#define MAX_KEY_ID_BITS                     6
#define HKID_START_BIT                      MAX_PA_CONSIDERED_BY_TDXMOD - MAX_KEY_ID_BITS
#define HKID_MASK                           BITS(MAX_PA_CONSIDERED_BY_TDXMOD - 1, HKID_START_BIT)
// #define TDX_GLOBAL_PRIVATE_HKID             0b000100UL
#define TDX_GLOBAL_PRIVATE_HKID             0b100000UL

// #define GET_NEXT_HKID(n)     (n + 0b100UL)

/*SEAMCALLs*/
#define PSEAMLDR_SEAMCALL_SEAMLDR_INFO      0x8000000000000000
#define PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL   0x8000000000000001
#define PSEAMLDR_SEAMCALL_SEAMLDR_SHUTDOWN  0x8000000000000002
#define PSEAMLDR_SEAMCALL_SEAMLDR_SEAMINFO  0x8000000000000003

#define END_OF_LAST_SEAMCALL                0xbeeeeeeeeeeeeeed                   

/**< Enum for SEAMCALL leaves opcodes */
typedef enum seamcall_leaf_opcode_e
{
    TDH_VP_ENTER                 = 0,
    TDH_MNG_ADDCX                = 1,
    TDH_MEM_PAGE_ADD             = 2,
    TDH_MEM_SEPT_ADD             = 3,
    TDH_VP_ADDCX                 = 4,
    TDH_MEM_PAGE_RELOCATE        = 5,
    TDH_MEM_PAGE_AUG             = 6,
    TDH_MEM_RANGE_BLOCK          = 7,
    TDH_MNG_KEY_CONFIG           = 8,
    TDH_MNG_CREATE               = 9,
    TDH_VP_CREATE                = 10,
    TDH_MNG_RD                   = 11,
    TDH_MEM_RD                   = 12,
    TDH_MNG_WR                   = 13,
    TDH_MEM_WR                   = 14,
    TDH_MEM_PAGE_DEMOTE          = 15,
    TDH_MR_EXTEND                = 16,
    TDH_MR_FINALIZE              = 17,
    TDH_VP_FLUSH                 = 18,
    TDH_MNG_VPFLUSHDONE          = 19,
    TDH_MNG_KEY_FREEID           = 20,
    TDH_MNG_INIT                 = 21,
    TDH_VP_INIT                  = 22,
    TDH_MEM_PAGE_PROMOTE         = 23,
    TDH_PHYMEM_PAGE_RDMD         = 24,
    TDH_MEM_SEPT_RD              = 25,
    TDH_VP_RD                    = 26,
    TDH_MNG_KEY_RECLAIMID        = 27,
    TDH_PHYMEM_PAGE_RECLAIM      = 28,
    TDH_MEM_PAGE_REMOVE          = 29,
    TDH_MEM_SEPT_REMOVE          = 30,
    TDH_SYS_KEY_CONFIG           = 31,
    TDH_SYS_INFO                 = 32,
    TDH_SYS_INIT                 = 33,
    TDH_SYS_RD                   = 34,
    TDH_SYS_LP_INIT              = 35,
    TDH_SYS_TDMR_INIT            = 36,
    TDH_SYS_RDALL                = 37,
    TDH_MEM_TRACK                = 38,
    TDH_MEM_RANGE_UNBLOCK        = 39,
    TDH_PHYMEM_CACHE_WB          = 40,
    TDH_PHYMEM_PAGE_WBINVD       = 41,
    TDH_MEM_SEPT_WR              = 42,
    TDH_VP_WR                    = 43,
    TDH_SYS_LP_SHUTDOWN          = 44,
    TDH_SYS_CONFIG               = 45,

    TDH_SYS_SHUTDOWN             = 52,
    TDH_SYS_UPDATE               = 53,
    TDH_SERVTD_BIND              = 48,
    TDH_SERVTD_PREBIND           = 49,
    TDH_EXPORT_ABORT             = 64,
    TDH_EXPORT_BLOCKW            = 65,
    TDH_EXPORT_RESTORE           = 66,
    TDH_EXPORT_MEM               = 68,
    TDH_EXPORT_PAUSE             = 70,
    TDH_EXPORT_TRACK             = 71,
    TDH_EXPORT_STATE_IMMUTABLE   = 72,
    TDH_EXPORT_STATE_TD          = 73,
    TDH_EXPORT_STATE_VP          = 74,
    TDH_EXPORT_UNBLOCKW          = 75,
    TDH_IMPORT_ABORT             = 80,
    TDH_IMPORT_END               = 81,
    TDH_IMPORT_COMMIT            = 82,
    TDH_IMPORT_MEM               = 83,
    TDH_IMPORT_TRACK             = 84,
    TDH_IMPORT_STATE_IMMUTABLE   = 85,
    TDH_IMPORT_STATE_TD          = 86,
    TDH_IMPORT_STATE_VP          = 87,
    TDH_MIG_STREAM_CREATE        = 96
} seamcall_leaf_opcode_t;

/**< Enum for TDCALL leaves opcodes */
typedef enum tdcall_leaf_opcode_e
{
    TDG_VP_VMCALL          = 0,
    TDG_VP_INFO            = 1,
    TDG_MR_RTMR_EXTEND     = 2,
    TDG_VP_VEINFO_GET      = 3,
    TDG_MR_REPORT          = 4,
    TDG_VP_CPUIDVE_SET     = 5,
    TDG_MEM_PAGE_ACCEPT    = 6,
    TDG_VM_RD              = 7,
    TDG_VM_WR              = 8,
    TDG_VP_RD              = 9,
    TDG_VP_WR              = 10,
    TDG_SYS_RD             = 11,
    TDG_SYS_RDALL          = 12,
    TDG_SERVTD_RD          = 18,
    TDG_SERVTD_WR          = 20,
    TDG_MR_VERIFYREPORT    = 22,
    TDG_MEM_PAGE_ATTR_RD   = 23,
    TDG_MEM_PAGE_ATTR_WR   = 24,
    TDG_VP_ENTER           = 25,
    TDG_VP_INVEPT          = 26,
    TDG_VP_INVVPID         = 27
} tdcall_leaf_opcode_t;

#define PSEAMLDR_SEAMCALL_SEAMLDR_INSTALL_NAME      "SEAMLDR_INSTALL"

#define TDH_SYS_INIT_NAME                           "TDH_SYS_INIT"
#define TDH_SYS_LP_INIT_NAME                        "TDH_SYS_LP_INIT"
#define TDH_SYS_CONFIG_NAME                         "TDH_SYS_CONFIG"
#define TDH_SYS_KEY_CONFIG_NAME                     "TDH_SYS_KEY_CONFIG"
#define TDH_SYS_TDMR_INIT_NAME                      "TDH_SYS_TDMR_INIT"
#define TDH_MNG_CREATE_NAME                         "TDH_MNG_CREATE"
#define TDH_MNG_KEY_CONFIG_NAME                     "TDH_MNG_KEY_CONFIG"
#define TDH_MNG_ADDCX_NAME                          "TDH_MNG_ADDCX"
#define TDH_SYS_INFO_NAME                           "TDH_SYS_INFO"
#define TDH_MNG_INIT_NAME                           "TDH_MNG_INIT"
#define TDH_VP_CREATE_NAME                          "TDH_VP_CREATE"
#define TDH_VP_ADDCX_NAME                           "TDH_VP_ADDCX"
#define TDH_VP_INIT_NAME                            "TDH_VP_INIT"
#define TDH_MEM_SEPT_ADD_NAME                       "TDH_MEM_SEPT_ADD"
#define TDH_MEM_PAGE_ADD_NAME                       "TDH_MEM_PAGE_ADD"
#define TDH_MEM_PAGE_AUG_NAME                       "TDH_MEM_PAGE_AUG"                        
#define TDH_MEM_SEPT_RD_NAME                        "TDH_MEM_SEPT_RD"
#define TDH_MR_EXTEND_NAME                          "TDH_MR_EXTEND"
#define TDH_MR_FINALIZE_NAME                        "TDH_MR_FINALIZE"
#define TDH_VP_ENTER_NAME                           "TDH_VP_ENTER"
#define TDH_SERVTD_BIND_NAME                        "TDH_SERVTD_BIND"
#define TDH_SERVTD_PREBIND_NAME                     "TDH_SERVTD_PREBIND"
#define TDH_MNG_RD_NAME                             "TDH_MNG_RD"
#define TDH_MNG_WR_NAME                             "TDH_MNG_WR"
#define TDH_MEM_RD_NAME                             "TDH_MEM_RD"
#define TDH_MEM_WR_NAME                             "TDH_MEM_WR"
#define TDH_SYS_RD_NAME                             "TDH_SYS_RD"
#define TDH_VP_FLUSH_NAME                           "TDH_VP_FLUSH"
#define TDH_MNG_VPFLUSHDONE_NAME                    "TDH_MNG_VPFLUSHDONE"
#define TDH_VP_RD_NAME                              "TDH_VP_RD"
#define TDH_SYS_RDALL_NAME                          "TDH_SYS_RDALL"
#define TDH_VP_WR_NAME                              "TDH_VP_WR"
#define TDH_MEM_PAGE_RELOCATE_NAME                  "TDH_MEM_PAGE_RELOCATE"
#define TDH_MEM_RANGE_BLOCK_NAME                    "TDH_MEM_RANGE_BLOCK"
#define TDH_MEM_RANGE_UNBLOCK_NAME                  "TDH_MEM_RANGE_UNBLOCK"
#define TDH_MEM_TRACK_NAME                          "TDH_MEM_TRACK"
#define TDH_MEM_PAGE_REMOVE_NAME                    "TDH_MEM_PAGE_REMOVE"
#define TDH_MEM_SEPT_REMOVE_NAME                    "TDH_MEM_SEPT_REMOVE"
#define TDH_PHYMEM_PAGE_RECLAIM_NAME                "TDH_PHYMEM_PAGE_RECLAIM"
#define TDH_MEM_PAGE_DEMOTE_NAME                    "TDH_MEM_PAGE_DEMOTE"
#define TDH_MEM_PAGE_PROMOTE_NAME                   "TDH_MEM_PAGE_PROMOTE"

#define TDG_VP_VMCALL_NAME                          "TDG_VP_VMCALL"
#define TDG_MEM_PAGE_ATTR_RD_NAME                   "TDG_MEM_PAGE_ATTR_RD"
#define TDG_MEM_PAGE_ATTR_WR_NAME                   "TDG_MEM_PAGE_ATTR_WR"
#define TDG_MEM_PAGE_ACCEPT_NAME                    "TDG_MEM_PAGE_ACCEPT"
#define TDG_MR_REPORT_NAME                          "TDG_MR_REPORT"
#define TDG_SYS_RD_NAME                             "TDG_SYS_RD"
#define TDG_SYS_RDALL_NAME                          "TDG_SYS_RDALL"
#define TDG_VM_RD_NAME                              "TDG_VM_RD"
#define TDG_VP_INVEPT_NAME                          "TDG_VP_INVEPT"
#define TDG_VM_WR_NAME                              "TDG_VM_WR"
#define TDG_VP_WR_NAME                              "TDG_VP_WR"
#define TDG_VP_INFO_NAME                            "TDG_VP_INFO"
#define TDG_VP_VEINFO_GET_NAME                      "TDG_VP_VEINFO_GET"
#define TDG_VP_CPUIDVE_SET_NAME                     "TDG_VP_CPUIDVE_SET"
#define TDG_VP_RD_NAME                              "TDG_VP_RD"
#define TDG_MR_RTMR_EXTEND_NAME                     "TDG_MR_RTMR_EXTEND"
#define TDG_SERVTD_WR_NAME                          "TDG_SERVTD_WR"
#define TDG_SERVTD_RD_NAME                          "TDG_SERVTD_RD"
#define TDG_SERVTD_WR_NAME                          "TDG_SERVTD_WR"

#define SEAMCALL_SUCCESS    0UL
#define TDCALL_SUCCESS      0UL