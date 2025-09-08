#pragma once

#include <stdint.h>
#include "seam.h"
#include "common.h"

#define _2KB        0x800
#define _4KB        0x1000
#define _8KB        0x2000
#define _2MB        0x200000
#define _1GB        0x40000000

// linear address defs
#define C_KEYHOLE_EDIT_REGION_BASE  0x0000000100000000
#define C_CODE_RGN_BASE             0xFFFF800000000000
#define C_STACK_RGN_BASE            0xFFFF800100000000
#define C_KEYHOLE_RGN_BASE          0xFFFF800200000000
#define C_DATA_RGN_BASE             0xFFFF800300000000
#define C_SYS_INFO_TABLE_BASE       0xFFFF8003FFFF0000
#define C_IO_SYS_INFO_TABLE_BASE    0xFFFF8003FFFF1000
#define C_MODULE_RGN_BASE           0x0000000200000000

#define CODE_REGION_ALLOCATED_SIZE  _2MB
#define P_SEAMLDR_SHADOW_STACK_SIZE _4KB
#define C_VMCS_REGION_SIZE          _8KB // including the reserved unmapped page

#define C_P_SYS_INFO_TABLE_SIZE     _4KB


#define MOD_PAGE_SIZE               _4KB /*page size for pseamldr code region mapping*/
#define SEAMRR_PAGE_SIZE            _4KB


#define SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE      8
#define SYS_INFO_TABLE_NUM_CMRS                     32

/*for paging*/
#define IA32_PG_P      1u
#define IA32_PG_RW     (1u << 1)
#define IA32_PG_U      (1u << 2)
#define IA32_PG_WT     (1u << 3)
#define IA32_PG_CD     (1u << 4)
#define IA32_PG_A      (1u << 5)
#define IA32_PG_D      (1u << 6)
#define IA32_PG_PS     (1u << 7)
#define IA32_PG_G      (1u << 8)
#define IA32_PG_PAT_2M (1u << 12)
#define IA32_PG_PAT_4K IA32_PG_PS
#define IA32_PG_NX     (1ull << 63)

typedef unsigned long ulong;
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef uint16_t UNIT16;
typedef uint8_t UINT8;
typedef int64_t INT64;

typedef enum {
  PAGE_4K,
  PAGE_2M
} PAGE_SIZE;

#define PAGING_STRUCTURE_SIZE(rgnSize) (((((((rgnSize) / _4KB) * 8) + _4KB - 1) / _4KB) + \
                                         ((((rgnSize) / _2MB) * 8) + _4KB - 1) / _4KB + \
                                         ((((rgnSize) / _1GB) * 8) + _4KB - 1) / _4KB) * _4KB)

typedef struct {
  UINT64 Base;
  UINT64 Size;
} MemRange_t;

typedef struct {
  // fields populated by mcheck
  UINT64     Version;
  UINT32     TotNumLps;
  UINT32     TotNumSockets;
  UINT32     SocketCpuidTable[SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE];
  MemRange_t PSeamldrRange;
  UINT8      SkipSMRR2Check;
  UINT8      TDX_AC;
  UINT8      Reserved_0[62];
  MemRange_t Cmr[SYS_INFO_TABLE_NUM_CMRS];
  UINT8      Reserved_1[1408];
  // fields populated by NP-SEAMLDR
  UINT64     NpSeamldrMutex;
  MemRange_t CodeRgn;
  MemRange_t DataRgn;
  MemRange_t StackRgn;
  MemRange_t KeyholeRgn;
  MemRange_t KeyholeEditRgn;
  UINT64     ModuleRgnBase;
  UINT32     AcmX2ApicId;
  UINT32     AcmX2ApicIdValid;
  UINT8      Reserved2[1944];
} P_SYS_INFO_TABLE_t;

typedef struct P_SEAMLDR_CONSTS {
  UINT64 CDataStackSize;
  UINT64 CCodeRgnSize;
  UINT64 CDataRgnSize;
  UINT64 CKeyholeRgnSize;
  UINT64 CKeyholeEditRgnSize;
  UINT64 CEntryPointOffset;
} P_SEAMLDR_CONSTS_t;

typedef struct {
  UINT64 SeamrrVa;
  UINT64 SeamrrVaLimit;
  UINT64 AslrRand;
  UINT64 PhysAddrMask;
// //  UINT64              TdxPrivateKidMask;
//   UINT64              CStackRgnSize;
//   UINT64              CKeyholeRgnSize;
//   UINT64              CKeyholeEditRgnSize;
  UINT64              SeamrrBase;
  UINT64              SeamrrSize;
  P_SYS_INFO_TABLE_t *PSysInfoTable;
//   UINT8               Padding_0[256 - 80]; // for the next field's alignment
//   __declspec(align(256)) SEAM_EXTEND_t SeamExtend;
  P_SEAMLDR_CONSTS_t *PSeamldrConsts;
//   UINT8               Padding_1[256 - sizeof(SEAM_EXTEND_t) - sizeof(UINTN)];
} SeamldrData_t;
SeamldrData_t SeamldrData;

typedef struct {
  UINT64 PtBaseAddrLa;
  UINT64 PtBaseAddrPa;
  UINT64 PtAllocatorPa;
  UINT64 NumPageLevels;
  INT64  VPDelta;
  UINT64 PagingStructSize;
} SEAMRR_PT_CTX;

BOOL load_p_seamldr();