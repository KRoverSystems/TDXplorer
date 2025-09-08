#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// #include "np_loader_defs.h"
#include "np_loader.h"
#include "defs.h"
#include "seam.h"
#include "common.h"
#include "data_read.h"
#include "msr.h"
#include "np_elf64.h"

extern struct vm *vm;
extern struct vcpu *vcpu;

static char pt_names[] = "pml4\0pdpt\0pd  \0pt  \0";
SEAMRR_PT_CTX SeamrrPtCtx;

// BOOL load_p_seamldr();
UINT64* map_page(SEAMRR_PT_CTX* SeamrrPtCtx, UINT64 LinearAddr, UINT64 PhysAddr, UINT64 Attr, PAGE_SIZE PageMappingSize, BOOL IsKeyHoleMapping);

void setup_sysinfo_table() {
    SeamldrData.PSysInfoTable->CodeRgn.Base = C_CODE_RGN_BASE | SeamldrData.AslrRand;
    SeamldrData.PSysInfoTable->CodeRgn.Size = SeamldrData.PSeamldrConsts->CCodeRgnSize;
    SeamldrData.PSysInfoTable->DataRgn.Base = C_DATA_RGN_BASE | SeamldrData.AslrRand;
    SeamldrData.PSysInfoTable->DataRgn.Size = SeamldrData.PSeamldrConsts->CDataRgnSize;
    SeamldrData.PSysInfoTable->StackRgn.Base = C_STACK_RGN_BASE | SeamldrData.AslrRand;
    SeamldrData.PSysInfoTable->StackRgn.Size = SeamldrData.PSeamldrConsts->CDataStackSize + P_SEAMLDR_SHADOW_STACK_SIZE;
    SeamldrData.PSysInfoTable->KeyholeRgn.Base = C_KEYHOLE_RGN_BASE | SeamldrData.AslrRand;
    SeamldrData.PSysInfoTable->KeyholeRgn.Size = SeamldrData.PSeamldrConsts->CKeyholeRgnSize;
    SeamldrData.PSysInfoTable->KeyholeEditRgn.Base = C_KEYHOLE_EDIT_REGION_BASE | SeamldrData.AslrRand;
    SeamldrData.PSysInfoTable->KeyholeEditRgn.Size = SeamldrData.PSeamldrConsts->CKeyholeEditRgnSize;
    SeamldrData.PSysInfoTable->ModuleRgnBase = C_MODULE_RGN_BASE | SeamldrData.AslrRand;
    
    /*TODO: 
    check an re-enable the following values. For the moment, keep commented.
    SeamldrData.PSysInfoTable->AcmX2ApicId = GetX2ApicId();x
    SeamldrData.PSysInfoTable->AcmX2ApicIdValid = SYS_INFO_TABLE_X2APICID_VALID;
    */
}

UINT64* map_page(SEAMRR_PT_CTX* SeamrrPtCtx, UINT64 LinearAddr, UINT64 PhysAddr, UINT64 Attr, PAGE_SIZE PageMappingSize, BOOL IsKeyHoleMapping) {
    UINT32 PtIdx, Idx;
    UINT64 *PxeLinear;
    UINT64 *PxePhysical = NULL;
    UINT64 CurNumPageLevels = SeamrrPtCtx->NumPageLevels;
    UINT32 PtShiftBits = 12;

    /*if page size is 2M*/
    if (PageMappingSize == PAGE_2M) {
        CurNumPageLevels--;             /*reduce page lavels by 1, i.e. no PTs to map at 4K granularity*/
        PtShiftBits = 21;               /*now, the last 21 bits of a VA corresponds to the index within a 2M page*/
        Attr |= IA32_PG_PS;             /*bit 1 indicates that the mapping is at 2M granularity*/
    }

    //NPLOG("mapping page, pa:0x%lx\tva:0x%lx\n", PhysAddr, LinearAddr);
    PxeLinear = (UINT64 *)SeamrrPtCtx->PtBaseAddrLa; /*address of pml4*/
    /*walk and fill PTs, allocate PTs if needed*/
    for (Idx = 0; Idx < CurNumPageLevels - 1; Idx++) {
        /*the PtIdx is the index in any of the paging table pml4, pdpt, pd or pt
        i.e. in the first round of this for loop PtIdx = pml4_idx, in second round PtIdx = pdpt_idx and so on*/
        PtIdx = (LinearAddr >> ((SeamrrPtCtx->NumPageLevels - 1) * 9 - Idx * 9 + 12)) & 0x1ff;
        //NPLOG("%s idx:%d", &pt_names[Idx*5], PtIdx);
        /*check if PT exists*/
        if (PxeLinear[PtIdx] == 0) {
            /*if the allocator reached the data region - error. i.e. the # of pages used for PTs have grown & 
            overlap with pseamldr's data region in the pa space. The region next to PTs in pseamlder's pa space is its data region*/
            if (SeamrrPtCtx->PtAllocatorPa >= SeamldrData.SeamrrBase + SeamldrData.SeamrrSize -
                (C_P_SYS_INFO_TABLE_SIZE + SeamldrData.PSeamldrConsts->CCodeRgnSize + SeamldrData.PSeamldrConsts->CDataStackSize + P_SEAMLDR_SHADOW_STACK_SIZE + 
                    SeamldrData.PSeamldrConsts->CDataRgnSize)) {
                return NULL;
            }
            /*since a page table(pml4, pdpt, pd or pt) does not exist, use one at pa: PtAllocatorPa (this is updated as new PTs are allocated) */
            PxeLinear[PtIdx] = SeamrrPtCtx->PtAllocatorPa | IA32_PG_P | IA32_PG_RW | IA32_PG_A | IA32_PG_U;
            // non leaf PDE mapping keyhole pages
            if (IsKeyHoleMapping && (2 == SeamrrPtCtx->NumPageLevels - Idx)) {
                PxeLinear[PtIdx] |= IA32_PG_NX;
            }
            //NPLOG("\tno mapping, allocating a %s at :0x%lx\t", &pt_names[(Idx + 1)*5], SeamrrPtCtx->PtAllocatorPa);
            SeamrrPtCtx->PtAllocatorPa += SEAMRR_PAGE_SIZE; /*update the next availabe pa for a page table(pml4, pdpt, pd or pt)*/
            //NPLOG("next PtAllocatorPa: 0x%lx", SeamrrPtCtx->PtAllocatorPa);
        }
        //NPLOG("\n");
        /*phy adr of next level pt page =  cur pt entry & (max phy adr: this is to limit) & (0xFFFFFFFFFFFFF000 : these pages are 4K aligned, hence)*/
        PxePhysical = (UINT64 *)(PxeLinear[PtIdx] & SeamldrData.PhysAddrMask & (~(SEAMRR_PAGE_SIZE - 1)));
        PxeLinear = (UINT64 *)((INT64)PxePhysical + SeamrrPtCtx->VPDelta);        // read pxe from virtual address
        //NPLOG("next pt level page, pa:0x%lx\tva:0x%lx\n", (ulong)PxePhysical, (ulong)PxeLinear);
    }
    /*map leaf level; if page size is 4K, PxeLinear points to a pt page.
    if page size is 2M PxeLinear points to a pd page*/
    PtIdx = (LinearAddr >> PtShiftBits) & 0x1ff;
    PxeLinear[PtIdx] = PhysAddr | Attr;
    //NPLOG("final level pt pa: 0x%lx\n", (ulong)PxePhysical);
    /*return PT(pd address or pt address) used for mapping*/
    return PxePhysical;
}

UINT64 map_pseamldr_tdxmodule_region(SEAMRR_PT_CTX* SeamrrPtCtx) {
    UINT64 CurLinAddr = C_MODULE_RGN_BASE | SeamldrData.AslrRand;
    UINT64 CurPhysAddr = SeamldrData.SeamrrBase;
    UINT32 Idx;
    UINT64 SeamrrSize = SeamldrData.SeamrrSize;
    UINT64 EndOf2MbMappingPhysAddr;
    
    for (Idx = 0; Idx < (SeamrrSize - SeamldrData.PSysInfoTable->PSeamldrRange.Size) / _2MB; Idx++) {
        if (CurPhysAddr + _2MB > SeamldrData.PSysInfoTable->PSeamldrRange.Base) {
            break;
        }
        if (map_page(SeamrrPtCtx, CurLinAddr, CurPhysAddr, IA32_PG_P | IA32_PG_RW | IA32_PG_A | IA32_PG_D | IA32_PG_NX, PAGE_2M, false) == NULL) {
            return -1;
        }
        CurLinAddr += _2MB;
        CurPhysAddr += _2MB;
    }
    
    if (CurPhysAddr < SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - SeamldrData.PSysInfoTable->PSeamldrRange.Size) {
        EndOf2MbMappingPhysAddr = CurPhysAddr;
        for (Idx = 0; Idx < (SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - SeamldrData.PSysInfoTable->PSeamldrRange.Size - EndOf2MbMappingPhysAddr) / _4KB; Idx++) {
            if (map_page(SeamrrPtCtx, CurLinAddr, CurPhysAddr, IA32_PG_P | IA32_PG_RW | IA32_PG_A | IA32_PG_D | IA32_PG_NX, PAGE_4K, false) == NULL) {
                return -1;
            }
            CurLinAddr += _4KB;
            CurPhysAddr += _4KB;
        }
    }

    return 0;
}

UINT64 map_pseamldr_sysinfo_table(SEAMRR_PT_CTX* SeamrrPtCtx) {
    UINT64 Status = 0;    
    UINT64 CurPhysAddress = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - _4KB;
    UINT64 CurLinAddress = C_SYS_INFO_TABLE_BASE | SeamldrData.AslrRand;

    if (map_page(SeamrrPtCtx, CurLinAddress, CurPhysAddress, IA32_PG_P | IA32_PG_A | IA32_PG_NX, PAGE_4K, false) == NULL) {
        Status = -1;
        NPLOG("Failed to map sysinfo table!\n");
        goto EXIT;
    }


EXIT:
    return Status;
}

UINT64 map_pseamldr_data_region(SEAMRR_PT_CTX *SeamrrPtCtx) {
    UINT64 CurLinAddr = C_DATA_RGN_BASE | SeamldrData.AslrRand;    
    /*why the _4kB below?*/ 
    UINT64 CurPhysAddr = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - (_4KB + SeamldrData.PSeamldrConsts->CCodeRgnSize + SeamldrData.PSeamldrConsts->CDataStackSize + C_P_SYS_INFO_TABLE_SIZE + SeamldrData.PSeamldrConsts->CDataRgnSize);
    UINT32 Idx;

    for (Idx = 0; Idx < SeamldrData.PSeamldrConsts->CDataRgnSize / SEAMRR_PAGE_SIZE; Idx++) {
        if (map_page(SeamrrPtCtx, CurLinAddr, CurPhysAddr, IA32_PG_P | IA32_PG_RW | IA32_PG_A | IA32_PG_D | IA32_PG_NX, PAGE_4K, true) == NULL) {
            return -1;
        }          
        CurLinAddr += SEAMRR_PAGE_SIZE;
        CurPhysAddr += SEAMRR_PAGE_SIZE;
    }

    return 0;
}

/*each page in keyhole rgn is mapped, however in the leaf level(pt) PTE, the PA is set as 0.
Then the phy page used for this leaf level pt is mapped to a page in 'key hole edit linear adr range' for easy identification/access*/
UINT64 setup_pseamldr_keyhole_region(SEAMRR_PT_CTX *SeamrrPtCtx) {
    UINT64 CurLinAddr = C_KEYHOLE_RGN_BASE | SeamldrData.AslrRand;
    UINT64 PrevMappedPtPa = (UINT64)-1;
    UINT64 CurMappedPtPa = (UINT64)NULL;
    UINT64 CurEditRgnLinAddr = C_KEYHOLE_EDIT_REGION_BASE | SeamldrData.AslrRand;
    UINT32 Idx;

    NPLOG("edit rgn linear address base\n");
    for (Idx = 0; Idx < SeamldrData.PSeamldrConsts->CKeyholeRgnSize / SEAMRR_PAGE_SIZE; Idx++) {
        /*arg2 is zero: because keyhole linear address range is to be mapped to phy adr 0 in leaf level pafe entries*/
        CurMappedPtPa = (UINT64)map_page(SeamrrPtCtx, CurLinAddr, 0, 0, PAGE_4K, true); 
        if (CurMappedPtPa == (UINT64) NULL) {
            return -1;
        }
        if (CurMappedPtPa != PrevMappedPtPa) {
            /*map the leaf level pt page in to keyhole edit region*/
            if (map_page(SeamrrPtCtx, CurEditRgnLinAddr, CurMappedPtPa,
                IA32_PG_P | IA32_PG_RW | IA32_PG_U | IA32_PG_A | IA32_PG_D | IA32_PG_NX, PAGE_4K, false) == NULL) {
                return -1;
            }

            PrevMappedPtPa = CurMappedPtPa;
            CurEditRgnLinAddr += SEAMRR_PAGE_SIZE;
            NPLOG("next edit rgn linear address");
        }
        CurLinAddr += SEAMRR_PAGE_SIZE;
    }

    return 0;
}


UINT64 map_pseamldr_stack_region(SEAMRR_PT_CTX *SeamrrPtCtx) {
    UINT32 StkPageIdx;
    UINT64 CurLinAddr = C_STACK_RGN_BASE | SeamldrData.AslrRand;
    UINT64 CurPhysAddr;
    
    CurPhysAddr = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - C_P_SYS_INFO_TABLE_SIZE - (SeamldrData.PSeamldrConsts->CCodeRgnSize) - (SeamldrData.PSeamldrConsts->CDataStackSize) - P_SEAMLDR_SHADOW_STACK_SIZE;

    for (StkPageIdx = 0; StkPageIdx < (UINT32)SeamldrData.PSeamldrConsts->CDataStackSize / SEAMRR_PAGE_SIZE; StkPageIdx++) {
        if (map_page(SeamrrPtCtx, CurLinAddr, CurPhysAddr, IA32_PG_RW | IA32_PG_A | IA32_PG_D | IA32_PG_NX | IA32_PG_P, PAGE_4K, false) == NULL) {
            return -1;
        }
        CurLinAddr += SEAMRR_PAGE_SIZE;
        CurPhysAddr += SEAMRR_PAGE_SIZE;
    }
    // shadow stack page
    if (map_page(SeamrrPtCtx, CurLinAddr, CurPhysAddr, IA32_PG_A | IA32_PG_D | IA32_PG_NX | IA32_PG_P, PAGE_4K, false) == NULL) {
        return -1;
    }
    
    return 0;
}

UINT64 map_pseamldr_code_region(SEAMRR_PT_CTX * SeamrrPtCtx, UINT32 ModuleSize) {
    UINT64 CurCodeLinearAddr = C_CODE_RGN_BASE | SeamldrData.AslrRand;
    UINT64 CurCodePhysicalAddr;
    uint32_t Idx;
        
    CurCodePhysicalAddr = SeamldrData.SeamrrBase + SeamldrData.SeamrrSize - (SeamldrData.PSeamldrConsts->CCodeRgnSize + C_P_SYS_INFO_TABLE_SIZE);
    NPLOG("CurCodePhysicalAddr:0x%lx\n", CurCodePhysicalAddr);
    for (Idx = 0; Idx < ModuleSize / MOD_PAGE_SIZE; Idx++) {
        if (map_page(SeamrrPtCtx, CurCodeLinearAddr, CurCodePhysicalAddr, IA32_PG_A | IA32_PG_P, PAGE_4K, false) == NULL) {

            return -1;
        }
        CurCodeLinearAddr += SEAMRR_PAGE_SIZE;
        CurCodePhysicalAddr += SEAMRR_PAGE_SIZE;
    }    
    return 0;
}

SEAMRR_PT_CTX* init_pseamldr_pt_ctx(SEAMRR_PT_CTX* SeamrrPtCtx, UINT64 SeamRrVa, UINT64 SeamRrBase, UINT64 SeamRrSize, UINT64 PSeamldrRangeBase, UINT64 PagingStructSize){
    (void)SeamRrSize;

    SeamrrPtCtx->PtBaseAddrLa = SeamRrVa + (PSeamldrRangeBase - SeamRrBase) + _8KB;    
    SeamrrPtCtx->PtBaseAddrPa = SeamRrBase + (PSeamldrRangeBase - SeamRrBase) + _8KB;
    
    SeamrrPtCtx->PtAllocatorPa = SeamrrPtCtx->PtBaseAddrPa + _4KB;
    SeamrrPtCtx->NumPageLevels = 4;

    SeamrrPtCtx->VPDelta = SeamRrVa - SeamRrBase;

    SeamrrPtCtx->PagingStructSize = PagingStructSize;

    NPLOG("SeamrrPtCtx->PtBaseAddrLa\t: 0x%lx\n", SeamrrPtCtx->PtBaseAddrLa);
    NPLOG("SeamrrPtCtx->PtBaseAddrPa\t: 0x%lx\n", SeamrrPtCtx->PtBaseAddrPa);
    NPLOG("SeamrrPtCtx->PtAllocatorPa\t: 0x%lx\n", SeamrrPtCtx->PtAllocatorPa);
    NPLOG("SeamrrPtCtx->PagingStructSize\t: 0x%lx\n", SeamrrPtCtx->PagingStructSize);
    NPLOG("SeamrrPtCtx->VPDelta\t\t: 0x%lx\n", SeamrrPtCtx->VPDelta);
    return SeamrrPtCtx;
}

BOOL load_p_seamldr(){

    P_SEAMLDR_CONSTS_t *pseamldr_consts;
    UINT64 CPagingStructSize;
    // SEAMRR_PT_CTX SeamrrPtCtx;
    uint64_t p_seamldr_size;
    uint64_t status;

    // SeamrrBase_u     SeamrrBaseMsr;
    // SeamrrMask_u     SeamrrMaskMsr;


    NPLOG("loading p-seamloader ......................................................\n");
    
    SeamldrData.PhysAddrMask = SEAM_MAX_PA - 1; /* (Maximum Supported phy MemAddress - 1)*/
    NPLOG("seam env max pa:0x%lx SeamldrData.PhysAddrMask: 0x%lx\n", SEAM_MAX_PA, (ulong)SeamldrData.PhysAddrMask);

    pseamldr_consts = (P_SEAMLDR_CONSTS_t *)malloc(sizeof(P_SEAMLDR_CONSTS_t));
    if(pseamldr_consts == NULL){
        NPLOG("malloc error\n");
        return false;
    }
    if(get_pseamldr_consts(pseamldr_consts) != 0){
        NPLOG("get pseamldr consts error\n");
        return false;
    }
    NPLOG("get pseamldr consts: OK\n\n");
    
    SeamldrData.PSeamldrConsts = pseamldr_consts;

    // SeamrrBaseMsr.raw = SEAM_RANGE_START_PA;
    // SeamrrMaskMsr.raw = SEAM_RANGE_SIZE | (1 << 11); /* bit 11 is the valid bit, set it to 1*/
    
    /* we do not read SEAMRR values from msr, however we do some checks as follows */
    SeamldrData.SeamrrBase = SEAM_RANGE_START_PA & B_SEAMRR_BASE;
    if(SeamldrData.SeamrrBase != SEAM_RANGE_START_PA){
        NPLOG("SEAM_RANGE_START_PA is malformed\n");  /* bits [24:0] must be 0*/
        return false;
    }
    SeamldrData.SeamrrSize = SEAM_RANGE_SIZE & B_SEAMRR_MASK;
    if(SeamldrData.SeamrrSize != SEAM_RANGE_SIZE){
        NPLOG("SEAM_RANGE_SIZE is malformed\n");  /* bits [24:0] must be 0*/
        return false;
    }
    if (SeamldrData.SeamrrSize > _1GB) {
        NPLOG("SEAM_RANGE_SIZE is too big ...\n");
        return false;
    }
    NPLOG("SeamrrBase pa: 0x%lx ,SeamrrSize: 0x%lx\n", SeamldrData.SeamrrBase, SeamldrData.SeamrrSize);

    if(sizeof(P_SYS_INFO_TABLE_t) != 4096){
        NPLOG("P_SYS_INFO_TABLE_t size is not 4K, size 0x%lx\n", sizeof(P_SYS_INFO_TABLE_t));
        return false;
    }

    SeamldrData.PSysInfoTable = (P_SYS_INFO_TABLE_t*)((UINT64)vm->mem + SEAM_RANGE_START_PA + SEAM_RANGE_SIZE - _4KB);
    
    /*The first 2K of the sysinfo table is provided as an input for NP. Here we populate some of them for our own future use.
    TODO: populate the remaining fields as needed */
    SeamldrData.PSysInfoTable->Version = 0;
    SeamldrData.PSysInfoTable->TotNumLps = NUM_ADDRESSIBLE_LPS;
    SeamldrData.PSysInfoTable->TotNumSockets = TOT_NUM_OF_SOCKETS;                 1;
    SeamldrData.PSysInfoTable->PSeamldrRange.Base = P_SEAMLDR_START_PA;
    SeamldrData.PSysInfoTable->PSeamldrRange.Size = P_SEAMLDR_SIZE;
    /*configure the CMR,Convertible Memory Regions. currently we only have one CMR*/
    SeamldrData.PSysInfoTable->Cmr[0].Base = TDX_CMR0_START_PA;
    SeamldrData.PSysInfoTable->Cmr[0].Size = TDX_CMR0_SIZE;
    NPLOG("PSysInfoTable NP's va: 0x%lx\n", (UINT64)SeamldrData.PSysInfoTable);
    NPLOG("SeamldrData.SysInfoTable->PSeamldrRange.Base: 0x%lx\n", SeamldrData.PSysInfoTable->PSeamldrRange.Base);
    NPLOG("SeamldrData.SysInfoTable->PSeamldrRange.Size: 0x%lx\n", SeamldrData.PSysInfoTable->PSeamldrRange.Size);

    SeamldrData.SeamrrVa = (UINT64)vm->mem + SEAM_RANGE_START_PA;
    SeamldrData.SeamrrVaLimit = SeamldrData.SeamrrVa + SeamldrData.SeamrrSize;
    NPLOG("SeamldrData.SeamrrVa: 0x%lx\n", SeamldrData.SeamrrVa);
    NPLOG("SeamldrData.SeamrrVaLimit: 0x%lx\n\n", SeamldrData.SeamrrVaLimit);

    SeamldrData.AslrRand = (((UINT64)(NP_SEAMLDR_ASLR_SEED & ASLR_MASK)) << 32);

    /*following the same calculation from intelNP*/
    CPagingStructSize = PAGING_STRUCTURE_SIZE(SeamldrData.PSeamldrConsts->CDataRgnSize) + 
                        PAGING_STRUCTURE_SIZE(SeamldrData.PSeamldrConsts->CCodeRgnSize) +
                        PAGING_STRUCTURE_SIZE(SeamldrData.PSeamldrConsts->CDataStackSize + P_SEAMLDR_SHADOW_STACK_SIZE) + 
                        PAGING_STRUCTURE_SIZE(SeamldrData.PSeamldrConsts->CKeyholeRgnSize) +
                        PAGING_STRUCTURE_SIZE(SeamldrData.PSeamldrConsts->CKeyholeEditRgnSize) + 
                        PAGING_STRUCTURE_SIZE(C_P_SYS_INFO_TABLE_SIZE) + 
                        PAGING_STRUCTURE_SIZE(SeamldrData.SeamrrSize - SeamldrData.PSysInfoTable->PSeamldrRange.Size) + 
                        _4KB;

    if (SeamldrData.PSysInfoTable->PSeamldrRange.Size < SeamldrData.PSeamldrConsts->CCodeRgnSize + SeamldrData.PSeamldrConsts->CDataStackSize + P_SEAMLDR_SHADOW_STACK_SIZE +
        + C_VMCS_REGION_SIZE + C_P_SYS_INFO_TABLE_SIZE + SeamldrData.PSeamldrConsts->CDataRgnSize + CPagingStructSize) {
        NPLOG("p_seamldr Range too small\n");
        return false;
    }

    /*just clearing the seam range as done by intelNP*/
    memset((UINT8*)(SeamldrData.SeamrrVa + SeamldrData.PSysInfoTable->PSeamldrRange.Base - SeamldrData.SeamrrBase), 0, (SeamldrData.SeamrrBase + SeamldrData.SeamrrSize -
        SeamldrData.PSysInfoTable->PSeamldrRange.Base - C_P_SYS_INFO_TABLE_SIZE));

    /*This is clearing the PSysInfoTable. the last 2K to be populated by NP. So NP clears it prior to using. The first 2K are not modified by NP. */
    memset((UINT8*)(SeamldrData.SeamrrVa + SeamldrData.SeamrrSize - _2KB), 0, _2KB);

    /*load pseamldr.so in to seam range: p_seamldr_code_region*/
    NPLOG("loading p_seamldr code ------------------------------------------------\n");
    p_seamldr_size = load_p_seamldr_code();
    if(p_seamldr_size == -1){
        NPLOG("load_p_seamldr_code error\n");
        return false;
    }
    NPLOG("loading p_seamldr code: OK\n\n");

    NPLOG("Init Pseamldr PT Ctx --------------------------------------------------\n");
    /*initialize data required to prepare p-seamldr's PTs*/
    init_pseamldr_pt_ctx(&SeamrrPtCtx, SeamldrData.SeamrrVa, SeamldrData.SeamrrBase, SeamldrData.SeamrrSize, SeamldrData.PSysInfoTable->PSeamldrRange.Base, CPagingStructSize);
    NPLOG("Init Pseamldr PT Ctx: OK\n\n");
    
    NPLOG("relocating image ------------------------------------------------------\n");
    /*handle relocatable sections in the pseamldr.so, do relocation. we observed one relocatable section.*/
    status = RelocateImage(SeamldrData.SeamrrVaLimit - (SeamldrData.PSeamldrConsts->CCodeRgnSize + C_P_SYS_INFO_TABLE_SIZE), C_CODE_RGN_BASE | SeamldrData.AslrRand);
    if (status != 0) {
        NPLOG("Failed to relocate P-Seamldr\n");
        return false;
    };
    NPLOG("relocating image: OK\n\n");

    NPLOG("mapping pseamldr code pages -------------------------------------------\n");
    status = map_pseamldr_code_region(&SeamrrPtCtx, p_seamldr_size);
    if (status != 0) {
        NPLOG("Failed to map pseamldr code pages\n");
        return false;
    };
    NPLOG("mapping pseamldr code pages: OK\n\n");

    NPLOG("mapping pseamldr stack pages ------------------------------------------\n");
    status = map_pseamldr_stack_region(&SeamrrPtCtx);
    if (status != 0) {
        NPLOG("Failed to map pseamldr stack pages\n");
        return false;
    };
    NPLOG("mapping pseamldr stack pages: OK\n\n");

    NPLOG("setup keyhole region --------------------------------------------------\n");
    status = setup_pseamldr_keyhole_region(&SeamrrPtCtx);
    if(status != 0){
    NPLOG("Failed to setup keyhole region\n");
        return false;
    };
    NPLOG("setup keyhole region: OK\n\n");

    NPLOG("mapping pseamldr data pages -------------------------------------------\n");
    status = map_pseamldr_data_region(&SeamrrPtCtx);
    if (status != 0) {
        NPLOG("Failed to map pseamldr data pages\n");
        return false;
    };
    NPLOG("mapping pseamldr data pages: OK\n\n");

    NPLOG("mapping pseamldr sysinfo table ----------------------------------------\n");
    status = map_pseamldr_sysinfo_table(&SeamrrPtCtx);
    if(status != 0){
        return false;
    }
    NPLOG("mapping pseamldr sysinfo table: OK\n\n");

    NPLOG("mapping pseamldr tdxmodule region -------------------------------------\n");
    status = map_pseamldr_tdxmodule_region(&SeamrrPtCtx);
    if(status != 0){
        NPLOG("Failed to map pseamldr tdxmodule region\n");
        return false;
    }
    NPLOG("mapping pseamldr tdxmodule region: OK\n\n");

    NPLOG("setting up sysinfo table\n");
    setup_sysinfo_table();

    NPLOG("SeamldrData.PSeamldrConsts->CCodeRgnSize:0x%lx\n", SeamldrData.PSeamldrConsts->CCodeRgnSize);



    NPLOG("ending NP-SEAMLDR ... .....................................................\n");
    return true;
}

