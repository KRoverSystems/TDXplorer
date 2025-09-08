#include <string>
#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"
#include "common_idata.h"
#include "seam.h"
#include "pageManager.h"
#include "tdx_local_data.h"
#include "configs.h"

struct iData *tdx_sp_ins;

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

extern bool endCurrentPath;
extern PATH_END_RSN endCurrentPathReason;
extern struct servReq *sreq;

struct MacReg*  m_regs;
std::map<ulong, ulong> seam_va_pa_map;
std::map<ulong, ulong> seam_pa_va_map;
std::map<ulong /*buf base*/, ulong /*conc adr from seeded*/> sym_buf_bases;

int             dispatch_count = 0;
int is_se = 0;

uint8_t sym_buffer[4096];
#define PTE_TO_PA_MASK		0xfffffff000UL
#define PG_SZ_4K            0x1000UL
#define PTE_PRESENT_MASK    0x1

bool epml5_mapped_once = false;
ulong updated_sept_page_seam_va = 0;
ulong td_sept_page_seam_va[5];

bool is_epte_defined = false;

ulong last_path = 0;
int scall_failed_count = 0; 

ulong lp_keyhole_va_base;
ulong lp_khole_edit_base_va;

int sym_buf_count = 1;
ulong tdx_call_ret_adr = 0;
bool path_to_end_at_next_ins  = false;

CAnalyze::CAnalyze(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    execData = new ExecData;
    execData->insn_count = 0; 
    execData->is_next_ins_seamret = false;
    execData->current_path = 0;

    execData->last_conc_exprptr = NULL;
    execData->last_conc_ins_count = 0;

    execProfile = new ExecProfile;
    execProfile->executionMode = 0; /*DEFAULT, single pat hseeded*/
    execProfile->terminationMode = 0; /*DEFAULT, terminate at stack balance, function return*/
    execProfile->terminate_ins_count = 0;

}

CAnalyze::~CAnalyze() {
}

void CAnalyze::setExecProfileSinglePath(){
    std::cout << "setExecProfileSinglePath" << std::endl;
    execProfile->executionMode = EXEC_MD_SINGLE_PATH_SEDED;
    execProfile->terminationMode = END_AT_ANA_REQUEST;
    execProfile->startIncCount = 0;
}

void CAnalyze::setExecProfileMultiPath(){
    std::cout << "setExecProfileMultiPath" << std::endl;
    execProfile->executionMode = EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT;
    // execProfile->startRip = rip;
    // execProfile->startIncCount = 2089;
    execProfile->startIncCount = 0;
    
    // execProfile->terminationMode = END_AT_GIVEN_INS_COUNT;
    // execProfile->terminate_ins_count = 100;
}   

ulong CAnalyze::getSeedFromMemory(ulong adr){

    bool res;
    MemValue mv;

    mv.size = 8;
    mv.addr = adr;
    mv.bsym = false;
    mv.isSymList = false;

    res = m_VM->readMemory (mv);
    assert(res);
    assert(!mv.bsym);

    return mv.i64;
}

ulong CAnalyze::keyholeIdxToVa(int khole_idx, ulong pa){

    ulong seam_va = lp_keyhole_va_base + khole_idx*(PG_SZ_4K);
    seam_pa_va_map.insert({pa, seam_va});
    seam_va_pa_map.insert({seam_va, pa});
    std::cout << "pa: 0x" << std::hex << pa << "\t seam va: 0x" << seam_va << std::endl;

    return seam_va;
}

bool CAnalyze::validateKholeEditRange(ulong adr){
    if((adr < lp_khole_edit_base_va) || (adr) >= (lp_khole_edit_base_va + 128*8)){
        std::cout << "key hole edit access out off range for current LP !" << std::endl;
        assert(0);
    }
    return false;
}

bool CAnalyze::isKholeEditAddress(ulong adr){
    std::cout << "adr: 0x" << std::hex << adr << std::endl;
    if((adr >> 63) != 1){ /*khole edit mapping in the lower half of 48bit adr space*/
        std::cout << "khole-edit adr: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

ulong CAnalyze::getKholePte(ulong rip){

    ulong pte;

    std::cout << "khe-ins: 0x" << sreq->keyhole_edit_ins_adr[0] << " 0x" << sreq->keyhole_edit_ins_adr[1] << std::endl;
    // assert(0);
    // if(eff_rip == 0xffffa00000009a9c){
    if(rip == sreq->keyhole_edit_ins_adr[0]){
        pte = m_regs->regs.rdx;
        std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
    }
    // else if(eff_rip == 0xffffa00000009d68){
    else if(rip == sreq->keyhole_edit_ins_adr[1]){
        pte = m_regs->regs.rsi;
        std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
    }
    else{
        assert(0);
    }
    return pte;
}


/*-----Analyzer Begins here -----------------------------------------------------------------------------------------------------------*/
ulong ret_addr = 0;
ulong tdcs_ptr = 0;
ulong tdcs_va = 0;
int CAnalyze::onEndOfInsExec(){ //analysis at the end of each instruction
    
    if(m_regs->regs.rip == 0xffffa00000002b10){ //check_state_map_tdcs_and_lock
        tdcs_ptr = m_regs->regs.r9;
        ret_addr = *(ulong *)m_regs->regs.rsp;
        std::cout << "at check_state_map_tdcs_and_lock\nret addr: 0x" << ret_addr << std::endl;
    }

    if(m_regs->regs.rip == ret_addr){

        std::cout << "end of function\n";
        a_EFlagsMgr->PrintConstraint();
        tdcs_va = *(ulong *)tdcs_ptr;
        std::cout << "tdcs va: 0x" << tdcs_va << std::endl;
        ulong seed = getSeedFromMemory(tdcs_va + 0x80);
        m_VM->createSYMemObject(tdcs_va + 0x80, 8, 1, 1, seed , "attributes");
    }

    return 0;
}

int CAnalyze::onBeforeCIESIE(){

    return 0;
} 

int CAnalyze::onPathEnd(){
    std::cout << "path end ana\n";
    return 1;
}

int CAnalyze::analyztsHub(int anaPoint) { //analysis of interpreter's SE by analyzer goes through this hub
#ifndef _PROD_PERF
    std::cout << "at analyztsHub" << std::endl;
#endif
    switch(anaPoint){
        case ON_END_OF_INS_EXEC: {
            return CAnalyze::onEndOfInsExec();
        }   break;
        case ON_BFR_CIE_OR_SIE: {
            // return CAnalyze::onBeforeCIESIE();
            break;
        }
        case ON_PATH_END: {
            return CAnalyze::onPathEnd();
        }
        default:
            break;
    }
    return 0;
}

bool CAnalyze::beginAnalysis(ulong addr) { //Analysis start

    uint64_t scall_id;
    m_regs = (struct MacReg*)m_VM->getPTRegs();
    std::cout << "at beginAnalysis" << std::endl;

    std::cout << "rip:0x" << std::hex << m_regs->regs.rip << std::endl;

    if(sreq->is_td_call == 1){
        switch (sreq->tdx_call_number)
        {
        case TDG_MEM_PAGE_ATTR_RD: {
            std::cout << "TDG_MEM_PAGE_ATTR_RD\n";
            ulong total_ref_c_addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            ulong total_ref_c = *(ulong *)sreq->lp_khole_ref_adr.tot_ref_count_adr;
            std::cout << "total refs " << std::dec << total_ref_c << std::endl;
            m_VM->createSYMemObject(total_ref_c_addr, 8, 1, 1, total_ref_c, "tot_r");

#ifdef IN_PATH_EXPLORATION_MODE
            m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, m_regs->regs.rcx, "rcx");

            tdxmod_keyhole_state_t *khs = (tdxmod_keyhole_state_t *)sreq->khole_state_seam_va;
            std::string sym_hkid_pa_prefix = "pa_";
            std::string sym_ref_c_prefix = "r_";
            int idx = 0;
            while(idx < 64){

                // std::cout << "pa: 0x" << std::hex << khs->keyhole_array[idx].mapped_pa << "\t";
                // std::cout << "ref: " << khs->keyhole_array[idx].ref_count << std::endl;

                std::string sym_str = sym_hkid_pa_prefix + std::to_string(idx);
                const char* sym_hkid_pa = sym_str.c_str();
                m_VM->createSYMemObject((ulong)&khs->keyhole_array[idx].mapped_pa, 8, 1, 1, khs->keyhole_array[idx].mapped_pa, sym_hkid_pa);
                
                sym_str = sym_ref_c_prefix + std::to_string(idx);
                const char* sym_ref_ct = sym_str.c_str();
                m_VM->createSYMemObject((ulong)&khs->keyhole_array[idx].ref_count, 8, 1, 1, khs->keyhole_array[idx].ref_count, sym_ref_ct);
                
                idx++;
            }
#endif
        }   break;
        case TDG_MEM_PAGE_ATTR_WR: {
            std::cout << "TDG_MEM_PAGE_ATTR_WR\n";
            m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, m_regs->regs.rdx, "rdx");
#ifdef IN_MEMORY_TEST
            ulong total_ref_c_addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            ulong total_ref_c = *(ulong *)sreq->lp_khole_ref_adr.tot_ref_count_adr;
            std::cout << "total refs " << std::dec << total_ref_c << std::endl;
            m_VM->createSYMemObject(total_ref_c_addr, 8, 1, 1, total_ref_c, "tot_r");
#endif
        }   break;
        case TDG_MEM_PAGE_ACCEPT: {
            std::cout << "TDG_MEM_PAGE_ACCEPT\n";
            ulong total_ref_c_addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            ulong total_ref_c = *(ulong *)sreq->lp_khole_ref_adr.tot_ref_count_adr;
            std::cout << "total refs " << std::dec << total_ref_c << std::endl;
            m_VM->createSYMemObject(total_ref_c_addr, 8, 1, 1, total_ref_c, "tot_r");
        }   break;
        case TDG_MR_REPORT: 
            std::cout << "TDG_MR_REPORT\n";
            m_VM->createSYRegObject(x86_64::r8, 8, 1, 1, m_regs->regs.r8, "r8");
            break;
        case TDG_SYS_RD:
            std::cout << "TDG_SYS_RD\n";
            m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, m_regs->regs.rdx, "rdx");
            break;
        case TDG_SYS_RDALL:
            std::cout << "TDG_SYS_RDALL\n";
            m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, m_regs->regs.r8, "r8");
            break;
        case TDG_VM_RD:
            std::cout << "TDG_VM_RD\n";
            m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, m_regs->regs.rcx, "rcx");
            m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, m_regs->regs.rdx, "rdx");
            break;
        case TDG_VP_INVEPT:
            std::cout << "TDG_VP_INVEPT\n";
            m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, m_regs->regs.rcx, "rcx");
            break;
        default:
            break;
        }        
    }
    else {
        switch (sreq->tdx_call_number)
        {
        case TDH_SYS_INIT:
            std::cout << "TDH_SYS_INIT\n";
            m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, m_regs->regs.rcx, "rcx");
            break;
        case TDH_SYS_LP_INIT: {
            std::cout << "TDH_SYS_LP_INIT\n";
            //sym local lp init flag
            //gs + 296
            ulong lp_init_flag_addr = m_regs->gs_base + 280;
            uint8_t lp_init_flag = *(uint8_t *)lp_init_flag_addr;
            m_VM->createSYMemObject(lp_init_flag_addr, 1, 1, 1, lp_init_flag, "lp_init");

            //sym global sys_state
            //fs + 684
            ulong global_sys_state_adr = 0xffffa00300221076; //m_regs->fs_base + 684;
            uint8_t global_sys_state = *(uint8_t *)global_sys_state_adr;
            m_VM->createSYMemObject(global_sys_state_adr, 1, 1, 1, global_sys_state, "s_st");        
        }    break;
        case TDH_SYS_TDMR_INIT: {
            std::cout << "TDH_SYS_TDMR_INIT\n";
            //sym global num_of_tdmr_entries
            ulong n_tdmr_adr = 0xffffa0030022e100; //&tdx_global_data_ptr->num_of_tdmr_entries; 4bytes
            uint8_t n_tdmr = *(uint32_t *)n_tdmr_adr;
            m_VM->createSYMemObject(n_tdmr_adr, 1, 1, 1, n_tdmr, "n_tdmr");  
        }   break;
        case TDH_MNG_CREATE: {
            std::cout << "TDH_MNG_CREATE\n";
            m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, m_regs->regs.rdx, "rdx");

#ifdef IN_PATH_EXPLORATION_MODE
            //for path exp 
            //global_data->kot.entries[td_hkid].state
            // ulong kot_adr = 0xffffa00300221188; 
            // ulong kot = *(ulong *)kot_adr;
            // m_VM->createSYMemObject(kot_adr, 1, 1, 1, kot, "kot");   
            
            //may be tot khole ref count ?
            ulong total_ref_c_addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            ulong total_ref_c = *(ulong *)sreq->lp_khole_ref_adr.tot_ref_count_adr;
            std::cout << "total refs " << std::dec << total_ref_c << std::endl;
            m_VM->createSYMemObject(total_ref_c_addr, 8, 1, 1, total_ref_c, "tot_r");
#endif
        }   break;
        case TDH_SYS_CONFIG: {
            std::cout << "TDH_SYS_CONFIG\n";
            m_VM->createSYRegObject(x86_64::r8, 8, 1, 1, m_regs->regs.r8, "r8");
#ifdef IN_PATH_EXPLORATION_MODE
            //for path exp
            //tdx_global_data_ptr->global_state.sys_state
            ulong global_sys_state_adr = 0xffffa00300221076;
            uint8_t global_sys_state = *(uint8_t *)global_sys_state_adr;
            m_VM->createSYMemObject(global_sys_state_adr, 1, 1, 1, global_sys_state, "s_st");

            //tdx_global_data_ptr->num_of_init_lps
            ulong global_num_of_init_lps_adr = 0xffffa00300221030;
            uint32_t global_num_of_init_lps = *(uint32_t *)global_num_of_init_lps_adr;
            m_VM->createSYMemObject(global_num_of_init_lps_adr, 4, 1, 1, global_num_of_init_lps, "i_lps");

            //tdx_global_data_ptr->num_of_lps
            ulong global_num_of_lps_adr = 0xffffa00300221028;
            uint32_t global_num_of_lps = *(uint32_t *)global_num_of_lps_adr;
            m_VM->createSYMemObject(global_num_of_lps_adr, 4, 1, 1, global_num_of_lps, "n_lps");

            ulong total_ref_c_addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            ulong total_ref_c = *(ulong *)sreq->lp_khole_ref_adr.tot_ref_count_adr;
            std::cout << "total refs " << std::dec << total_ref_c << std::endl;
            m_VM->createSYMemObject(total_ref_c_addr, 8, 1, 1, total_ref_c, "tot_r");
#endif
        }   break;
        case TDH_SYS_KEY_CONFIG: {
            std::cout << "TDH_SYS_KEY_CONFIG\n";
            
            // 0xffffa00300221074; //&tdx_global_data_ptr->hkid; 2byte
            ulong global_hkid_adr = 0xffffa00300221074;
            uint32_t global_hkid = *(uint16_t *)global_hkid_adr;
            m_VM->createSYMemObject(global_hkid, 2, 1, 1, global_hkid_adr, "g_hkid");

            //tdx_global_data_ptr->global_state.sys_state
            ulong global_sys_state_adr = 0xffffa00300221076;
            uint8_t global_sys_state = *(uint8_t *)global_sys_state_adr;
            m_VM->createSYMemObject(global_sys_state_adr, 1, 1, 1, global_sys_state, "s_st");
        }   break;
        case TDH_SYS_INFO:
            std::cout << "TDH_SYS_INFO\n";
            m_VM->createSYRegObject(x86_64::r9, 8, 1, 1, m_regs->regs.r9, "r9");
            break;
        case TDH_VP_INIT:
            std::cout << "TDH_VP_INIT\n";
            m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, m_regs->regs.rdx, "rdx");
            break;
        case TDH_MEM_SEPT_ADD: {
            std::cout << "TDH_MEM_SEPT_ADD\n";
            
            ulong vpid_cap_adr = 0xffffa0030022e150; //&global_data->plt_common_config.ia32_vmx_ept_vpid_cap; // 8byte
            ulong vpid_cap = *(ulong *)vpid_cap_adr;
            m_VM->createSYMemObject(vpid_cap_adr, 8, 1, 1, vpid_cap, "vpid_cap");

            ulong total_ref_c_addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            ulong total_ref_c = *(ulong *)sreq->lp_khole_ref_adr.tot_ref_count_adr;
            std::cout << "total refs " << std::dec << total_ref_c << std::endl;
            m_VM->createSYMemObject(total_ref_c_addr, 8, 1, 1, total_ref_c, "tot_r");
            //sym lp key hole total ref
        }   break;  
        case TDH_VP_ENTER: {
            std::cout << "TDH_VP_ENTER\n";

            //sym local_data_ptr->vp_ctx.last_tdvpr_pa.raw
            ulong last_tdvpr_pa_adr = 0xffffa0030002017b; //&local_data_ptr->vp_ctx.last_tdvpr_pa.raw; //8byte
            ulong last_tdvpr_pa = *(ulong *)last_tdvpr_pa_adr;
            m_VM->createSYMemObject(last_tdvpr_pa_adr, 8, 1, 1, last_tdvpr_pa, "last_tdvpr");

            //sym global_data_ptr->plt_common_config.ia32_tsc_adjust
            ulong tsc_adj_adr = 0xffffa0030022e108; //&tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust; 8byte
            ulong tsc_adj = *(ulong *)tsc_adj_adr;
            m_VM->createSYMemObject(tsc_adj_adr, 8, 1, 1, tsc_adj, "tsc_adj");

        }   
        break; 
        case TDH_SERVTD_BIND:
            std::cout << "TDH_SERVTD_BIND\n";
            m_VM->createSYRegObject(x86_64::r8, 8, 1, 1, m_regs->regs.r8, "r8");
            m_VM->createSYRegObject(x86_64::r9, 8, 1, 1, m_regs->regs.r9, "r9");
            break;
        case TDH_SERVTD_PREBIND:
            std::cout << "TDH_SERVTD_BIND\n";
            m_VM->createSYRegObject(x86_64::r8, 8, 1, 1, m_regs->regs.r8, "r8");
            m_VM->createSYRegObject(x86_64::r9, 8, 1, 1, m_regs->regs.r9, "r9");
            break;
        default:
            break;
        }
    }

#ifndef IN_PATH_EXPLORATION_MODE
    setExecProfileSinglePath();
#else
    setExecProfileMultiPath();
#endif

    dispatch_count++;

    m_Thin->processFunction(addr);
    std::cout << "ending analsis at interpreter's analyzer function\n" << std::endl;

    return false;
}



























