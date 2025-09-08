#include <iostream>
#include <fstream>
#include "Expr.h"
#include "InstructionDecoder.h"
#include "EFlagsManager.h"
#include "HistoryTree.h"
#include "VMState.h"

#include "com.h"
#include "ExprUtils.h"
#include "Analyze.h"

extern struct servReq *sreq;

HistoryManager *g_hm = nullptr ;
class VMState;

using namespace std;
using namespace Dyninst;
using namespace InstructionAPI;
using namespace EXPR;

static const entryID stateChangingInstrList[] = {e_adc, e_add, e_cmp, e_cmpw, e_cmpxch, e_cmpxch8b, e_and, 
    e_bsf, e_bsr, e_bt, e_btc, e_btr, e_bts, e_dec, e_decl, e_div, e_idiv, e_imul, e_inc, e_neg, e_or, 
    e_popcnt, e_popf, e_popfq, e_popfd, e_rdrand, e_rol, e_rolb, e_ror, e_salc, e_sar, e_sarb, e_sbb, e_sbbl, 
    e_scas, e_scasb, e_scasd, e_scasw, e_shl_sal, e_shld, e_shr, e_shrb, e_shrd, e_sub, e_sysret, e_test, 
    e_tzcnt, e_xadd, e_xor, e_sahf
} ;

static int instrAttr[_entry_ids_max_] ;

bool EFlagsManager::ConcreteFlag (entryID instrID, bool bExecute) {

    FLAG_STAT fset = FLAG_SET, fclr = FLAG_CLEAR ;

    if (!isConditionalExecuteInstr(instrID)) 
        return false ;

    switch (instrID)
    {
        case e_jnb:
        case e_jnb_jae_j:
        case e_cmovnb:
        case e_setnb:
            // AE/NB/No Carry;		(CF=0)
            m_VM->setFlagBit(x86_64::cf, bExecute?fclr:fset) ;
            break ;

        case e_ja:
        case e_jnbe:
        case e_cmovnbe:
        case e_setnbe:
            // A/NBE; 			(CF=0 and ZF=0)
            if(bExecute) {
                m_VM->setFlagBit(x86_64::cf, fclr) ;
                m_VM->setFlagBit(x86_64::zf, fclr) ;
            }
            
            break ;

        case e_jbe:
        case e_cmovbe:
        case e_setbe:
            // BE/NA;			(CF=1 or ZF=1)
            // can't do anyting
            break ;
        
        case e_jb:
        case e_jb_jnaej_j:
        case e_cmovnae:
        case e_setb:
        case e_sbb:
            // B/NAE/Carry;		(CF=1)
            m_VM->setFlagBit(x86_64::cf, bExecute?fset:fclr) ;
            
            break ;
        
        case e_jge:
        case e_jnl:
        case e_cmovnl:
        case e_setnl:
            // GE/NL;			(SF=OF)
            // cannot do anything
            break ;

        
        case e_jnle:
        case e_jg:
        // case e_cmovnle:
        case e_setnle:
            // G/NLE;			(ZF=0 and SF=OF)
            if(bExecute) {
                  m_VM->setFlagBit(x86_64::zf, fclr) ;
            }
            break ;
        
        case e_jle:
        case e_cmovng:
        case e_setle:
            // LE/NG;			(ZF=1 or SF≠ OF)
            m_VM->setFlagBit(x86_64::zf, bExecute?fset:fclr) ;
            break ;
        
        case e_jl:
        case e_cmovnge:
        case e_setl:
            // L/NGE; 			(SF≠ OF)
            // cannot do anything
            break ;

        case e_je:
        case e_jz:
        case e_cmove:
        case e_setz:
            // E/Z/NE/NZ (zf)
            m_VM->setFlagBit(x86_64::zf, bExecute?fset:fclr) ;
            break ;

        case e_jne:
        case e_jnz:
        case e_cmovne:
        case e_setnz:
            // E/Z/NE/NZ (zf)
            m_VM->setFlagBit(x86_64::zf, bExecute?fclr:fset) ;
            break ;

        case e_jns:
        case e_cmovns:
        case e_setns:
            // S/NS (sf)
            m_VM->setFlagBit(x86_64::sf, bExecute?fclr:fset) ;
            break ;

        case e_js:
        case e_cmovs:
        case e_sets:
            // S/NS (sf)
            m_VM->setFlagBit(x86_64::sf, bExecute?fset:fclr) ;
            break ;

        case e_jno:
        case e_cmovno:
        case e_setno:
            // O/NO (of)
            m_VM->setFlagBit(x86_64::of, bExecute?fclr:fset) ;
            break ;

        case e_jo:
        case e_cmovo:
        case e_seto:
            m_VM->setFlagBit(x86_64::of, bExecute?fset:fclr) ;
            // O/NO (of)
            
            break ;

        case e_jrcxz:
        case e_jcxz_jec:
        case e_jp:
        case e_jnp:
        case e_cmovpe:
        case e_cmovpo:
        case e_setp:
        case e_setnp:
            assert(0);
            break ;   
        default:
            assert(0);
            break;
    }
    return true ;
}

bool EFlagsManager::SaveFlagChangingInstruction (FSInstrPtr &ptr) {
    m_LastInstr = ptr ;
    return true ;
}

bool EFlagsManager::SaveFlagChangingInstructionExpr (entryID instrID, KVExprPtr exprPtr) {
    if(isFlagChangingInstr(instrID) || isFlagSettingInstr(instrID)) {
        FLAG_STAT flag = FLAG_UNCERTAIN ;
        m_LastExpr = exprPtr ;
        m_VM->setFlagBit(x86_64::zf, flag) ;
        m_VM->setFlagBit(x86_64::cf, flag) ;
        m_VM->setFlagBit(x86_64::of, flag) ;
        m_VM->setFlagBit(x86_64::af, flag) ;
        m_VM->setFlagBit(x86_64::pf, flag) ;
        m_VM->setFlagBit(x86_64::sf, flag) ;
        return true ;
    } else
        return false ;
}

bool EFlagsManager::DoCreateConstraint(int exprID, bool bExecute) {
    
    extern KVExprPtr CreateExprByID(int id, KVExprPtr R, KVExprPtr M, KVExprPtr L, int size = 4, int offset = 0) ;
    KVExprPtr cstnt = NULL ;

    if (m_LastExpr)
        cstnt = (CreateExprByID(exprID, m_LastExpr, NULL, NULL, m_LastExpr->size, m_LastExpr->offset));
    else
        assert(0);

    if (!bExecute)
        cstnt.reset(new LNotExpr(cstnt, cstnt->size, cstnt->offset)) ;

    m_Constraint.insert(cstnt) ;

#ifdef _SYM_DEBUG_OUTPUT
    cstnt->print() ;
    std::cout << "\n" ;
    
    SolveConstraints ();
#endif
    return true ;
}

bool EFlagsManager::CreateConstraint(entryID instrID, bool bExecute) {
    
    int exprID = EXPR_UNDEFINED ;
    if (!isConditionalExecuteInstr(instrID)) 
        return false ;

    switch (instrID)
    {
        case e_jnb:
        case e_jnb_jae_j:
        case e_cmovnb:
        case e_setnb:
            // AE/NB/No Carry;		(CF=0)
            exprID = EXPR_Uge ;
            break ;

        case e_ja:
        case e_jnbe:
        case e_cmovnbe:
        case e_setnbe:
            // A/NBE; 			(CF=0 and ZF=0)
            exprID = EXPR_Ugt ;
            break ;

        case e_jbe:
        case e_cmovbe:
        case e_setbe:
            // BE/NA;			(CF=1 or ZF=1)
            exprID = EXPR_Ule ;
            break ;
        
        case e_jb:
        case e_jb_jnaej_j:
        case e_cmovnae:
        case e_setb:
            // B/NAE/Carry;		(CF=1)
            exprID = EXPR_Ult ;
            break ;
        
        case e_jge:
        case e_jnl:
        case e_cmovnl:
        case e_setnl:
            // GE/NL;			(SF=OF)
            exprID = EXPR_Sge ;
            break ;

        
        case e_jnle:
        case e_jg:
        // case e_cmovnle:
        case e_setnle:
            // G/NLE;			(ZF=0 and SF=OF)
            exprID = EXPR_Sgt ;
            break ;
        
        case e_jle:
        case e_cmovng:
        case e_setle:
            // LE/NG;			(ZF=1 or SF≠ OF)
            exprID = EXPR_Sle ;
            break ;
        
        case e_jl:
        case e_cmovnge:
        case e_setl:
            // L/NGE; 			(SF≠ OF)
            exprID = EXPR_Slt ;
            break ;

        case e_je:
        case e_jz:
        case e_cmove:
        case e_setz:
            exprID = EXPR_Equal ;
            break ;

        case e_jne:
        case e_jnz:
        case e_cmovne:
        case e_setnz:
            // E/Z/NE/NZ (zf)
            exprID = EXPR_Distinct ;
            break ;

        case e_jns:
        case e_cmovns:
        case e_setns:
            exprID = EXPR_NoSign ;
            break ;

        case e_js:
        case e_cmovs:
        case e_sets:
            // S/NS (sf)
            exprID = EXPR_Sign ;
            break ;

        case e_jno:
        case e_cmovno:
        case e_setno:
            exprID = EXPR_NoOverflow ;
            break ;

        case e_jo:
        case e_cmovo:
        case e_seto:
            // O/NO (of)
            exprID = EXPR_Overflow ;
            break ;

        case e_jrcxz:
        case e_jcxz_jec:
        case e_jp:
        case e_jnp:
        case e_cmovpe:
        case e_cmovpo:
        case e_setp:
        case e_setnp:
            assert(0);
            break ;   

        default:
            assert(0);
            break;
    }
    
    if(exprID != EXPR_UNDEFINED) {
        DoCreateConstraint (exprID, bExecute) ;
        return true ;
    } else
        return (false) ;
    
}

bool EFlagsManager::DependencyFlagConcreted(entryID instrID, bool &bExecute) {
    
    bool ret = false;
    switch (instrID)
    {
        case e_jnb:
        case e_jnb_jae_j:
        case e_cmovnb:
        case e_setnb:
            // AE/NB/No Carry;		(CF=0)
            ret = (m_VM->FlagBitDefinited(x86_64::cf)) ;
            if (ret) {
                FLAG_STAT cf ;
                assert(m_VM->getFlagBit(x86_64::cf, cf)) ;
                bExecute = (cf==FLAG_CLEAR) ? true : false ;
            }
            break ;

        case e_ja:
        case e_jnbe:
        case e_cmovnbe:
        case e_setnbe:
            // A/NBE; 			(CF=0 and ZF=0)
            ret = ((m_VM->FlagBitDefinited(x86_64::cf)) && (m_VM->FlagBitDefinited(x86_64::zf))) ;
            if (ret) {
                FLAG_STAT cf, zf ;
                assert(m_VM->getFlagBit(x86_64::cf, cf));
                assert(m_VM->getFlagBit(x86_64::zf, zf));

                bExecute = (cf==FLAG_CLEAR && zf==FLAG_CLEAR) ? true : false ;
            }
            break ;

        case e_jbe:
        case e_cmovbe:
        case e_setbe:
            // BE/NA;			(CF=1 or ZF=1)
            ret = ((m_VM->FlagBitDefinited(x86_64::cf)) && (m_VM->FlagBitDefinited(x86_64::zf))) ;
            if (ret) {
                FLAG_STAT cf, zf ;
                assert(m_VM->getFlagBit(x86_64::cf, cf));
                assert(m_VM->getFlagBit(x86_64::zf, zf));

                // bExecute = (cf==FLAG_SET && zf==FLAG_SET) ? true : false ;
                bExecute = (cf==FLAG_SET || zf==FLAG_SET) ? true : false ;
            }
            break ;
        
        case e_jb:
        case e_jb_jnaej_j:
        case e_cmovnae:
        case e_sbb:
        case e_setb:
        case e_adc:
            // B/NAE/Carry;		(CF=1)
            ret = (m_VM->FlagBitDefinited(x86_64::cf)) ;
            if (ret) {
                FLAG_STAT cf;
                assert(m_VM->getFlagBit(x86_64::cf, cf));

                bExecute = (cf==FLAG_SET) ? true : false ;
            }
            break ;
        
        case e_jge:
        case e_jnl:
        case e_cmovnl:
        case e_setnl:
            // GE/NL;			(SF=OF)
            ret = ((m_VM->FlagBitDefinited(x86_64::sf)) && (m_VM->FlagBitDefinited(x86_64::of))) ;
            if (ret) {
                FLAG_STAT sf, of ;
                assert(m_VM->getFlagBit(x86_64::sf, sf));
                assert(m_VM->getFlagBit(x86_64::of, of));

                bExecute = (sf == of) ? true : false ;
            }
            break ;

        case e_jnle:
        case e_jg:
        case e_setnle:
            // G/NLE;			(ZF=0 and SF=OF)
            ret = ((m_VM->FlagBitDefinited(x86_64::zf)) && 
                    (m_VM->FlagBitDefinited(x86_64::sf)) && 
                    (m_VM->FlagBitDefinited(x86_64::of))) ;
            if (ret) {
                FLAG_STAT zf, sf, of;
                assert(m_VM->getFlagBit(x86_64::zf, zf));
                assert(m_VM->getFlagBit(x86_64::sf, sf));
                assert(m_VM->getFlagBit(x86_64::of, of));

                bExecute = (zf==FLAG_CLEAR && sf==of) ? true : false ;
            }                    
            break ;
        
        case e_jle:
        case e_cmovng:
        case e_setle:
            // LE/NG;			(ZF=1 or SF≠ OF)
            ret = ((m_VM->FlagBitDefinited(x86_64::zf)) && 
                    (m_VM->FlagBitDefinited(x86_64::sf)) && 
                    (m_VM->FlagBitDefinited(x86_64::of))) ;
            if (ret) {
                FLAG_STAT zf, sf, of;
                assert(m_VM->getFlagBit(x86_64::zf, zf));
                assert(m_VM->getFlagBit(x86_64::sf, sf));
                assert(m_VM->getFlagBit(x86_64::of, of));
                bExecute = (zf==FLAG_SET || sf!=of) ? true : false ;
            } 
            break ;

        case e_jl:
        case e_cmovnge:
        case e_setl:
            // L/NGE; 			(SF≠ OF)
            ret = ((m_VM->FlagBitDefinited(x86_64::sf)) && (m_VM->FlagBitDefinited(x86_64::of))) ;
             if (ret) {
                FLAG_STAT sf, of ;
                assert(m_VM->getFlagBit(x86_64::sf, sf));
                assert(m_VM->getFlagBit(x86_64::of, of));

                bExecute = (sf != of) ? true : false ;
            }
            break ;   

        case e_je:
        case e_jz:
        case e_cmove:
        case e_setz:
            ret = (m_VM->FlagBitDefinited(x86_64::zf)) ;
            if (ret) {
                FLAG_STAT zf ;
                assert(m_VM->getFlagBit(x86_64::zf, zf));
 
                bExecute = (zf == FLAG_SET) ? true : false ;
            } 
            break ;

        case e_jne:
        case e_jnz:
        case e_cmovne:
        case e_setnz:
            // E/Z/NE/NZ (zf)
            ret = (m_VM->FlagBitDefinited(x86_64::zf)) ;
            if (ret) {
                FLAG_STAT zf ;
                assert(m_VM->getFlagBit(x86_64::zf, zf));
 
                bExecute = (zf == FLAG_CLEAR) ? true : false ;
            } 
            break ;

        case e_jns:
        case e_cmovns:
        case e_setns:
            ret = (m_VM->FlagBitDefinited(x86_64::sf)) ;
            if (ret) {
                FLAG_STAT sf ;
                assert(m_VM->getFlagBit(x86_64::sf, sf));
 
                bExecute = (sf == FLAG_CLEAR) ? true : false ;
            } 
            break ;    

        case e_js:
        case e_cmovs:
        case e_sets:
            // S/NS (sf)
            ret = (m_VM->FlagBitDefinited(x86_64::sf)) ;
            if (ret) {
                FLAG_STAT sf ;
                assert(m_VM->getFlagBit(x86_64::sf, sf));
 
                bExecute = (sf == FLAG_SET) ? true : false ;
            } 
            break ;

        case e_jno:
        case e_cmovno:
        case e_setno:
            ret = (m_VM->FlagBitDefinited(x86_64::of)) ;
            if (ret) {
                FLAG_STAT of ;
                assert(m_VM->getFlagBit(x86_64::of, of));
 
                bExecute = (of == FLAG_CLEAR) ? true : false ;
            }             
            break ;

        case e_jo:
        case e_cmovo:
        case e_seto:
            // O/NO (of)
            ret = (m_VM->FlagBitDefinited(x86_64::of)) ;
            if (ret) {
                FLAG_STAT of ;
                assert(m_VM->getFlagBit(x86_64::of, of));
 
                bExecute = (of == FLAG_SET) ? true : false ;
            }             
            break ;

        case e_jrcxz:
        case e_jcxz_jec:
        case e_jp:
        case e_jnp:
        case e_cmovpe:
        case e_cmovpo:
        case e_setp:
        case e_setnp:
            assert(0);
            break ;   

        default:
            assert(0);
            break;
    }
    return (ret) ;
}



// instructions only for set flags.
bool EFlagsManager::isFlagSettingInstr(entryID id){
    if (instrAttr[id] & FLAG_SETING_ATTR) {
        return true ;
    }
    return false;
}

// instructions which will change flags.
bool EFlagsManager::isFlagChangingInstr(entryID id){
    int i = 0;

    if(instrAttr[id] & FLAG_CHANGING_ATTR) {
        return true ;
    }
    return false;
}

// insturctions will depend on flags
bool EFlagsManager::isConditionalExecuteInstr(entryID id){
    if(instrAttr[id] & CONDITIONAL_EXEC_ATTR) {
        return true ;
    }
    return false;
}

void EFlagsManager::InitInstructionAttr()
{
    for (int i =0; i< sizeof(instrAttr)/sizeof(instrAttr[0]); i++){
        instrAttr[i] = 0 ;
        for (int j=0; j<sizeof(stateChangingInstrList)/sizeof(stateChangingInstrList[0]); j++) {
            if(i == stateChangingInstrList[j]) {
                instrAttr[i] |= FLAG_CHANGING_ATTR;
                break ;
            }
        }
        if (i == e_cmp ||i == e_cmpw || i == e_test || i == e_bt) {
            instrAttr[i] |= FLAG_SETING_ATTR ;
        }
        if((i >= e_jb && i <= e_jrcxz && i != e_jmp) || 
            (i>=e_cmovbe && i<=e_cmovs) ||
            (i>=e_setb && i<=e_setz)    ||
            (i==e_adc || i==e_sbb || i==e_sbbl) ) {
                instrAttr[i] |= CONDITIONAL_EXEC_ATTR ;
        }
    }
}

EFlagsManager::EFlagsManager(VMState *vm) {
    
    InitInstructionAttr () ;
    m_VM = vm;
    m_Constraint.clear();
    m_LastExpr = NULL ;
    m_LastInstr = NULL ;
    
    m_Z3Handler.reset(new Z3Handler());
    if (g_hm == nullptr)
        g_hm = new HistoryManager(0, 0) ;
};

bool EFlagsManager::PrintConstraint (void) {
    std::cout << "Current path constraint: \n";
    for(auto it : m_Constraint) {
        
        it->print() ;
        std::cout << "\n" ;

    }
    return true ;
}

bool EFlagsManager::SolveConstraints () {

    std::map<std::string, unsigned long long> ret_result;
    ret_result = m_Z3Handler->Z3SolveOne(m_Constraint); // now the [symbolic name, concrete value] map will be returned
// #ifdef _DEBUG_OUTPUT
    printf ("\nSolveConstraints result size: %lu \n", ret_result.size());
    for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
        std::cout << "symbol : " << it->first << "   value : " << it->second << std::endl;
    }
    last_solved_constraints = ret_result;
// #endif
    return true ;
}

bool EFlagsManager::SolveOneConstraint() {

    std::map<std::string, unsigned long long> ret_result;
    ret_result = m_Z3Handler->Z3SolveOne(one_constraint); // now the [symbolic name, concrete value] map will be returned
// #ifdef _DEBUG_OUTPUT
    printf ("\nSolveOneConstraint result size: %lu. \n", ret_result.size());
    for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
        std::cout << "symbol : " << it->first << "   value : " << it->second << std::endl;
    }
// #endif
    return true ;
}

bool EFlagsManager::SolveNegatedConstraints() {

    std::map<std::string, unsigned long long> ret_result;
    std::set<KVExprPtr> neg_path_constraints;
    KVExprPtr last_expr(nullptr), tmpexpr(nullptr);

    if (!m_Constraint.empty()) {
        auto first = *neg_path_constraints.begin();
        last_expr = first;

        for (auto it = std::next(neg_path_constraints.begin()); it != neg_path_constraints.end(); ++it) {
            KVExprPtr expr = *it;
            KVExprPtr tmpexpr(nullptr);
            tmpexpr.reset(new OrExpr(last_expr, expr));
            last_expr = tmpexpr;
        }
    }
    else{
        assert(0);
    }
    assert(last_expr);
    neg_path_constraints.insert(last_expr);
    ret_result = m_Z3Handler->Z3SolveOne(neg_path_constraints); // now the [symbolic name, concrete value] map will be returned
// #ifdef _DEBUG_OUTPUT
    printf ("result size: %lu. \n", ret_result.size());
    for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
        std::cout << "symbol : " << it->first << "   value : " << it->second << std::endl;
    }
// #endif
    return true ;
}


std::set<unsigned long> EFlagsManager::SolveConstraint(std::set<KVExprPtr> constraints, std::string s_name){

    std::map<std::string, unsigned long long> ret_result;
    std::set<unsigned long> result;
    std::set<KVExprPtr> path_constraint(m_Constraint);
    // std::string s_name = "gpa_B4_7";
    unsigned long s_val;

    int round = 0;
    // ret_result = m_Z3Handler->Z3SolveOne(path_constraint); // now the [symbolic name, concrete value] map will be returned
    // std::cout << "round: " << std::dec << round << " result size: " << ret_result.size() << std::endl;
    // assert(ret_result.size() > 0);
    // for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
    //     std::cout << "symbol : " << it->first << "   value : 0x" << std::hex << it->second << std::endl;
    //     if(it->first == s_name){
    //         s_val = it->second;
    //     }
    // }

    // VMState::SYMemObject *msym = m_VM->GetSymMemObject(s_name);
    VMState::SYRegObject *msym = m_VM->GetSymRegObject(s_name);
    assert(msym);

    while (true){
        
        ret_result.clear();
        ret_result = m_Z3Handler->Z3SolveOne(path_constraint); // now the [symbolic name, concrete value] map will be returned
        std::cout << "round: " << std::dec << round << " result size: " << ret_result.size() << std::endl;
        if(ret_result.size() == 0){
            break;
        }

        for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
            std::cout << "symbol : " << it->first << "   value :0x" << std::hex << it->second << std::endl;
            if(it->first == s_name){
                s_val = it->second;
            }
        }
        result.insert(s_val);
        //now create a new constraint
        // KVExprPtr n_expr = GetSymExpr(s_name);
        KVExprPtr c0(nullptr), e1(nullptr), e(nullptr);
        c0.reset(new ConstExpr(s_val, msym->size, 0));
        e1.reset(new SubExpr(msym->expr, c0));
        e.reset(new DistinctExpr(e1, msym->size, 0));

        std::cout << "adding a new constraint:";
        e->print();
        std::cout << std::endl;

        path_constraint.insert(e);

        // ret_result = m_Z3Handler->Z3SolveOne(path_constraint); // now the [symbolic name, concrete value] map will be returned
        // std::cout << "round: " << std::dec << round << " result size: " << ret_result.size() << std::endl;
        // for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
        //     std::cout << "symbol : " << it->first << "   value :0x " << std::hex << it->second << std::endl;
        //     if(it->first == s_name){
        //         s_val = it->second;
        //     }
        // }
        round++;
    }
    std::cout << "solved for all possible values....\n";

    return result;
}

uint64_t EFlagsManager::GetSymAddrConcreteBase(KVExprPtr exprPtr){

    ulong base_adr = 0;
    ulong const_val = 0;
    assert(exprPtr);

    if (ExprUtils::extractConstValues(exprPtr, const_val)) {
        std::cout << "symbolic address: concrete base_adr:0x" << std::hex << const_val << std::endl;
        base_adr = const_val;
    } else {
        std::cout << "Not a valid AddExpr in 'base + sym ofst format'\n";
    }
    return base_adr;
}

int ccount = 0;
extern ulong updated_sept_page_seam_va;
extern bool is_epte_defined;
extern std::map<ulong, ulong> sym_buf_bases;
extern struct ExecData *execData;

uint64_t EFlagsManager::ConcretizeExpression(KVExprPtr exprPtr, bool use_symbuf)
{
    uint64_t c_val = 0x0;
    uint64_t base_adr = 0;
    std::set<KVExprPtr> expression;
    ccount++;
    std::vector<VMState::SYMemObject*> symobjs;

    // std::cout << "Concretizing a symbolic expr, count :" << std::dec << ccount << std::endl;
    // std::cout << "Current path constraint : \n";
    // for(auto it : m_Constraint)
    // {
    //     if(it != nullptr){
    //         it->print();
    //         std::cout << "\n";
    //     }
    // }
    // std::cout << "\n";

    assert(exprPtr);

    // if(!use_seed){
    //     ulong conc_val;
    //     std::map<std::string, unsigned long long> ret_result;
    
    //     std::cout << "use seed " << (int)use_seed << std::endl;
    //     /*as of now, if the use seed is false, we only expect a single symbol for simplicity*/
    //     assert((m_VM->m_SYRegObjects.size() == 1) || (m_VM->m_SYMemObjects.size() == 1));
        
    //     //first try solving the path constraint
    //     ret_result = m_Z3Handler->Z3SolveOne(m_Constraint); // now the [symbolic name, concrete value] map will be returned
    //     printf ("result size: %d. \n", ret_result.size());
    //     assert(ret_result.size() == 1);
    //     std::cout << "path constraint, solved" << std::endl;
        
    //     for (auto it = ret_result.begin(); it != ret_result.end(); it ++){
    //         std::cout << "symbol : " << it->first << "   value : " << it->second << std::endl;
    //         conc_val = it->second;
    //     }
        
    //     if(m_VM->m_SYRegObjects.size() == 1){
    //         for (auto it : m_VM->m_SYRegObjects){
    //             it.second->i64 = conc_val;
    //             symobjs.push_back((VMState::SYMemObject*)it.second);
    //         }
    //     }else if(m_VM->m_SYMemObjects.size() == 1){
    //         for (auto it : m_VM->m_SYMemObjects) {
    //             it.second->i64 = conc_val;
    //             symobjs.push_back(it.second);
    //         }
    //     }
    //     else{
    //         assert(0);
    //     }

    //     expression.insert(exprPtr);
    //     c_val = m_Z3Handler->Z3SolveConcritizeToConstant(symobjs, expression);
    //     std::cout << "concrete_val: 0x" << std::hex << c_val << std::endl;

    //     // assert(0);
    // }


    if (exprPtr)
    {
        for (auto it : m_VM->m_SYMemObjects)
        {
            symobjs.push_back(it.second);
            //print symbols, and seed values 
            // std::cout << "name :" << it.second->name << " ,hasseed : " << it.second->has_seed  << std::endl;
            // switch(it.second->size)
            // {
            //     case 1:
            //         std::cout << "val: " << it.second->i8 << std::endl;
            //         break;
            //     case 4:
            //         std::cout << "val: " << it.second->i32 << std::endl;
            //         break;
            //     case 8:
            //         std::cout << "val: " << it.second->i64 << std::endl;
            //         break;
            // }
        }

        //The following fix to be improved
        //start
        //proper support should be added to pass register symbol objects to z3
        for (auto it : m_VM->m_SYRegObjects){
            symobjs.push_back((VMState::SYMemObject*)it.second);
            //print symbols, and seed values 
            // std::cout << "name :" << it.second->name << " ,hasseed : " << it.second->has_seed  << std::endl;
            // switch(it.second->size)
            // {
            //     case 1:
            //         std::cout << std::hex << "val: " << it.second->i8 << std::endl;
            //         break;
            //     case 4:
            //         std::cout <<  std::hex << "val: " << it.second->i32 << std::endl;
            //         break;
            //     case 8:
            //         std::cout << std::hex << "val: " << it.second->i64 << std::endl;
            //         break;
            // }
        }
        //end

        expression.insert(exprPtr);


        /*std::cout << "constraints : \n";
        for(auto it : constraints)
        {
            it->print();
            std::cout << "\n";
        }*/
        c_val = m_Z3Handler->Z3SolveConcritizeToConstant(symobjs, expression);
        
    }
    else
    {
        assert(0);
    }

    // if(use_symbuf){

    //     ulong byte_offset = c_val % 0x8;
    //     base_adr = GetSymAddrConcreteBase(exprPtr);

    //     if((base_adr >= sreq->mod_code_rgn_start) && (base_adr < sreq->mod_stack_rgn_start)){
    //         std::cout << "module lib symbol access, deduced sym buf adr: 0x" << c_val << std::endl;
    //         sym_buf_bases.insert({base_adr, c_val});
    //         c_val = base_adr;
    //     }
            
    //     auto it = sym_buf_bases.find(base_adr);
    //     if(!(it == sym_buf_bases.end())){
    //         c_val = base_adr + byte_offset;
    //         // std::cout << "deduced sym buf adr: 0x" << c_val << std::endl;
    //     }


    //     // if((c_val >= sreq->khole_start) && (c_val < (sreq->khole_start + sreq->khole_size)) && is_epte_defined){
    //     //         // ulong byte_offset = c_val % 0x8;
    //     //         assert(updated_sept_page_seam_va != 0);
    //     //         c_val = updated_sept_page_seam_va + byte_offset;
    //     //         // c_val = (ulong)sym_buffer + 8 + byte_offset;
    //     //         std::cout << "using sym buf: 0x" << c_val << std::endl;
    //     // }
    //     // else if((c_val >= 0xffffa00000000000) && (c_val < 0xffffa00100000000)){

    //     // }
    // }

    /*for analyzer's use*/
    if(execData != NULL){
        execData->last_conc_exprptr = exprPtr;
        execData->last_conc_expr_val = c_val;
        execData->last_conc_ins_count = execData->insn_count;
    }

    return c_val;
}

// bool EFlagsManager::EvalCondition(entryID insnID)
// {
//     bool bExecute = false;

//     std::set<KVExprPtr> constraints;
//     KVExprPtr exprPtr = GetCondition(insnID);
//     if (exprPtr)
//     {
//         std::vector<VMState::SymObject*> symobjs;
//         for (auto it : m_VM->m_SymObjects)
//         {
//             symobjs.push_back(it.second);
            
//              //print symbols, and seed values 
//             std::cout << "name :" << it.second->name << " ,hasseed : " << it.second->has_seed;
//             std::cout << " ,type: " << ((it.second->sym_type == SYM_TYPE_REG) ? "reg" : "mem")  << std::endl;
//             switch(it.second->size)
//             {
//                 case 4:
//                     std::cout << "sz 4, val: " << it.second->i32 << std::endl;
//                     break;
//                 case 8:
//                     std::cout << "sz 8, val: " << it.second->i64 << std::endl;
//                     break;
//             }
            
//         }
        
//         constraints.insert(exprPtr);
        
//         std::cout << "constraints : \n";
//         for(auto it : constraints)
//         {
//             it->print();
//             std::cout << "\n";
//         }

//         bExecute = m_Z3Handler->Z3SolveConcritize(symobjs, constraints);
// #ifdef _DEBUG_LOG_L0
//         std::cout << "Symbolic branch, resolved to be : " << bExecute << std::endl; 
// #endif

// #ifdef DEBUG_LOG
//         std::cout << "----------bExecute: " << bExecute << std::endl; 
//         exprPtr->print() ;
//         std::cout << "\n" ;
// #endif

//         if (!bExecute)
//             exprPtr.reset(new LNotExpr(exprPtr, exprPtr->size, exprPtr->offset));
        

// #ifdef _DEBUG_OUTPUT 
//         std::cout << "----------bExecute: " << bExecute << std::endl; 
//         exprPtr->print() ;
//         std::cout << "\n" ;
// #endif

//         m_Constraint.insert(exprPtr) ;

// #ifdef _SYM_DEBUG_OUTPUT
//         // exprPtr->print() ;
//         // std::cout << "\n" ;
// #endif
//     }
//     else
//     {
//         std::cout << "Get Expr for conditional insn failed! " << std::endl;
//         assert(false);
//     }
//     return bExecute;
// }


bool EFlagsManager::EvalCondition(entryID insnID)
{
    bool bExecute = false;

    std::set<KVExprPtr> constraints;
    KVExprPtr exprPtr = GetCondition(insnID);
    std::cout << "EvalCondition\n";
    if (exprPtr)
    {
        // std::cout << "EvalCondition2\n";
        std::vector<VMState::SYMemObject*> symobjs;
        for (auto it : m_VM->m_SYMemObjects)
        {
            symobjs.push_back(it.second);
            
            //  //print symbols, and seed values 
            // std::cout << "m sym name :" << it.second->name << " ,hasseed : " << it.second->has_seed  << std::endl;
            // switch(it.second->size)
            // {
            //     case 4:
            //         std::cout << "val32: " << it.second->i32 << std::endl;
            //         break;
            //     case 8:
            //         std::cout << "val64: " << it.second->i64 << std::endl;
            //         break;
            // }
            
        }
        
        for (auto it : m_VM->m_SYRegObjects){
            symobjs.push_back((VMState::SYMemObject*)it.second);
            //print symbols, and seed values 
            // std::cout << "r sym name :" << it.second->name << " ,hasseed : " << it.second->has_seed  << std::endl;
            // switch(it.second->size)
            // {
            //     case 4:
            //         std::cout <<  std::hex << "val32: " << it.second->i32 << std::endl;
            //         break;
            //     case 8:
            //         std::cout << std::hex << "val64: " << it.second->i64 << std::endl;
            //         break;
            // }
        }

        
        constraints.insert(exprPtr);
        
        // std::cout << "debug_log constraints : \n";
        // for(auto it : constraints)
        // {
        //     std::cout << "debug_log :";
        //     it->print();
        //     std::cout << "\n";
        // }
        bExecute = m_Z3Handler->Z3SolveConcritize(symobjs, constraints);
#ifdef _DEBUG_LOG_L0
        std::cout << "Symbolic branch, resolved to be : " << bExecute << std::endl; 
#endif

#ifdef DEBUG_LOG
        std::cout << "----------bExecute: " << bExecute << std::endl; 
        exprPtr->print() ;
        std::cout << "\n" ;
#endif

        if (!bExecute)
            exprPtr.reset(new LNotExpr(exprPtr, exprPtr->size, exprPtr->offset));
        

#ifdef _DEBUG_OUTPUT 
        std::cout << "----------bExecute: " << bExecute << std::endl; 
        exprPtr->print() ;
        std::cout << "\n" ;
#endif
        std::cout << "----------bExecute: " << bExecute << std::endl; 
        exprPtr->print() ;
        std::cout << "\n" ;
        
        m_Constraint.insert(exprPtr) ;

#ifdef _SYM_DEBUG_OUTPUT
        // exprPtr->print() ;
        // std::cout << "\n" ;
#endif
    }
    else
    {
        std::cout << "Get Expr for conditional insn failed! " << std::endl;
        assert(false);
    }
    return bExecute;
}

KVExprPtr EFlagsManager::DoGetCondition(int exprID) {
    
    extern KVExprPtr CreateExprByID(int id, KVExprPtr R, KVExprPtr M, KVExprPtr L, int size = 4, int offset = 0) ;
    KVExprPtr cstnt = NULL ;

    if (m_LastExpr) {
        cstnt = (CreateExprByID(exprID, m_LastExpr, NULL, NULL, m_LastExpr->size, m_LastExpr->offset));
        
        //this is  to fix the issue of passing the wrong expression for jle followed by test(creates an and expression)
        //it is possible that the same issue exists if the flag updating instruction is xor and or rtc.: check and FIX !!!
        /*if(m_LastExpr->exprID==EXPR_And) { 
            cstnt.reset (new EqualExpr(m_LastExpr, m_LastExpr->size, m_LastExpr->offset) );
        }
        else {
            cstnt = (CreateExprByID(exprID, m_LastExpr, NULL, NULL, m_LastExpr->size, m_LastExpr->offset));
        }*/
    }
    else
        assert(0);

    return cstnt ;
}

KVExprPtr EFlagsManager::GetCondition(entryID instrID) {
    
    int exprID = EXPR_UNDEFINED ;
    if (!isConditionalExecuteInstr(instrID)) 
        return nullptr;

    switch (instrID)
    {
        case e_jnb:
        case e_jnb_jae_j:
        case e_cmovnb:
        case e_setnb:
            // AE/NB/No Carry;		(CF=0)
            exprID = EXPR_Uge ;
            break ;

        case e_ja:
        case e_jnbe:
        case e_cmovnbe:
        case e_setnbe:
            // A/NBE; 			(CF=0 and ZF=0)
            exprID = EXPR_Ugt ;
            break ;

        case e_jbe:
        case e_cmovbe:
        case e_setbe:
            // BE/NA;			(CF=1 or ZF=1)
            exprID = EXPR_Ule ;
            break ;
        
        case e_jb:
        case e_jb_jnaej_j:
        case e_cmovnae:
        case e_setb:
        // case e_sbb:
            // B/NAE/Carry;		(CF=1)
            exprID = EXPR_Ult ;
            break ;
        
        case e_jge:
        case e_jnl:
        case e_cmovnl:
        case e_setnl:
            // GE/NL;			(SF=OF)
            exprID = EXPR_Sge ;
            break ;

        
        case e_jnle:
        case e_jg:
        // case e_cmovnle:
        case e_setnle:
            // G/NLE;			(ZF=0 and SF=OF)
            exprID = EXPR_Sgt ;
            break ;
        
        case e_jle:
        case e_cmovng:
        case e_setle:
            // LE/NG;			(ZF=1 or SF≠ OF)
            exprID = EXPR_Sle ;
            break ;
        
        case e_jl:
        case e_cmovnge:
        case e_setl:
            // L/NGE; 			(SF≠ OF)
            exprID = EXPR_Slt ;
            break ;

        case e_je:
        case e_jz:
        case e_cmove:
        case e_setz:
            exprID = EXPR_Equal ;
            break ;

        case e_jne:
        case e_jnz:
        case e_cmovne:
        case e_setnz:
            // E/Z/NE/NZ (zf)
            exprID = EXPR_Distinct ;
            break ;

        case e_jns:
        case e_cmovns:
        case e_setns:
            exprID = EXPR_NoSign ;
            break ;

        case e_js:
        case e_cmovs:
        case e_sets:
            // S/NS (sf)
            exprID = EXPR_Sign ;
            break ;

        case e_jno:
        case e_cmovno:
        case e_setno:
            exprID = EXPR_NoOverflow ;
            break ;

        case e_jo:
        case e_cmovo:
        case e_seto:
            // O/NO (of)
            exprID = EXPR_Overflow ;
            break ;

        case e_jrcxz:
        case e_jcxz_jec:
        case e_jp:
        case e_jnp:
        case e_cmovpe:
        case e_cmovpo:
        case e_setp:
        case e_setnp:
            assert(0);
            break ;   

        default:
            assert(0);
            break;
    }
    
    if(exprID != EXPR_UNDEFINED) {
        return DoGetCondition (exprID) ;
    } else
        return nullptr;
    
}


uint64_t EFlagsManager::EvalCondition(entryID insnID, uint64_t addr, uint64_t b1, uint64_t b2) {
    
    uint64_t uRet = g_hm->getExecAddress(addr, b1, b2) ;
    bool bExec = ((uRet==b1) || (uRet==1)); 	// true : left(true) is selected, or left is loop
						// false : right(false) is selected, or right is loop

    /*if uRet is 0 or 1, it means we wncountered a loop. If we want to go ahead with looping, keep the below.
    Sometimes, we may encounter a looong loops. In such cases we can comment the following to stop the current path
    when a loop is encountered.*/
    if(uRet == 1)
        uRet = b1;
    if(uRet == 0)
        uRet = b2;


    // std::cout << "uRet1: " << uRet << std::endl;
    if (uRet != -1) {   //if not an error, check which scenarions are these
        KVExprPtr exprPtr = GetCondition(insnID);
        if (!bExec) { 
            exprPtr.reset(new LNotExpr(exprPtr, exprPtr->size, exprPtr->offset)) ;
        }
        m_Constraint.insert(exprPtr) ;
        last_constraint = exprPtr;
        
        // std::cout << "New_constraint:";
        // exprPtr->print();
        // std::cout << std::endl;
        // std::cout << "constraint check: " << std::endl;
        if (!m_Z3Handler->Z3ConstraintChecking(m_Constraint)) { //check if the current condition for the path to  be taken is consistent with the path constriant

            // std::cout << "\nImpossible branch, selected branch: " 
            //             << ((uRet == b1) ? b1 : ((uRet == b2) ? b2 : (uint64_t)-1)) 
            //             << ((uRet == b1) ? " TRUE_BRANCH" : ((uRet == b2) ? " FALSE_BRANCH" : "ERROR")) 
            //             << std::endl;
            // std::cout << "Last_constraint:";
            // exprPtr->print();
            // std::cout << std::endl;
            uRet = -1 ;
            // std::cout << "uRet2: " << uRet << std::endl;
        }
    }
    return uRet ;
}