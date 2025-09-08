#ifndef _SYM_EXEC_H__
#define _SYM_EXEC_H__

#include <linux/types.h>
#include <iostream>
#include <memory>
#include <vector>
#include "VMState.h"

struct OprndInfo;
class SymInfoDB;
class VMState;
class EFlagsManager;

typedef union {
    struct
    {
        uint64_t
            cf         : 1,
            reserved_0 : 1, // must be 1
            pf         : 1,
            reserved_1 : 1, // must be 0
            af         : 1,
            reserved_2 : 1, // must be 0
            zf         : 1,
            sf         : 1,
            tf         : 1,
            ief        : 1,
            df         : 1,
            of         : 1,
            iopl       : 2,
            nt         : 1,
            reserved_3 : 1, // must be 0
            rf         : 1,
            vm         : 1,
            ac         : 1,
            vif        : 1,
            vip        : 1,
            id         : 1,
            reserved_4 : 42; // must be 0
    };
    uint64_t raw;
} ia32_rflags_t;

namespace Dyninst::InstructionAPI {
class Instruction;
}

class SymExecutor {
   protected:
    std::vector<InstrInfoPtr> m_IOIs;
    bool m_RIPUpdated;  // Is RIP already updated in run()?

   public:
    SymExecutor() : m_IOIs(){};
    ~SymExecutor(){};
    
    bool pushInstr(InstrInfoPtr &ptr);
    bool run(VMState *cs);
    bool _run_prologue(void);
    bool _run_postlogue(void);

    bool parseOperands(VMState *vm, InstrInfo *info, bool isSymList);
    ulong isUsingFSGS(VMState* vm, DAPIInstrPtr &I);
    ulong getSegRegVal(VMState* vm, DAPIInstrPtr& I);

    bool _parseOperand_XX(VMState *vm, DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _parseOperand_RX(VMState *vm, DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _parseOperand_XW(VMState *vm, DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _parseOperand_RW(VMState *vm, DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool maySymbolicRegister(VMState *vm, uint ID) ;
    bool setReadRegs(VMState *vm, DAPIInstr *I) ;
    bool setReadRegs(VMState *vm, DAPIInstrPtr &I) ;

    bool process_jmp(VMState *vm, InstrInfoPtr &infoptr);
    bool process_call(VMState *vm, InstrInfoPtr &infoptr);
    bool process_jcc(VMState *vm, InstrInfoPtr &infoptr);
    bool process_add(VMState *vm, InstrInfoPtr &infoptr);
    bool process_lea(VMState *vm, InstrInfoPtr &infoptr);
    bool process_mov(VMState *vm, InstrInfoPtr &infoptr);
    bool process_mov_rep(VMState *vm, InstrInfoPtr &infoptr);
    bool process_test(VMState *vm, InstrInfoPtr &infoptr);
    bool process_cmovxx(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_cmp(VMState *vm, InstrInfoPtr &infoptr);
    bool process_sub(VMState *vm, InstrInfoPtr &infoptr);
    bool process_jxx(VMState *vm, InstrInfoPtr &infoptr);
    bool process_and(VMState *vm, InstrInfoPtr &infoptr);
    bool process_or(VMState *vm, InstrInfoPtr &infoptr);
    bool process_xor(VMState *vm, InstrInfoPtr &infoptr);
    bool process_shl_sal(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_shr(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_shrd(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_sar(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_idiv(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_mul(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_not(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_neg(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_pop(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_push(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_xchg(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_movsx(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_movzx(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_cdq(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_cbw(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_set(VMState *vm, InstrInfoPtr &infoptr) ;
    bool process_sbb(VMState *vm, InstrInfoPtr &infoptr);
    bool process_sidt(VMState *vm, InstrInfoPtr &infoptr);
    bool process_dec(VMState *vm, InstrInfoPtr &infoptr);
    bool process_xadd(VMState *vm, InstrInfoPtr &infoptr);
    bool process_div(VMState *vm, InstrInfoPtr &infoptr);
    bool process_bswap(VMState *vm, InstrInfoPtr &infoptr);
    bool process_leave(VMState *vm, InstrInfoPtr &infoptr);
    bool process_bsr(VMState *vm, InstrInfoPtr &infoptr);
    bool process_bt(VMState *vm, InstrInfoPtr &infoptr);
    bool process_rotate(VMState *vm, InstrInfoPtr &infoptr);
    bool process_stos (VMState *vm, InstrInfoPtr &infoptr)  ;
    bool process_movs (VMState *vm, InstrInfoPtr &infoptr)  ;
    bool process_bts(VMState *vm, InstrInfoPtr &infoptr);
    bool process_btr(VMState *vm, InstrInfoPtr &infoptr);
    bool process_adc(VMState *vm, InstrInfoPtr &infoptr);

    ia32_rflags_t calculate_eflags_cmp(int value1, int value2, int size);
    ia32_rflags_t calculate_eflags_add(int value1, int value2, int size);
    ia32_rflags_t calculate_eflags_test(int value1, int value2, int size);

    bool set_concrete_eflags(VMState *vm, ulong eflags);
    bool calculateBinaryFunction (Dyninst::InstructionAPI::BinaryFunction* bf, KVExprPtr &exprPtr, VMState* vm) ;

    bool Print_Inst(VMState *vm, InstrInfoPtr &infoptr, const char* cstr) ;
};


#endif  // !_SYM_EXEC_H__
