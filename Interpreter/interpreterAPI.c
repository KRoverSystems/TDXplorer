#include <stdio.h>
#include "interpreterAPI.h"
#include "CPURegState.h"
// #include "../simTDX/include/common.h"
// #include "../simTDX/include/defs.h"
// #include "../simTDX/include/x64bin.h"
#include "interpreterWrapper.h"
#include "common.h"
#include "defs.h"
#include "x64bin.h"
#include "common_idata.h"

struct MacReg cpu_state;
extern struct comArea *com;
struct vm *vm;
unsigned long *targ_rsp_adr;
struct iData *tdx_sp_ins;
struct servReq *sreq;
struct ExecState *estate;

/*should only be used for GPRs other than rip, rsp, r15 and rflags
This macro does not work for above 4 registers.
rip, and rflags are saved on to interrupt stack by HW*/
ulong get_target_reg(REGS_64 reg){
    return (*(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - com->int3_stack_offsets[reg]));
}

/*should only be used for GPRs other than rip, rsp, r15 and rflags
This macro does not work for above 4 registers.
rip, and rflags are saved on to interrupt stack by HW*/
ulong set_target_reg(REGS_64 reg, ulong val){
    *(uint64_t *)(vm->mem + SEAM_AGENT_STACK_PA - com->int3_stack_offsets[reg]) = val;
}

void native_to_SE_ctx_switch()
{
    
    uint64_t *targ_rsp_now;

    cpu_state.regs.r8       = get_target_reg(R8); 
    cpu_state.regs.r9       = get_target_reg(R9); 
    cpu_state.regs.r10      = get_target_reg(R10);  
    cpu_state.regs.r11      = get_target_reg(R11); 
    cpu_state.regs.r12      = get_target_reg(R12); 
    cpu_state.regs.r13      = get_target_reg(R13); 
    cpu_state.regs.r14      = get_target_reg(R14); 
    cpu_state.regs.rax      = get_target_reg(RAX); 
    cpu_state.regs.rbx      = get_target_reg(RBX); 
    cpu_state.regs.rcx      = get_target_reg(RCX); 
    cpu_state.regs.rdx      = get_target_reg(RDX); 
    cpu_state.regs.rsi      = get_target_reg(RSI); 
    cpu_state.regs.rdi      = get_target_reg(RDI); 
    cpu_state.regs.rbp      = get_target_reg(RBP);

    targ_rsp_now            = (uint64_t *)(*targ_rsp_adr);
    cpu_state.regs.rsp      = targ_rsp_now[4];
    cpu_state.regs.rip      = targ_rsp_now[1];
    cpu_state.regs.r15      = targ_rsp_now[0];
    cpu_state.regs.eflags   = targ_rsp_now[3];
    
    // SELOG("cpu_state.regs.rsp: %lx\n", cpu_state.regs.rsp);
    // SELOG("cpu_state.regs.rip: %lx\n", cpu_state.regs.rip);
    // SELOG("cpu_state.regs.r15: %lx\n", cpu_state.regs.r15);
    // SELOG("cpu_state.regs.eflags: %lx\n", cpu_state.regs.eflags);

    if(com->current_sw == SEAM_SW_TDXMODULE) {
        cpu_state.fs_base       = com->tdxmod_state.fsbase;
        cpu_state.gs_base       = com->tdxmod_state.gsbase;
        // SELOG("cpu_state.gs: %lx\n", cpu_state.gs_base);

        // cpu_state.fs_base       = com->vmcs[com->current_lp].fsbase;
        // cpu_state.gs_base       = com->vmcs[com->current_lp].gsbase;
    }
    else {
        cpu_state.fs_base       = com->pseamldr_state.fsbase;
        cpu_state.gs_base       = com->pseamldr_state.gsbase;
    }
}

void SE_to_native_ctx_switch()
{
    uint64_t *targ_rsp_now;

    set_target_reg(R8, cpu_state.regs.r8); 
    set_target_reg(R9, cpu_state.regs.r9);
    set_target_reg(R10, cpu_state.regs.r10); 
    set_target_reg(R11, cpu_state.regs.r11);
    set_target_reg(R12, cpu_state.regs.r12);
    set_target_reg(R13, cpu_state.regs.r13);
    set_target_reg(R14, cpu_state.regs.r14);
    set_target_reg(RAX, cpu_state.regs.rax);
    set_target_reg(RBX, cpu_state.regs.rbx);
    set_target_reg(RCX, cpu_state.regs.rcx);
    set_target_reg(RDX, cpu_state.regs.rdx);
    set_target_reg(RSI, cpu_state.regs.rsi);
    set_target_reg(RDI, cpu_state.regs.rdi);
    set_target_reg(RBP, cpu_state.regs.rbp);

    targ_rsp_now    = (uint64_t *)(*targ_rsp_adr);
    targ_rsp_now[4] = cpu_state.regs.rsp;
    targ_rsp_now[1] = cpu_state.regs.rip;
    targ_rsp_now[0] = cpu_state.regs.r15;
    targ_rsp_now[3] = cpu_state.regs.eflags;

    return;
}

void dispatch_nie(){

    do_SynRegsToNative(estate, &cpu_state);
    SE_to_native_ctx_switch();
    // SELOG("rdispatching to NIE\n");
    com->se.target_owner = TARGET_OWNER_S_AGENT;
    asm volatile ("mfence; \n");
    while(com->se.target_owner == TARGET_OWNER_S_AGENT){
    }

    if(com->se.target_owner == TARGET_OWNER_INTERPRETER){
        // SELOG("--------------------------exec back from NIE at seam\n");
        native_to_SE_ctx_switch();
        do_SynRegsFromNative(estate, &cpu_state);
        return;
    }
    SELOG("--------------------------ERR\n");

}

int interpreterStart() {
    int count = 0;

    SELOG("##################### at interpreterStart \n");
    sreq = (struct servReq *)&com->sreq; /*to com between Interpreter and seam agent*/

    targ_rsp_adr = (ulong *)(vm->mem + SEAM_AGENT_STACK_PA - 0x8);
    // SELOG("target_rsp_after_interrupt:%lx\n", (ulong)targ_rsp_adr);
    tdx_sp_ins = (struct iData *)com->tdx_ins;
    // printf("com->tdx_ins: %lx\n", (ulong)&com->tdx_ins);
    estate = newExecState();
    // SELOG("owner:%d\n", com->se.target_owner);

    while(true){

        while(com->se.target_owner == TARGET_OWNER_S_AGENT){
        }
        
        if(com->se.target_owner == TARGET_OWNER_INTERPRETER){
            count++;
            LOG("\n");
            SELOG("--------------------------exec request received from seam\n");

            native_to_SE_ctx_switch();
            do_SynRegsFromNative(estate, &cpu_state);

            if(do_dispatch(estate, 0) == 0){
                com->sreq.terminate = 1;
                asm volatile ("mfence; \n");
                return 0; /*end of SE, now return to Monitor*/
            }
            
            do_SynRegsToNative(estate, &cpu_state);
            SE_to_native_ctx_switch();
            
            SELOG("returning control to seam\n");
            com->se.target_owner = TARGET_OWNER_S_AGENT;

        }

        // if(count > 300)
        //     break;
    }

return 0;
}

