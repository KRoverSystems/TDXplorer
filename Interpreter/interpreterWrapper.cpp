#include "centralhub.h"
#include "interpreterWrapper.h"
#include "CPURegState.h"

extern "C" {

        // struct MacReg* get_m_regs(){
        //     return new struct MacReg;
        // }

        ExecState* newExecState() {
            unsigned long adds, adde;
            adds = 0x0;
            adde = 0xfffffffffffff000;
            return new ExecState(adds, adde);
        }

        void do_SynRegsFromNative(ExecState *e, struct MacReg *mreg){
            e->SynRegsFromNative(mreg);
        }

        void do_SynRegsToNative(ExecState *e, struct MacReg *mreg){
            e->SynRegsToNative(mreg);
        }

        int do_dispatch(ExecState *e, unsigned long adr) {
            if(!e->processAt(adr)){
                return 0;
            } 
            return 1;
        }


}