#ifndef __INTERPRETERWRAPPER_H
#define __INTERPRETERWRAPPER_H

#include "CPURegState.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ExecState ExecState;

ExecState* newExecState();
void do_SynRegsFromNative(ExecState *e, struct MacReg *mreg);
void do_SynRegsToNative(ExecState *e, struct MacReg *mreg);
int do_dispatch(ExecState *e, unsigned long adr);

#ifdef __cplusplus
}
#endif
#endif