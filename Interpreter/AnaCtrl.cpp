#include "Analyze.h"
#include "AnaCtrl.h"

#include <asm/ptrace.h>
#include <linux/types.h>
#include <signal.h>
#include <ucontext.h>

#include <iostream>

#include "BPatch.h"
#include "BPatch_basicBlock.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "VMState.h"
#include "defines.h"
#include "interface.h"
#include "thinctrl.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;    


CAnaCtrl::CAnaCtrl(VMState *VM, EveMeta* meta) {
    m_VM = VM;
}

CAnaCtrl::~CAnaCtrl() {
}
