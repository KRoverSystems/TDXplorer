#pragma once

#include "seam.h"

#define AGENT_STACK_R15_OFFSET       0x8
#define AGENT_STACK_RAX_OFFSET      0x10
#define AGENT_STACK_RBX_OFFSET      0x18
#define AGENT_STACK_RCX_OFFSET      0x20
#define AGENT_STACK_RDX_OFFSET      0x28
#define AGENT_STACK_RDI_OFFSET      0x30
#define AGENT_STACK_RSI_OFFSET      0x38
#define AGENT_STACK_RBP_OFFSET      0x40
#define AGENT_STACK_R8_OFFSET       0x48
#define AGENT_STACK_R9_OFFSET       0x50
#define AGENT_STACK_R10_OFFSET      0x58
#define AGENT_STACK_R11_OFFSET      0x60
#define AGENT_STACK_R12_OFFSET      0x68
#define AGENT_STACK_R13_OFFSET      0x70
#define AGENT_STACK_R14_OFFSET      0x78
/*#define AGENT_STACK_RFALGS_OFFSET   0x80   uncomment this if we push rflags
 on to int3 handler's stack someday*/
#define AGENT_STACK_INVALID_OFFSET  0xffff

