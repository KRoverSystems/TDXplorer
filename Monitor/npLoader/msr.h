#pragma once

#include <stdint.h>
typedef uint64_t UINT64;

#define B_SEAMRR_BASE                    0xFFFFFFFFFE000000
#define B_SEAMRR_MASK                    0xFFFFFFFFFE000000


// typedef union {
//   struct {
//     UINT64 reserved0 : 25; // bits [24:0]
//     UINT64 base      : 39; // bits [63:25]
//   };
//   UINT64 raw;
// } SeamrrBase_u;

// typedef union {
//   struct {
//     UINT64 reserved0 : 10; // bits [9:0]
//     UINT64 lock      : 1;  // bit 10
//     UINT64 valid     : 1;  // bit 11
//     UINT64 reserved1 : 13; // bits [24:12]
//     UINT64 mask      : 39; // bits [63:25]
//   };
//   UINT64 raw;
// } SeamrrMask_u;