#ifndef COMMON_IDATA_H
#define COMMON_IDATA_H

#include <stdint.h>

#define TDXMODULE_SPECIAL_INS_COUNT     600UL

struct iData {
    uint64_t va;
    uint32_t size;
    uint8_t  first_byte;
}__attribute__((packed));


#endif /*COMMON_IDATA_H*/