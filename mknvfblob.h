#ifndef _MKNVFBLOB_H
#define _MKNVFBLOB_H
#include <stdint.h>

#include "nvaes.h"

typedef struct {
    enum {
        TYPE_VERSION = 0x1,
        TYPE_RCMVER,
        TYPE_RCMDLEXEC,
        TYPE_BLHASH,
        TYPE_EXT_WHEELIE_BCTC = 0x7F000000,
        TYPE_EXT_WHEELIE_BCTR,
        TYPE_EXT_WHEELIE_BL,
        TYPE_EXT_WHEELIE_ODMDATA,
        TYPE_EXT_WHEELIE_CPU_ID,
        TYPE_FORCE32 = 0x7FFFFFFF
    } type;

    uint32_t length;
    uint32_t reserved1;
    uint32_t reserved2;
    unsigned char hash[AES_BLOCK_SIZE];
} BlobHeader;
#endif
