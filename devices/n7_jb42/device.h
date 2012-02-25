#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <device_data.h>

static unsigned char miniloader[] = {
#include "miniloader.h"
};

uint32_t const miniloader_len = sizeof(miniloader);

static unsigned char bct[] = {
#include "bct.h"
};
uint32_t const bct_len = sizeof(bct);


#define USE_DEVTMPFS

#define DEVICE_NAME "N7 JB4.2"

#define BLOB_VERSION "v1.13.00000"

#define ODMDATA 0x40000000
#define BL_ENTRYPOINT 0x4000A000

#define BCT_BL_COUNT_OFFSET 0xf50
#define BCT_BL_RECORD_LEN (11 * 4)
#define BCT_BL_HASH_OFFSET 0xf70

struct device_data device_data =
	{ "grouper",  CHIP_TYPE_TEGRA3,
      BL_ENTRYPOINT, ODMDATA,
      miniloader, sizeof(miniloader),
	  bct, sizeof(bct),
    };

#endif