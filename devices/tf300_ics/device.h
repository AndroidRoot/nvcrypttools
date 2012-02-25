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

#define DEVICE_NAME "TF300 ICS"
#define DATADEV "/dev/mmcblk0p8"
#define DATADIR "/data"
#define DATAFS "ext4"

#define DESTDIR "/data/media/AndroidRoot/"


#define ODMDATA 0x40080105
#define BL_ENTRYPOINT 0x4000A000

#define BCT_BL_COUNT_OFFSET 0xf50
#define BCT_BL_RECORD_LEN (11 * 4)
#define BCT_BL_HASH_OFFSET 0xf70

struct device_data device_data =
	{ "cardhu",  CHIP_TYPE_TEGRA3,
      BL_ENTRYPOINT, ODMDATA,
      miniloader, sizeof(miniloader),
	  bct, sizeof(bct),
    };

#endif