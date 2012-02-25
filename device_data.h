#ifndef _DEVICE_DATA_H_
#define _DEVICE_DATA_H_

struct device_data {
    const char *name;
    enum {
        CHIP_TYPE_TEGRA2=0x20,
        CHIP_TYPE_TEGRA3=0x30,
        CHIP_TYPE_UNKNOWN=0xFFFFFFFF
    } type;
    uint32_t entrypoint;
    uint32_t odmdata;
    unsigned char *miniloader;
    uint32_t miniloader_len;
	unsigned char *bct;
	uint32_t bct_len;
};

#endif /* _DEVICE_DATA_H_ */