#ifndef _NVRCM_H_
#define _NVRCM_H_

#define NVRCM_CODE_DLEXEC 4
#define NVRCM_CODE_VERSION 6

#define NVRCM_HASH_LEN 16
#define NVRCM_PADDING_LEN 16

#define NVRCM_MIN_MSG_LEN 1024
#define NVRCM_MAX_MSG_LEN (98304 + sizeof(nvrcm_msg))

#define NVRCM_CLEAR_LEN (sizeof(int32_t) + NVRCM_HASH_LEN)

#define NVRCM_VERSION 0x10000

typedef struct {
    int32_t length;
    char hash[NVRCM_HASH_LEN];
    char unused1[NVRCM_HASH_LEN];
    int32_t code;
    int32_t enclen;
    int32_t datalen;
    int32_t version;
    int32_t entrypoint;
    char unused2[44];
    char padding[NVRCM_PADDING_LEN];
} nvrcm_msg;

int nvrcm_create(int code, int entrypoint, int datalen, const unsigned char *data,
                 unsigned char **buf, int *len);

void nvrcm_free(unsigned char *buf);
#endif
