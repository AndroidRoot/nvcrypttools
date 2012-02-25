#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nvrcm.h"

static int get_rcm_msg_len(int datalen)
{
    if(datalen + sizeof(nvrcm_msg) >= NVRCM_MIN_MSG_LEN) {
        datalen += sizeof(nvrcm_msg) + NVRCM_PADDING_LEN - (datalen & 0x0F);
    } else {
        datalen -= (datalen + (int)sizeof(nvrcm_msg));
        datalen += NVRCM_MIN_MSG_LEN + sizeof(nvrcm_msg);
        datalen += (sizeof(nvrcm_msg) & 0x0F);
    }

    return datalen;
}

int nvrcm_create(int code, int entrypoint, int datalen, const unsigned char *data,
                 unsigned char **buf, int *len)
{
    nvrcm_msg *msg;

    *len = get_rcm_msg_len(datalen);
    *buf = (unsigned char *)malloc(*len);

    if(!*buf) {
        *len = 0;
        perror("failed to allocate memory for rcm message");
        return 0;
    }

    /* Initialise the RCM message. */
    memset(*buf, 0, *len);
    msg = (nvrcm_msg *)*buf;
    msg->length = *len;
    msg->code = code;
    msg->enclen = msg->length;
    msg->datalen = datalen;
    msg->version = NVRCM_VERSION;
    msg->entrypoint = entrypoint;
    msg->padding[0] = 0x80;

    if(datalen)
        memcpy(*buf + sizeof(nvrcm_msg), data, datalen);

    (*buf + sizeof(nvrcm_msg) + datalen)[0] = msg->padding[0];

    return 1;
}

void nvrcm_free(unsigned char *buf)
{
    if(buf)
        free(buf);
}

#ifdef __DEBUG_RCM_TEST
int main(int argc, char **argv)
{
    unsigned char *buf;
    int len;

    if(!nvrcm_create(NVRCM_CODE_VERSION, 0, 0, NULL, &buf, &len)) {
        fprintf(stderr, "failed to create rcm message!\n");
        return 1;
    }

    FILE *fp = fopen("version.bin", "w");
    fwrite(buf, 1, len, fp);
    fclose(fp);

    nvrcm_free(buf);
    return 0;
}
#endif
