#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nvaes.h"

int main(int argc, char **argv)
{
    char iv[AES_BLOCK_SIZE] = {0};
    char out[NVAES_PAGE_SIZE];
    char in[NVAES_PAGE_SIZE];
    int bytes, fi, fo;
    nvaes_ctx ctx;

    if(argc < 3) {
        printf("Usage: %s <file to encrypt> <encrypted file>\n", argv[0]);
        exit(3);
    }

    if((fi = open(argv[1], O_RDONLY)) <= 0) {
        fprintf(stderr, "Error opening input file: %s\n", argv[1]);
        perror("Error");
        exit(3);
    }

    if((fo = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC)) <= 0) {
        fprintf(stderr, "Error opening output file: %s\n", argv[2]);
        perror("Error");
        exit(3);
    }

    if((ctx = nvaes_open()) < 0) {
        perror("Error opening AES engine");
        exit(3);
    }

    if(nvaes_use_ssk(ctx, 1) == 0) {
        fprintf(stderr, "Error requesting the use of the SSK.\n");
        exit(3);
    }

    if(nvaes_encrypt_fd(ctx, fi, fo) == 0) {
        fprintf(stderr, "Failed to encrypt file.\n");
        exit(3);
    }

    nvaes_close(ctx);
    close(fo);
    close(fi);
    return 0;
}
