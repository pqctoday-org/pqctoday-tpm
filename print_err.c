#include <stdio.h>
#define MAX_CAP_BUFFER 1024
#define MAX_DIGEST_SIZE 64
#define MAX_HASH_BLOCK_SIZE 128
#define MAX_SYM_KEY_BITS 256
#define MAX_SYM_BLOCK_SIZE 16
#define RSA_MAX_KEY_SIZE_BITS 4096
#include "libtpms/src/tpm2/TPMCmd/tpm/include/Tpm.h"
int main() {
    printf("0x1DA == %d\n", 0x1DA);
    return 0;
}
