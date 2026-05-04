#include <stdio.h>
#define MAX_CAP_BUFFER 1024
#define MAX_DIGEST_SIZE 64
#define MAX_HASH_BLOCK_SIZE 128
#define MAX_SYM_KEY_BITS 256
#define MAX_SYM_BLOCK_SIZE 16
#define RSA_MAX_KEY_SIZE_BITS 4096
#define SMAC_IMPLEMENTED 0
#define NUM_POLICY_PCR_GROUP 1
#define NUM_AUTHVALUE_PCR_GROUP 1
#include "libtpms/src/tpm2/TPMCmd/tpm/include/Tpm.h"
#include "libtpms/src/tpm2/Global.h"

int main() {
    printf("sizeof(OBJECT) = %lu\n", sizeof(OBJECT));
    printf("sizeof(HASH_OBJECT) = %lu\n", sizeof(HASH_OBJECT));
    printf("sizeof(PQC_SEQ_STATE) = %lu\n", sizeof(PQC_SEQ_STATE));
    return 0;
}
