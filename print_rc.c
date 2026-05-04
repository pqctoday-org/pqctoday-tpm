#include <stdio.h>
#include "libtpms/src/tpm2/TpmTypes.h"
#include "libtpms/src/tpm2/ContextSave_fp.h"
int main() {
    printf("RC_ContextSave_saveHandle: %x\n", RC_ContextSave_saveHandle);
    printf("TPM_RC_TYPE: %x\n", TPM_RC_TYPE);
    printf("TPM_RCS_TYPE + RC_ContextSave_saveHandle: %x\n", TPM_RC_TYPE + RC_ContextSave_saveHandle);
    return 0;
}
