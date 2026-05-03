/********************************************************************************/
/*                                                                              */
/*  PqcSequence.c — V1.85 RC4 Phase 4 sign/verify sequence slot pool            */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                         */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#include "Tpm.h"
#include "PqcSequence_fp.h"
#include "Object_spt_fp.h"

#if (ALG_MLDSA || ALG_HASH_MLDSA) && (CC_SignSequenceStart || CC_SignSequenceComplete \
                                       || CC_VerifySequenceStart || CC_VerifySequenceComplete)

LIB_EXPORT void
PqcSequenceStartup(void)
{
    /* No longer a private pool, managed by core object system */
}

LIB_EXPORT TPM_HANDLE
PqcSequenceAllocate(BOOL isSign, TPM2B_AUTH *auth)
{
    TPM_HANDLE newHandle;
    HASH_OBJECT *hashObject;

    hashObject = (HASH_OBJECT*)ObjectAllocateSlot(&newHandle);
    if (hashObject == NULL)
        return TPM_RH_UNASSIGNED; /* Out of memory */

    MemorySet(hashObject, 0, sizeof(HASH_OBJECT));
    
    hashObject->attributes.occupied = SET;
    hashObject->attributes.pqcSeq = SET;
    
    /* Initialize type and nameAlg to TPM_ALG_NULL so unmarshaling succeeds */
    hashObject->type = TPM_ALG_NULL;
    hashObject->nameAlg = TPM_ALG_NULL;

    /* Ensure other sequence attributes are CLEAR */
    hashObject->attributes.hmacSeq = CLEAR;
    hashObject->attributes.hashSeq = CLEAR;
    hashObject->attributes.eventSeq = CLEAR;

    if (auth != NULL) {
        hashObject->auth = *auth;
    }

    hashObject->state.pqcState.isSign = isSign;

    return newHandle;
}

LIB_EXPORT BOOL
PqcSequenceIsHandle(TPM_HANDLE handle)
{
    OBJECT *obj;
    if (HandleGetType(handle) != TPM_HT_TRANSIENT)
        return FALSE;
    if (!IsObjectPresent(handle))
        return FALSE;
    obj = HandleToObject(handle);
    return (obj->attributes.pqcSeq == SET);
}

LIB_EXPORT PQC_SEQ_STATE *
PqcSequenceFromHandle(TPM_HANDLE handle)
{
    HASH_OBJECT *hashObject;

    if (!PqcSequenceIsHandle(handle))
        return NULL;

    hashObject = (HASH_OBJECT*)HandleToObject(handle);
    return &hashObject->state.pqcState;
}

LIB_EXPORT void
PqcSequenceFlush(TPM_HANDLE handle)
{
    if (PqcSequenceIsHandle(handle)) {
        FlushObject(handle);
    }
}

LIB_EXPORT TPM_RC
PqcSequenceUpdate(PQC_SEQ_STATE *seq, const BYTE *data, UINT16 dataLen)
{
    if (seq == NULL)
        return TPM_RC_HANDLE;

    /* V1.85 §17.5: "for EdDSA signing, TPM2_SequenceUpdate() is not allowed,
     * because the TPM needs to buffer the entire message when producing
     * EdDSA signatures." FIPS 204 ML-DSA has the same property (μ is
     * computed over the entire message before the signing iteration), so
     * we apply the same gate. The error code is TPM_RC_ONE_SHOT_SIGNATURE
     * per V1.85 §6.6.4 + §20.6. */
    if (seq->isSign)
        return TPM_RC_ONE_SHOT_SIGNATURE;

    if (dataLen == 0)
        return TPM_RC_SUCCESS;
    if ((UINT32)seq->bufferUsed + dataLen > MAX_PQC_SEQ_BUFFER)
        return TPM_RC_SIZE;
    MemoryCopy(&seq->buffer[seq->bufferUsed], data, dataLen);
    seq->bufferUsed += dataLen;
    return TPM_RC_SUCCESS;
}

#endif  /* sequence commands enabled */
