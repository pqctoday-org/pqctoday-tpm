/********************************************************************************/
/*                                                                              */
/*  TPM2_VerifyDigestSignature — V1.85 ML-DSA verify over digest (Part 3 §20.4) */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#ifndef VERIFYDIGESTSIGNATURE_FP_H
#define VERIFYDIGESTSIGNATURE_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

/* V1.85 RC4 Part 3 §20.4.2 Table 120 wire order:
 *   { @keyHandle, TPM2B_SIGNATURE_CTX context, TPM2B_DIGEST digest,
 *     TPMT_SIGNATURE signature }
 * Struct field order MUST match the wire order so dispatcher paramOffsets
 * align with `types[]` in CommandDispatchData.h. */
typedef struct {
    TPMI_DH_OBJECT       keyHandle;   /* IN  H1: loaded ML-DSA verification key     */
    TPM2B_SIGNATURE_CTX  context;     /* IN  P1: domain-separation context          */
    TPM2B_DIGEST         digest;      /* IN  P2: pre-computed message digest        */
    TPMT_SIGNATURE       signature;   /* IN  P3: signature to verify                */
} VerifyDigestSignature_In;

#define RC_VerifyDigestSignature_keyHandle   (TPM_RC_H + TPM_RC_1)
#define RC_VerifyDigestSignature_context     (TPM_RC_P + TPM_RC_1)
#define RC_VerifyDigestSignature_digest      (TPM_RC_P + TPM_RC_2)
#define RC_VerifyDigestSignature_signature   (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPMT_TK_VERIFIED  validation;  /* OUT: TPM_ST_DIGEST_VERIFIED ticket */
} VerifyDigestSignature_Out;

TPM_RC
TPM2_VerifyDigestSignature(
    VerifyDigestSignature_In  *in,
    VerifyDigestSignature_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* VERIFYDIGESTSIGNATURE_FP_H */
