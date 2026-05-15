/********************************************************************************/
/*                                                                              */
/*  TPM2_SignDigest — V1.85 ML-DSA / HashML-DSA sign over digest (Part 3 §20.7) */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#ifndef SIGNDIGEST_FP_H
#define SIGNDIGEST_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

/* V1.85 RC4 Part 3 §20.7.2 Table 126 wire order:
 *   { @keyHandle, TPM2B_SIGNATURE_CTX context, TPM2B_DIGEST digest,
 *     TPMT_TK_HASHCHECK validation }
 * Struct field order MUST match the wire order so dispatcher paramOffsets
 * align with `types[]` in CommandDispatchData.h. */
typedef struct {
    TPMI_DH_OBJECT       keyHandle;   /* IN  H1: loaded ML-DSA signing key          */
    TPM2B_SIGNATURE_CTX  context;     /* IN  P1: domain-separation context          */
    TPM2B_DIGEST         digest;      /* IN  P2: pre-computed message digest        */
    TPMT_TK_HASHCHECK    validation;  /* IN  P3: hashcheck ticket (NULL ok for      */
                                      /*        non-restricted keys per §20.7.1)    */
} SignDigest_In;

#define RC_SignDigest_keyHandle   (TPM_RC_H + TPM_RC_1)
#define RC_SignDigest_context     (TPM_RC_P + TPM_RC_1)
#define RC_SignDigest_digest      (TPM_RC_P + TPM_RC_2)
#define RC_SignDigest_validation  (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPMT_SIGNATURE  signature;  /* OUT: ML-DSA / HashML-DSA signature */
} SignDigest_Out;

TPM_RC
TPM2_SignDigest(
    SignDigest_In  *in,
    SignDigest_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* SIGNDIGEST_FP_H */
