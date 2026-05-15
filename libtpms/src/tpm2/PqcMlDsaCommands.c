/********************************************************************************/
/*                                                                              */
/*  V1.85 ML-DSA / HashML-DSA command handlers                                 */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Implemented (V1.85 RC4 Part 3 section numbers):                            */
/*    TPM2_SignDigest              (§20.7) — real, calls CryptMlDsaSign        */
/*    TPM2_VerifyDigestSignature   (§20.4) — real, calls CryptMlDsaValidate    */
/*                                                                              */
/*  Phase 4 (streaming, needs MLDSA_SEQUENCE_OBJECT):                          */
/*    TPM2_SignSequenceStart       (§17.5) — returns TPM_RC_COMMAND_CODE       */
/*    TPM2_SignSequenceComplete    (§20.6) — returns TPM_RC_COMMAND_CODE       */
/*    TPM2_VerifySequenceStart     (§17.6) — returns TPM_RC_COMMAND_CODE       */
/*    TPM2_VerifySequenceComplete  (§20.3) — returns TPM_RC_COMMAND_CODE       */
/*                                                                              */
/********************************************************************************/

#include "Tpm.h"

/* ── TPM2_SignDigest ──────────────────────────────────────────────────────── */

#include "SignDigest_fp.h"

#if CC_SignDigest

#  include "Attest_spt_fp.h"    /* IsSigningObject() */

/*
 * Sign a pre-computed digest using a loaded ML-DSA or HashML-DSA key.
 *
 * V1.85 RC4 Part 3 §20.7.2 Table 126 wire shape:
 *   { @keyHandle, TPM2B_SIGNATURE_CTX context, TPM2B_DIGEST digest,
 *     TPMT_TK_HASHCHECK validation }
 *
 * §20.7.1: "Signing using a restricted key is permitted, but it requires a
 * valid TPMT_TK_HASHCHECK indicating that digest is known by the TPM to be
 * the hash of some message which does not begin with TCG_GENERATED_VALUE."
 * Note: for ML-DSA, no valid HASHCHECK ticket can be produced (the message
 * representative µ is not a plain hash), so restricted keys cannot satisfy
 * the ticket requirement and are effectively rejected.
 *
 * Return:
 *   TPM_RC_KEY        keyHandle does not reference a signing key
 *   TPM_RC_ATTRIBUTES key does not support digest-mode signing
 *   TPM_RC_TICKET     restricted key without a valid HASHCHECK ticket
 *   TPM_RC_FAILURE    crypto engine failure
 */
TPM_RC
TPM2_SignDigest(SignDigest_In *in, SignDigest_Out *out)
{
    OBJECT *signObject = HandleToObject(in->keyHandle);

    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_SignDigest_keyHandle;

    /* ML-DSA and HashML-DSA are the only algorithms supported by this command. */
    if(signObject->publicArea.type != TPM_ALG_MLDSA
       && signObject->publicArea.type != TPM_ALG_HASH_MLDSA)
        return TPM_RCS_ATTRIBUTES + RC_SignDigest_keyHandle;

    /* V1.85 RC4 Part 2 §12.2.3.6 Table 229: TPMS_MLDSA_PARMS.allowExternalMu
     * gates SignDigest / VerifyDigestSignature for ML-DSA keys. When NO, the
     * digest field would be interpreted as the external Mu (μ) per FIPS 204 —
     * which the key was not provisioned to accept, so the TPM MUST refuse.
     * HashML-DSA keys are not gated by this flag (Table 230 has no allowExternalMu). */
    if(signObject->publicArea.type == TPM_ALG_MLDSA
       && signObject->publicArea.parameters.mldsaDetail.allowExternalMu != YES)
        return TPM_RCS_ATTRIBUTES + RC_SignDigest_keyHandle;

    /* §20.7.1 restriction rule: restricted keys require a valid HASHCHECK
     * ticket. A NULL ticket (hierarchy = TPM_RH_NULL) is by definition not
     * "valid" for a restricted key per §22.1.2. For ML-DSA, no valid ticket
     * can ever be produced — the µ value isn't a TPM-attested hash — so
     * this path always rejects restricted ML-DSA SignDigest. */
    if(IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       && in->validation.hierarchy == TPM_RH_NULL)
        return TPM_RCS_TICKET + RC_SignDigest_validation;

    return CryptMlDsaSign(
        &out->signature,
        signObject,
        &in->digest,
        NULL,
        in->context.t.size > 0 ? &in->context : NULL,
        NULL);   /* hint not in V1.85 RC4 wire — passed as NULL */
}

#endif  /* CC_SignDigest */

/* ── TPM2_VerifyDigestSignature ──────────────────────────────────────────── */

#include "VerifyDigestSignature_fp.h"

#if CC_VerifyDigestSignature

/*
 * Verify an ML-DSA or HashML-DSA signature over a pre-computed digest.
 * On success returns a TPM_ST_DIGEST_VERIFIED ticket.
 *
 * Return:
 *   TPM_RC_ATTRIBUTES   keyHandle is not a signing/verification key
 *   TPM_RC_SIGNATURE    signature fails verification
 *   TPM_RC_SCHEME       signature scheme not compatible with key
 *   TPM_RC_FAILURE      crypto engine failure
 */
TPM_RC
TPM2_VerifyDigestSignature(VerifyDigestSignature_In  *in,
                           VerifyDigestSignature_Out *out)
{
    TPM_RC  result;
    OBJECT *signObject = HandleToObject(in->keyHandle);

    if(!IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_ATTRIBUTES + RC_VerifyDigestSignature_keyHandle;

    /* V1.85 RC4 Part 2 §12.2.3.6 Table 229: TPMS_MLDSA_PARMS.allowExternalMu
     * gate (see TPM2_SignDigest above for full rationale). HashML-DSA keys are
     * not gated by this flag. */
    if(signObject->publicArea.type == TPM_ALG_MLDSA
       && signObject->publicArea.parameters.mldsaDetail.allowExternalMu != YES)
        return TPM_RCS_ATTRIBUTES + RC_VerifyDigestSignature_keyHandle;

    result = CryptMlDsaValidateSignature(
        &in->signature,
        signObject,
        &in->digest,
        in->context.t.size > 0 ? &in->context : NULL);

    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_VerifyDigestSignature_signature);

    /* Build a TPM_ST_DIGEST_VERIFIED ticket (V1.85 §10.6.5 Table 112). */
    {
        TPMI_RH_HIERARCHY hier = GetHierarchy(in->keyHandle);
        if(hier == TPM_RH_NULL
           || signObject->publicArea.nameAlg == TPM_ALG_NULL)
        {
            out->validation.tag               = TPM_ST_DIGEST_VERIFIED;
            out->validation.hierarchy         = TPM_RH_NULL;
            out->validation.metadata.digestVerified = TPM_ALG_NULL;
            out->validation.hmac.t.size       = 0;
        }
        else
        {
            result = TicketComputeVerified(
                hier, &in->digest, &signObject->name, &out->validation);
            if(result != TPM_RC_SUCCESS)
                return result;
            /* Override tag to DIGEST_VERIFIED and record hash algorithm. */
            out->validation.tag = TPM_ST_DIGEST_VERIFIED;
            out->validation.metadata.digestVerified =
                in->signature.sigAlg == TPM_ALG_HASH_MLDSA
                    ? in->signature.signature.hash_mldsa.hash
                    : TPM_ALG_NULL;
        }
    }

    return TPM_RC_SUCCESS;
}

#endif  /* CC_VerifyDigestSignature */

/* Phase 4 sequence-command handlers live in PqcSequenceCommands.c. */
