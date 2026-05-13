/*
 * tcg_pqc_ek_constants.h
 *
 * Spec-mandated constants from the TCG EK Credential Profile for TPM Family
 * 2.0; Level 0; Version 2.7 RC1 (7 November 2025) — Public Review.
 *
 * Source PDF: docs/standards/TCG-EK-Credential-Profile-for-TPM-Family-2p0-
 *             Level-0-V2p7-RC1_7November2025.pdf
 * Source quote: see docs/TPMdocextract.md §17 for the extracted spec text
 *               (Tables 8, 13, 14, NV index allocations).
 *
 * Phase A of issue #2 (G7-A) compliance work — see CHANGELOG. Phase B adds
 * the full spec-compliant EK templates that *use* these constants; Phase C
 * adds X.509 cert generation per §6.x and populates the NV cert slots.
 *
 * This header is INDEPENDENT of any compile-time ALG_* feature switches — the
 * constants are defined by the TCG spec, not by libtpms build options. Code
 * that uses them must still gate on ALG_MLKEM / ALG_MLDSA at use sites.
 */

#ifndef PQCTODAY_TPM_TCG_PQC_EK_CONSTANTS_H
#define PQCTODAY_TPM_TCG_PQC_EK_CONSTANTS_H

/* ────────────────────────────────────────────────────────────────────────
 * §5.3.1 — NV Index allocations for PQC EK certificates.
 *
 * These NV indexes hold the X.509 EK Certificates (cert blobs), NOT the EK
 * keys themselves. Persistent EK key handles are NOT normatively assigned
 * in V2.7 RC1 — they remain implementation-defined (see swtpm.c
 * TPM2_EK_MLKEM768_HANDLE etc. in the 0x8101xx range).
 *
 * Layout (V2.7 §5.3.1 page 47):
 *   ML-KEM Storage EK Certificates:           0x01c00060 .. 0x01c00064
 *   ML-KEM Firmware-limited EK Certificates:  0x01c00066 .. 0x01c0006a
 *   ML-DSA Signing  EK Certificates:          0x01c00070 .. 0x01c00074
 *   ML-DSA Firmware-limited EK Certificates:  0x01c00076 .. 0x01c0007a
 * ──────────────────────────────────────────────────────────────────────── */

/* ML-KEM Storage EK Certificate NV indices (Storage, not Firmware-limited) */
#define TCG_NV_EKCERT_MLKEM_512        0x01c00060u  /* H-26 */
#define TCG_NV_EKCERT_MLKEM_768        0x01c00062u  /* H-27 */
#define TCG_NV_EKCERT_MLKEM_1024       0x01c00064u  /* H-28 */

/* ML-KEM Storage EK Certificate NV indices, Firmware-limited variant */
#define TCG_NV_EKCERT_MLKEM_512_FWL    0x01c00066u  /* H-29 */
#define TCG_NV_EKCERT_MLKEM_768_FWL    0x01c00068u  /* H-30 */
#define TCG_NV_EKCERT_MLKEM_1024_FWL   0x01c0006au  /* H-31 */

/* ML-DSA Signing EK Certificate NV indices (not Firmware-limited) */
#define TCG_NV_EKCERT_MLDSA_44         0x01c00070u  /* H-32 */
#define TCG_NV_EKCERT_MLDSA_65         0x01c00072u  /* H-33 */
#define TCG_NV_EKCERT_MLDSA_87         0x01c00074u  /* H-34 */

/* ML-DSA Signing EK Certificate NV indices, Firmware-limited variant */
#define TCG_NV_EKCERT_MLDSA_44_FWL     0x01c00076u  /* H-35 */
#define TCG_NV_EKCERT_MLDSA_65_FWL     0x01c00078u  /* H-36 */
#define TCG_NV_EKCERT_MLDSA_87_FWL     0x01c0007au  /* H-37 */

/* ────────────────────────────────────────────────────────────────────────
 * §A.1.3 / §A.1.4 / §A.1.5 — Policy Index NV objects.
 *
 * These NV objects hold the Policy Index digests (I-1..I-3) referenced by
 * the PolicyAuthorizeNV branches of PolicyB. A TPM that ships PQC EKs MUST
 * have these NV objects created and populated at provisioning time.
 * ──────────────────────────────────────────────────────────────────────── */

#define TCG_NV_POLICY_INDEX_SHA256     0x01c07f01u  /* I-1 — Policy Index for SHA-256 */
#define TCG_NV_POLICY_INDEX_SHA384     0x01c07f02u  /* I-2 — Policy Index for SHA-384 */
#define TCG_NV_POLICY_INDEX_SHA512     0x01c07f03u  /* I-3 — Policy Index for SHA-512 */

/* ────────────────────────────────────────────────────────────────────────
 * §5.4.5.2 Table 8 — PolicyB digests.
 *
 * These are the EXACT byte values of the authPolicy field embedded in the
 * Tables 13/14 PQC EK templates. PolicyB is computed as:
 *
 *   PolicyA OR PolicyAuthorizeNV(I-x)
 *
 * The Verifier reproduces it by running the corresponding TPM2_PolicyOR over
 * a fresh policy session. The digest is hash-algorithm-dependent: SHA-256 →
 * 32 B, SHA-384 → 48 B, SHA-512 → 64 B.
 *
 * Embedding: PolicyB_SHA256 is the authPolicy for ML-KEM-512 + ML-DSA-44
 * (whose nameAlg == SHA-256); PolicyB_SHA384 for ML-KEM-768 + ML-DSA-65;
 * PolicyB_SHA512 for ML-KEM-1024 + ML-DSA-87.
 * ──────────────────────────────────────────────────────────────────────── */

/* PolicyB SHA-256 — 32 bytes (Table 8) */
#define TCG_POLICYB_SHA256_SIZE 32u
static const unsigned char tcg_policyB_sha256[TCG_POLICYB_SHA256_SIZE] = {
    0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9, 0x39, 0x06,
    0xF7, 0xA3, 0x34, 0x24, 0x14, 0xEF, 0xCF, 0xB3,
    0xA3, 0x85, 0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
    0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0, 0xB7, 0xA0,
};

/* PolicyB SHA-384 — 48 bytes (Table 8) */
#define TCG_POLICYB_SHA384_SIZE 48u
static const unsigned char tcg_policyB_sha384[TCG_POLICYB_SHA384_SIZE] = {
    0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC,
    0x53, 0xD8, 0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A,
    0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
    0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA,
    0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
    0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
};

/* PolicyB SHA-512 — 64 bytes (Table 8) */
#define TCG_POLICYB_SHA512_SIZE 64u
static const unsigned char tcg_policyB_sha512[TCG_POLICYB_SHA512_SIZE] = {
    0xB8, 0x22, 0x1C, 0xA6, 0x9E, 0x85, 0x50, 0xA4,
    0x91, 0x4D, 0xE3, 0xFA, 0xA6, 0xA1, 0x8C, 0x07,
    0x2C, 0xC0, 0x12, 0x08, 0x07, 0x3A, 0x92, 0x8D,
    0x5D, 0x66, 0xD5, 0x9E, 0xF7, 0x9E, 0x49, 0xA4,
    0x29, 0xC4, 0x1A, 0x6B, 0x26, 0x95, 0x71, 0xD5,
    0x7E, 0xDB, 0x25, 0xFB, 0xDB, 0x18, 0x38, 0x42,
    0x56, 0x08, 0xB4, 0x13, 0xCD, 0x61, 0x6A, 0x5F,
    0x6D, 0xB5, 0xB6, 0x07, 0x1A, 0xF9, 0x9B, 0xEA,
};

/* ────────────────────────────────────────────────────────────────────────
 * Cross-mapping: nameAlg → (PolicyB variant, byte size) for the V2.7 PQC
 * EK templates per Tables 13/14.
 *
 *   ML-KEM-512  / ML-DSA-44  : nameAlg = SHA-256 → PolicyBSHA256 (32 B)
 *   ML-KEM-768  / ML-DSA-65  : nameAlg = SHA-384 → PolicyBSHA384 (48 B)
 *   ML-KEM-1024 / ML-DSA-87  : nameAlg = SHA-512 → PolicyBSHA512 (64 B)
 * ──────────────────────────────────────────────────────────────────────── */

#endif /* PQCTODAY_TPM_TCG_PQC_EK_CONSTANTS_H */
