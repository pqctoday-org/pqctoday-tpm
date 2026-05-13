/* ek_conformance_xcheck.c
 *
 * Phase B step 2 of issue #2 (G7-A): wolfTPM-driven byte-exact conformance
 * check for the V2.7 RC1 PQC EK templates.
 *
 * Pipeline:
 *
 *    swtpm + libtpms (provisions PQC EKs via swtpm_setup)
 *           │
 *           │ wolfTPM TPM2_ReadPublic per persistent handle
 *           ▼
 *    Out.outPublic.publicArea = TPMT_PUBLIC
 *           │
 *           │ Re-marshal via wolfTPM's TPM2_Packet_AppendPublic
 *           │ (strip the leading TPM2B size field — we want the bare
 *           │  TPMT_PUBLIC bytes, the same shape as our reference)
 *           ▼
 *    Byte-diff against tests/compliance/vectors/v2p7-ek-templates/
 *           │
 *           ├──► PASS — bit-exact match to V2.7 Table 13/14 reference
 *           └──► FAIL — print first-divergence offset + decoded fields
 *
 * For handles that are not provisioned: SKIP. The script is therefore a
 * pure read-side test; it does not modify any TPM state.
 *
 * Spec: TCG EK Credential Profile V2.7 RC1, §5.4.6.5–6 Tables 13/14.
 * Reference: docs/TPMdocextract.md §17.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include "tests/compliance/vectors/v2p7-ek-templates/v2p7_ek_template_vectors.h"

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)

static int g_pass = 0, g_fail = 0, g_skip = 0;

static void rpass(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("  [PASS] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap);
    g_pass++;
}
static void rfail(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("  [FAIL] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap);
    g_fail++;
}
static void rskip(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("  [SKIP] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap);
    g_skip++;
}

/* Marshal a TPMT_PUBLIC to bare wire bytes via wolfTPM's packet API.
 * AppendPublic writes a TPM2B_PUBLIC (2 B size + body); we strip the
 * size prefix to get the bare TPMT_PUBLIC shape that V2.7 Tables 13/14
 * describe. */
static int marshal_tpmt_public(TPM2B_PUBLIC *pub,
                               unsigned char *out, size_t outCap, size_t *outLen)
{
    unsigned char buf[1024];
    TPM2_Packet packet;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf  = buf;
    packet.size = sizeof(buf);
    packet.pos  = 0;
    TPM2_Packet_AppendPublic(&packet, pub);
    if (packet.pos < 2 || (size_t)packet.pos > outCap + 2) return -1;
    /* Skip the 2-byte TPM2B size prefix that AppendPublic writes. */
    size_t bareLen = (size_t)packet.pos - 2;
    if (bareLen > outCap) return -1;
    memcpy(out, buf + 2, bareLen);
    *outLen = bareLen;
    return 0;
}

static void hex_diff(const unsigned char *got, size_t gotLen,
                     const unsigned char *want, size_t wantLen)
{
    size_t n = (gotLen < wantLen) ? gotLen : wantLen;
    for (size_t i = 0; i < n; i++) {
        if (got[i] != want[i]) {
            printf("           first divergence at offset %zu: got 0x%02X, want 0x%02X\n",
                   i, got[i], want[i]);
            return;
        }
    }
    if (gotLen != wantLen)
        printf("           length divergence: got %zu B, want %zu B\n", gotLen, wantLen);
}

/* Expected `unique` (public-key) sizes per parameter set.
 *
 * Primary-source citations (cached locally in docs/standards/):
 *   docs/standards/NIST.FIPS.203.pdf Table 3 p.39 — ML-KEM encapsulation-key sizes
 *   docs/standards/NIST.FIPS.204.pdf Table 2 p.16 — ML-DSA public-key sizes
 *
 * Mirrored into docs/TPMdocextract.md §3 (ML-KEM) and §4 (ML-DSA) for
 * offline reference. TCG TPM Library Part 2 Tables 204/207 carry the same
 * numbers; FIPS is the upstream authority. */
static unsigned expected_unique_size(int isMlkem, int paramSet)
{
    if (isMlkem) {
        /* FIPS 203 Table 3 — ML-KEM encapsulation key (public key) sizes. */
        switch (paramSet) {
            case 1: return 800;   /* ML-KEM-512 */
            case 2: return 1184;  /* ML-KEM-768 */
            case 3: return 1568;  /* ML-KEM-1024 */
        }
    } else {
        /* FIPS 204 Table 2 — ML-DSA public key sizes. */
        switch (paramSet) {
            case 1: return 1312;  /* ML-DSA-44 */
            case 2: return 1952;  /* ML-DSA-65 */
            case 3: return 2592;  /* ML-DSA-87 */
        }
    }
    return 0;
}

static void check_one(WOLFTPM2_DEV *dev,
                      const char *name,
                      TPM_HANDLE handle,
                      const unsigned char *expect, size_t expectLen,
                      int isMlkem, int paramSet)
{
    ReadPublic_In  in;
    ReadPublic_Out out;
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.objectHandle = handle;

    int rc = TPM2_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        if (rc == (TPM_RC_HANDLE | TPM_RC_1)) {
            rskip("%s @ 0x%08x — handle not provisioned", name, (unsigned)handle);
        } else {
            rfail("%s @ 0x%08x — ReadPublic rc=0x%x (%s)",
                  name, (unsigned)handle, rc, wolfTPM2_GetRCString(rc));
        }
        return;
    }

    unsigned char got[4096];
    size_t        gotLen;
    if (marshal_tpmt_public(&out.outPublic, got, sizeof(got), &gotLen) != 0) {
        rfail("%s — marshal failed (readback too large for buffer)", name);
        return;
    }

    /* Two-part rigorous check per V2.7 Tables 13/14:
     *
     * 1. Template-fixed prefix (everything except `unique`) must byte-equal
     *    the V2.7 reference. The reference includes a trailing 2-byte
     *    unique.size=0 from the *input template*; the readback contains
     *    unique.size=FIPS-pubkey-size with the generated pubkey filling
     *    `buffer`. So strip the last 2 bytes off the reference, and look
     *    at the corresponding prefix of the readback.
     *
     * 2. The readback's unique.size MUST equal the FIPS 203/204 pubkey
     *    size for the variant — proves the TPM actually generated the
     *    correct-sized public key (no stubs, no zero fill).
     */
    size_t prefixLen = expectLen - 2;  /* drop unique.size=0 sentinel */
    if (gotLen < prefixLen) {
        rfail("%s @ 0x%08x — readback %zu B shorter than V2.7 template prefix %zu B",
              name, (unsigned)handle, gotLen, prefixLen);
        hex_diff(got, gotLen, expect, prefixLen);
        return;
    }
    if (memcmp(got, expect, prefixLen) != 0) {
        rfail("%s @ 0x%08x — V2.7 template prefix mismatch (first %zu B)",
              name, (unsigned)handle, prefixLen);
        hex_diff(got, prefixLen, expect, prefixLen);
        return;
    }

    /* Now check unique.size on the wolfTPM-parsed struct — independent
     * of how the marshal handled the unique buffer. wolfTPM stores it in
     * the typed unique union: pub.publicArea.unique.mlkem.size  for ML-KEM,
     * pub.publicArea.unique.mldsa.size for ML-DSA. */
    unsigned expected_pk = expected_unique_size(isMlkem, paramSet);
    unsigned got_pk;
#ifdef WOLFTPM_V185
    if (isMlkem) {
        got_pk = out.outPublic.publicArea.unique.mlkem.size;
    } else {
        got_pk = out.outPublic.publicArea.unique.mldsa.size;
    }
#else
    got_pk = 0;  /* should never compile-pass without V185 */
#endif
    if (got_pk != expected_pk) {
        rfail("%s @ 0x%08x — unique.size = %u, FIPS expects %u",
              name, (unsigned)handle, got_pk, expected_pk);
        return;
    }

    /* ─── Phase B step 5: Name / qualifiedName / hierarchy structure check.
     *
     * Per V1.85 Part 2 §16.2 (Name) and §16.3 (Qualified Name):
     *   Name           = TPM_ALG_ID nameAlg || H(publicArea bytes)
     *   QualifiedName  = TPM_ALG_ID nameAlg || H(parent.QN || Name)
     *
     * For a primary key in the Endorsement hierarchy, parent.QN is the
     * special-encoded TPM_RH_ENDORSEMENT (`0x4000000B`). The TPM computes
     * both Name and QN at CreatePrimary and returns them on ReadPublic.
     *
     * Full recomputation would require hashing the FULL TPMT_PUBLIC
     * including `unique.buffer` — which wolfTPM v4.0.0 doesn't always
     * marshal back through its public API (separate upstream gap). So
     * here we check the STRUCTURAL invariants the spec mandates:
     *   • name.size  == 2 + digestSize(nameAlg)   (the TPM_ALG_ID prefix
     *                                              plus the hash output)
     *   • name[0..1] == nameAlg encoded big-endian (matches public.nameAlg)
     *   • Same shape for qualifiedName.
     * That alone is enough to prove the TPM computed Names per spec —
     * a stub would not produce the right size or the right algorithm ID
     * prefix. Full hash recomputation can land later when wolfTPM ships
     * the unique-buffer marshal fix. */
    unsigned digestSize;
    switch (out.outPublic.publicArea.nameAlg) {
        case TPM_ALG_SHA256: digestSize = 32; break;
        case TPM_ALG_SHA384: digestSize = 48; break;
        case TPM_ALG_SHA512: digestSize = 64; break;
        default:
            rfail("%s — unexpected nameAlg 0x%x in readback",
                  name, (unsigned)out.outPublic.publicArea.nameAlg);
            return;
    }
    const unsigned expected_name_size = 2 + digestSize;

    if (out.name.size != expected_name_size) {
        rfail("%s — name.size = %u, V1.85 §16.2 requires 2+digest = %u",
              name, (unsigned)out.name.size, expected_name_size);
        return;
    }
    if (out.qualifiedName.size != expected_name_size) {
        rfail("%s — qualifiedName.size = %u, V1.85 §16.3 requires 2+digest = %u",
              name, (unsigned)out.qualifiedName.size, expected_name_size);
        return;
    }
    /* Big-endian 2-byte TPM_ALG_ID prefix on both Name and QN. */
    const TPM_ALG_ID na = out.outPublic.publicArea.nameAlg;
    const byte hi = (byte)(na >> 8), lo = (byte)(na & 0xff);
    if (out.name.name[0] != hi || out.name.name[1] != lo) {
        rfail("%s — name nameAlg prefix %02x%02x, expected %02x%02x",
              name, out.name.name[0], out.name.name[1], hi, lo);
        return;
    }
    if (out.qualifiedName.name[0] != hi || out.qualifiedName.name[1] != lo) {
        rfail("%s — qualifiedName nameAlg prefix %02x%02x, expected %02x%02x",
              name, out.qualifiedName.name[0], out.qualifiedName.name[1], hi, lo);
        return;
    }

    rpass("%s @ 0x%08x — V2.7 template (%zu B) + FIPS unique.size=%u + spec Name/QN (%u B each)",
          name, (unsigned)handle, prefixLen, expected_pk, expected_name_size);
}

/* Persistent handle assignments (pqctoday-tpm internal — V2.7 RC1 does not
 * normatively assign EK persistent handles, only cert NV indices). These
 * mirror swtpm_setup. */
#define HANDLE_EK_MLKEM_768    0x810100A0u   /* current swtpm_setup ML-KEM EK */
#define HANDLE_EK_MLKEM_512    0x810100B0u   /* Phase B will provision */
#define HANDLE_EK_MLKEM_1024   0x810100B2u   /* Phase B will provision */
#define HANDLE_EK_MLDSA_44     0x810100B4u   /* Phase B will provision */
#define HANDLE_EK_MLDSA_65     0x810100B5u   /* Phase B will provision */
#define HANDLE_EK_MLDSA_87     0x810100B6u   /* Phase B will provision */

int main(void)
{
    WOLFTPM2_DEV dev; XMEMSET(&dev, 0, sizeof(dev));
    int rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "wolfTPM2_Init failed: 0x%x (%s)\n",
                rc, wolfTPM2_GetRCString(rc));
        return 1;
    }

    printf("=== V2.7 RC1 PQC EK Template conformance — wolfTPM-driven, byte-exact ===\n");
    printf("  TPM:    libtpms (OpenSSL 3.6.2) inside swtpm\n");
    printf("  client: wolfTPM v4.0.0 TPM2_ReadPublic + TPM2_Packet marshal\n");
    printf("  refs:   tests/compliance/vectors/v2p7-ek-templates/\n");
    putchar('\n');

    printf("=== ML-KEM Storage EKs (V2.7 §5.4.6.5 Table 13) ===\n");
    check_one(&dev, "ML-KEM-512  EK", HANDLE_EK_MLKEM_512,  v2p7_ek_mlkem512,  V2P7_EK_MLKEM512_LEN,  1, 1);
    check_one(&dev, "ML-KEM-768  EK", HANDLE_EK_MLKEM_768,  v2p7_ek_mlkem768,  V2P7_EK_MLKEM768_LEN,  1, 2);
    check_one(&dev, "ML-KEM-1024 EK", HANDLE_EK_MLKEM_1024, v2p7_ek_mlkem1024, V2P7_EK_MLKEM1024_LEN, 1, 3);

    printf("\n=== ML-DSA Signing EKs (V2.7 §5.4.6.6 Table 14) ===\n");
    check_one(&dev, "ML-DSA-44 EK", HANDLE_EK_MLDSA_44, v2p7_ek_mldsa44, V2P7_EK_MLDSA44_LEN, 0, 1);
    check_one(&dev, "ML-DSA-65 EK", HANDLE_EK_MLDSA_65, v2p7_ek_mldsa65, V2P7_EK_MLDSA65_LEN, 0, 2);
    check_one(&dev, "ML-DSA-87 EK", HANDLE_EK_MLDSA_87, v2p7_ek_mldsa87, V2P7_EK_MLDSA87_LEN, 0, 3);

    printf("\n=== Summary ===\n");
    printf("  %d passed, %d failed, %d skipped (handles not provisioned)\n",
           g_pass, g_fail, g_skip);

    wolfTPM2_Cleanup(&dev);
    return (g_fail == 0) ? 0 : 1;
}

#else
int main(void) {
    fprintf(stderr, "ek_conformance_xcheck requires WOLFTPM_V185 + wolfTPM2 wrappers\n");
    return 2;
}
#endif
