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

static void check_one(WOLFTPM2_DEV *dev,
                      const char *name,
                      TPM_HANDLE handle,
                      const unsigned char *expect, size_t expectLen)
{
    ReadPublic_In  in;
    ReadPublic_Out out;
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.objectHandle = handle;

    int rc = TPM2_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        /* TPM_RC_HANDLE = 0x18B — handle not provisioned on this TPM */
        if (rc == (TPM_RC_HANDLE | TPM_RC_1)) {
            rskip("%s @ 0x%08x — handle not provisioned", name, (unsigned)handle);
        } else {
            rfail("%s @ 0x%08x — ReadPublic rc=0x%x (%s)",
                  name, (unsigned)handle, rc, wolfTPM2_GetRCString(rc));
        }
        return;
    }

    unsigned char got[512];
    size_t        gotLen;
    if (marshal_tpmt_public(&out.outPublic, got, sizeof(got), &gotLen) != 0) {
        rfail("%s — marshal failed", name);
        return;
    }

    if (gotLen == expectLen && memcmp(got, expect, expectLen) == 0) {
        rpass("%s @ 0x%08x — TPMT_PUBLIC byte-exact match (%zu B) vs V2.7 Table 13/14",
              name, (unsigned)handle, gotLen);
    } else {
        rfail("%s @ 0x%08x — TPMT_PUBLIC mismatch (got %zu B, want %zu B)",
              name, (unsigned)handle, gotLen, expectLen);
        hex_diff(got, gotLen, expect, expectLen);
    }
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
    check_one(&dev, "ML-KEM-512  EK", HANDLE_EK_MLKEM_512,  v2p7_ek_mlkem512,  V2P7_EK_MLKEM512_LEN);
    check_one(&dev, "ML-KEM-768  EK", HANDLE_EK_MLKEM_768,  v2p7_ek_mlkem768,  V2P7_EK_MLKEM768_LEN);
    check_one(&dev, "ML-KEM-1024 EK", HANDLE_EK_MLKEM_1024, v2p7_ek_mlkem1024, V2P7_EK_MLKEM1024_LEN);

    printf("\n=== ML-DSA Signing EKs (V2.7 §5.4.6.6 Table 14) ===\n");
    check_one(&dev, "ML-DSA-44 EK", HANDLE_EK_MLDSA_44, v2p7_ek_mldsa44, V2P7_EK_MLDSA44_LEN);
    check_one(&dev, "ML-DSA-65 EK", HANDLE_EK_MLDSA_65, v2p7_ek_mldsa65, V2P7_EK_MLDSA65_LEN);
    check_one(&dev, "ML-DSA-87 EK", HANDLE_EK_MLDSA_87, v2p7_ek_mldsa87, V2P7_EK_MLDSA87_LEN);

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
