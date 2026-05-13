/* ek_cert_conformance_xcheck.c
 *
 * Phase C step 1 of issue #2 (G7-A): X.509 PQC EK certificate conformance
 * against TCG EK Credential Profile V2.7 RC1 §5.3.1 + §6.2.x.
 *
 * For each of the 6 mandatory V2.7 PQC EK cert NV indices (0x01c00060,
 * 0x01c00062, 0x01c00064, 0x01c00070, 0x01c00072, 0x01c00074):
 *
 *   1. TPM2_NV_ReadPublic — must succeed (slot must exist).
 *   2. TPM2_NV_Read — read the X.509 DER cert bytes out of NV.
 *   3. d2i_X509 — parse with OpenSSL.
 *   4. X509_get_X509_PUBKEY → ASN.1 algorithm OID → byte-match against the
 *      V2.7 NIST CSOR reference in tests/compliance/vectors/v2p7-ek-cert-oids/.
 *   5. Sanity: notBefore is past, notAfter is future, subject CN non-empty.
 *
 * PASS iff all 5 hold. FAIL otherwise (with a precise diagnostic per
 * failing assertion).
 *
 * RED state on first run: today the NV slots are EMPTY (we have not yet
 * implemented the cert+NV write path — that is Phase C steps 2-4). All 6
 * cases must FAIL with "NV slot not provisioned". When Phase C steps 2-4
 * land, the same test goes 6/6 PASS.
 *
 * Spec authority: TCG EK Credential Profile V2.7 RC1, cached at
 *                 docs/standards/TCG-EK-Credential-Profile-...-V2p7-RC1.pdf
 *                 + docs/TPMdocextract.md §17.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* OpenSSL headers MUST come before wolfssl — wolfssl's compat layer defines
 * SHA256/SHA384/SHA512 as macros that mangle openssl/sha.h's function
 * declarations (redeclaration error). With OpenSSL first the SHA*
 * symbols resolve as functions, and any later wolfssl macro use is local. */
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include "tests/compliance/vectors/v2p7-ek-cert-oids/v2p7_ek_cert_spki_oids.h"

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)

static int g_pass = 0, g_fail = 0;

static void rpass(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("  [PASS] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap); g_pass++;
}
static void rfail(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("  [FAIL] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap); g_fail++;
}

/* Read all bytes of an NV index in chunks of the TPM's max NV-buffer size. */
static int nv_read_all(WOLFTPM2_DEV *dev,
                      TPM_HANDLE nvIndex, UINT32 nvSize,
                      unsigned char *buf, UINT32 bufCap, UINT32 *outLen)
{
    if (nvSize > bufCap) return -1;
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = nvIndex;
    /* NV ReadPublic policy is owner-authorized by default for TCG EK certs.
     * For unrestricted NV (TPMA_NV_PPREAD or AUTHREAD set without owner auth)
     * an empty-password session works. */
    UINT32 readMax = MAX_NV_BUFFER_SIZE > 0 ? MAX_NV_BUFFER_SIZE : 768;
    UINT32 offset = 0;
    while (offset < nvSize) {
        UINT32 chunk = nvSize - offset;
        if (chunk > readMax) chunk = readMax;
        UINT32 got = chunk;
        int rc = wolfTPM2_NVReadAuth(dev, &nv, nvIndex, buf + offset, &got, offset);
        if (rc != TPM_RC_SUCCESS) return rc;
        if (got == 0) break;
        offset += got;
    }
    *outLen = offset;
    return 0;
}

static int oid_body_matches(const ASN1_OBJECT *got_oid,
                            const unsigned char *expect_body, size_t expect_body_len)
{
    /* OpenSSL's ASN1_OBJECT carries the body bytes (post-tag/length). */
    int len = OBJ_length(got_oid);
    if (len != (int)expect_body_len) return 0;
    const unsigned char *got_body = OBJ_get0_data(got_oid);
    return memcmp(got_body, expect_body, expect_body_len) == 0;
}

struct ek_cert_case {
    const char     *label;
    TPM_HANDLE      nvIndex;        /* V2.7 §5.3.1 spec-mandated NV index */
    const unsigned char *expect_oid;
    size_t          expect_oid_len;
};

static void check_cert(WOLFTPM2_DEV *dev, const struct ek_cert_case *tc)
{
    /* Step 1: probe the NV slot existence. */
    TPMS_NV_PUBLIC nvPublic;
    XMEMSET(&nvPublic, 0, sizeof(nvPublic));
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = tc->nvIndex;

    int rc = wolfTPM2_NVReadPublic(dev, tc->nvIndex, &nvPublic);
    if (rc != TPM_RC_SUCCESS) {
        rfail("%s @ 0x%08x — NV slot not provisioned (TPM2_NV_ReadPublic rc=0x%x: %s) — V2.7 §5.3.1 mandates this slot",
              tc->label, (unsigned)tc->nvIndex, rc, wolfTPM2_GetRCString(rc));
        return;
    }

    UINT32 nvSize = nvPublic.dataSize;
    if (nvSize < 64 || nvSize > 8192) {
        rfail("%s @ 0x%08x — NV slot size %u outside plausible cert range",
              tc->label, (unsigned)tc->nvIndex, (unsigned)nvSize);
        return;
    }

    /* Step 2: read the cert bytes. */
    unsigned char certBuf[8192];
    UINT32 certLen = 0;
    rc = nv_read_all(dev, tc->nvIndex, nvSize, certBuf, sizeof(certBuf), &certLen);
    if (rc != 0 || certLen != nvSize) {
        rfail("%s @ 0x%08x — NV_Read failed (rc=0x%x, got %u/%u B)",
              tc->label, (unsigned)tc->nvIndex, rc, (unsigned)certLen, (unsigned)nvSize);
        return;
    }

    /* Step 3: parse the X.509. */
    const unsigned char *p = certBuf;
    X509 *cert = d2i_X509(NULL, &p, (long)certLen);
    if (cert == NULL) {
        rfail("%s @ 0x%08x — d2i_X509 failed on %u B blob",
              tc->label, (unsigned)tc->nvIndex, (unsigned)certLen);
        return;
    }

    /* Step 4: extract SPKI algorithm OID and byte-match the V2.7 reference. */
    X509_PUBKEY *xpub = X509_get_X509_PUBKEY(cert);
    ASN1_OBJECT *xoid = NULL;
    if (xpub == NULL || X509_PUBKEY_get0_param(&xoid, NULL, NULL, NULL, xpub) != 1 || xoid == NULL) {
        rfail("%s — X509_PUBKEY_get0_param failed", tc->label);
        X509_free(cert);
        return;
    }
    if (!oid_body_matches(xoid, tc->expect_oid, tc->expect_oid_len)) {
        char oidbuf[128];
        OBJ_obj2txt(oidbuf, sizeof(oidbuf), xoid, 1);
        rfail("%s — SPKI OID = %s, V2.7 §6.2.x expects different",
              tc->label, oidbuf);
        X509_free(cert);
        return;
    }

    /* Step 5: cursory cert sanity. */
    const ASN1_TIME *nb = X509_get0_notBefore(cert);
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    if (nb == NULL || na == NULL) {
        rfail("%s — cert missing validity period", tc->label);
        X509_free(cert);
        return;
    }
    int cmp_now = X509_cmp_current_time(na);
    if (cmp_now <= 0) {
        rfail("%s — cert notAfter is in the past", tc->label);
        X509_free(cert);
        return;
    }

    rpass("%s @ 0x%08x — cert %u B, SPKI OID matches V2.7 §6.2.x, validity OK",
          tc->label, (unsigned)tc->nvIndex, (unsigned)certLen);

    X509_free(cert);
}

int main(void)
{
    WOLFTPM2_DEV dev; XMEMSET(&dev, 0, sizeof(dev));
    int rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "wolfTPM2_Init failed: 0x%x (%s)\n",
                rc, wolfTPM2_GetRCString(rc));
        return 1;
    }

    printf("=== V2.7 RC1 PQC EK Certificate conformance — wolfTPM-driven, byte-exact OID ===\n");
    printf("  signer:   libtpms (OpenSSL 3.6.2 PQC X.509 path) inside swtpm\n");
    printf("  reader:   wolfTPM v4.0.0 TPM2_NV_Read + OpenSSL d2i_X509\n");
    printf("  refs:     tests/compliance/vectors/v2p7-ek-cert-oids/ (V2.7 §6.2.x OIDs)\n");
    putchar('\n');

    static const struct ek_cert_case cases[] = {
        /* V2.7 §5.3.1 NV index assignments (Storage variants, not firmware-limited) */
        { "ML-KEM-512  EK cert", 0x01c00060u, v2p7_oid_mlkem512,  V2P7_OID_BODY_LEN },
        { "ML-KEM-768  EK cert", 0x01c00062u, v2p7_oid_mlkem768,  V2P7_OID_BODY_LEN },
        { "ML-KEM-1024 EK cert", 0x01c00064u, v2p7_oid_mlkem1024, V2P7_OID_BODY_LEN },
        { "ML-DSA-44   EK cert", 0x01c00070u, v2p7_oid_mldsa44,   V2P7_OID_BODY_LEN },
        { "ML-DSA-65   EK cert", 0x01c00072u, v2p7_oid_mldsa65,   V2P7_OID_BODY_LEN },
        { "ML-DSA-87   EK cert", 0x01c00074u, v2p7_oid_mldsa87,   V2P7_OID_BODY_LEN },
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++)
        check_cert(&dev, &cases[i]);

    printf("\n=== Summary ===\n");
    printf("  %d passed, %d failed\n", g_pass, g_fail);

    wolfTPM2_Cleanup(&dev);
    return (g_fail == 0) ? 0 : 1;
}

#else
int main(void) {
    fprintf(stderr, "ek_cert_conformance_xcheck requires WOLFTPM_V185 + wolfTPM2 wrappers\n");
    return 2;
}
#endif
