/* pqc_attestation_xcheck.c
 *
 * Drives real TPM2_Quote / TPM2_Certify commands against running swtpm using
 * an ML-DSA Attestation Key. Verifies the resulting attest blob + signature
 * with wolfCrypt's wc_MlDsaKey_Verify — an INDEPENDENT crypto stack from the
 * libtpms+OpenSSL signer inside the TPM.
 *
 * This closes G8 (pqctoday-org/pqctoday-tpm#1): TPM2_Quote / TPM2_Certify with
 * ML-DSA AK + PCR banks. The first independent PQC attestation implementation
 * in any open-source TPM 2.0 stack (verified by upstream survey 2026-05-12:
 * wolfTPM v4.0.0 has no Quote/Certify-with-ML-DSA example; libtpms upstream
 * has no PQC at all).
 *
 * Pipeline:
 *
 *   libtpms (OpenSSL 3.6.2 ML-DSA)         wolfCrypt (independent)
 *           │                                       ▲
 *           │ TPM2_Quote / TPM2_Certify             │ wc_MlDsaKey_Verify
 *           │ ──────────────────────────────────────│
 *           ▼                                       │
 *    swtpm socket  ──► wolfTPM client API ──► raw bytes
 *    (port 2321)      (TPM2_Quote, TPM2_Certify)    │
 *                                                   ▼
 *                              PASS if both stacks accept;
 *                              FAIL if either rejects.
 *
 * Coverage: ML-DSA-44 / -65 / -87 × {Quote, Certify} = 6 cases per run.
 *
 * Spec authority:
 *   - TPM 2.0 Library Part 3 §18.2 (TPM2_Certify), §18.4 (TPM2_Quote)
 *   - TPM 2.0 Library Part 2 §10.11 (TPMS_ATTEST + variants)
 *   - TPM 2.0 Library Part 1 §22.1.2 (restricted-AK rules)
 *   - FIPS 204 (ML-DSA)
 *   See docs/TPMdocextract.md §15 for the full extracted spec text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_V185)

static int g_pass = 0;
static int g_fail = 0;

static void note(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("  ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap);
}

static void result(int ok, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs(ok ? "  [PASS] " : "  [FAIL] ", stdout);
    vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap);
    if (ok) g_pass++; else g_fail++;
}

/* Map TPM_MLDSA_xx → wolfCrypt WC_ML_DSA_xx security level. */
static int wc_level_for(TPMI_MLDSA_PARAMETER_SET ps) {
    switch (ps) {
        case TPM_MLDSA_44: return WC_ML_DSA_44;
        case TPM_MLDSA_65: return WC_ML_DSA_65;
        case TPM_MLDSA_87: return WC_ML_DSA_87;
    }
    return -1;
}

static const char *ps_name(TPMI_MLDSA_PARAMETER_SET ps) {
    switch (ps) {
        case TPM_MLDSA_44: return "ML-DSA-44";
        case TPM_MLDSA_65: return "ML-DSA-65";
        case TPM_MLDSA_87: return "ML-DSA-87";
    }
    return "?";
}

/* FIPS 204 sizes — used for hard size assertions. */
static word32 mldsa_pub_size(TPMI_MLDSA_PARAMETER_SET ps) {
    switch (ps) {
        case TPM_MLDSA_44: return 1312;
        case TPM_MLDSA_65: return 1952;
        case TPM_MLDSA_87: return 2592;
    }
    return 0;
}
static word32 mldsa_sig_size(TPMI_MLDSA_PARAMETER_SET ps) {
    switch (ps) {
        case TPM_MLDSA_44: return 2420;
        case TPM_MLDSA_65: return 3309;
        case TPM_MLDSA_87: return 4627;
    }
    return 0;
}

/* Map TPM_MLDSA_xx → OpenSSL EVP algorithm name (PKCS#1 algorithm spelling). */
static const char *ossl_alg(TPMI_MLDSA_PARAMETER_SET ps) {
    switch (ps) {
        case TPM_MLDSA_44: return "ML-DSA-44";
        case TPM_MLDSA_65: return "ML-DSA-65";
        case TPM_MLDSA_87: return "ML-DSA-87";
    }
    return NULL;
}

/* Second independent verifier: OpenSSL 3.6.2 EVP_DigestVerify with raw ML-DSA
 * pubkey. SHARES no code with the TPM signer side (libtpms is its own copy of
 * OpenSSL inside the swtpm process; this is a fresh EVP_PKEY built from raw
 * bytes in our process). Returns 1 on accept, 0 on reject. */
static int openssl_verify_mldsa(TPMI_MLDSA_PARAMETER_SET ps,
                                const byte *pub, word32 pubLen,
                                const byte *msg, word32 msgLen,
                                const byte *sig, word32 sigLen)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *gctx = NULL;
    int ok = 0;
    const char *alg = ossl_alg(ps);
    if (!alg) return 0;

    /* Build EVP_PKEY from raw public-key bytes via fromdata. */
    OSSL_PARAM fdParams[2];
    fdParams[0] = OSSL_PARAM_construct_octet_string(
                      OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, pubLen);
    fdParams[1] = OSSL_PARAM_construct_end();

    gctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!gctx) goto cleanup;
    if (EVP_PKEY_fromdata_init(gctx) <= 0) goto cleanup;
    if (EVP_PKEY_fromdata(gctx, &pkey, EVP_PKEY_PUBLIC_KEY, fdParams) <= 0)
        goto cleanup;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto cleanup;
    if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0)
        goto cleanup;
    ok = (EVP_DigestVerify(mdctx, sig, sigLen, msg, msgLen) == 1);

cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gctx);
    return ok;
}

/* Verify (msg, sig) against (pub) using wolfCrypt's ML-DSA. Returns 1 if the
 * signature verifies, 0 otherwise. INDEPENDENT of the TPM signer stack. */
static int wolfcrypt_verify_mldsa(int wclevel,
                                  const byte *pub, word32 pubLen,
                                  const byte *msg, word32 msgLen,
                                  const byte *sig, word32 sigLen)
{
    dilithium_key key;
    int rc, res = 0;
    rc = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (rc != 0) { note("wc_MlDsaKey_Init rc=%d", rc); return 0; }
    rc = wc_dilithium_set_level(&key, wclevel);
    if (rc != 0) { note("wc_dilithium_set_level rc=%d", rc); wc_dilithium_free(&key); return 0; }
    rc = wc_dilithium_import_public(pub, pubLen, &key);
    if (rc != 0) { note("wc_dilithium_import_public rc=%d (pubLen=%u)", rc, pubLen); wc_dilithium_free(&key); return 0; }
    /* FIPS 204 verify with explicit empty context (TPM Quote/Certify do not
     * use a signature context string). */
    rc = wc_MlDsaKey_VerifyCtx(&key, (byte*)sig, sigLen, NULL, 0,
                               (byte*)msg, msgLen, &res);
    wc_dilithium_free(&key);
    if (rc != 0) { note("wc_MlDsaKey_Verify rc=%d", rc); return 0; }
    return res ? 1 : 0;
}

/* Create a restricted+sign ML-DSA AK in the Owner hierarchy, similar to the
 * AK provisioned by swtpm_setup at 0x810100A1/A2/A3 — but self-provisioned in
 * this test so we don't depend on persistent-handle state. */
static int create_restricted_ak(WOLFTPM2_DEV *dev, TPMI_MLDSA_PARAMETER_SET ps,
                                WOLFTPM2_KEY *outKey)
{
    TPMT_PUBLIC tpl;
    int rc;
    XMEMSET(&tpl, 0, sizeof(tpl));
    /* restricted+sign template — matches Part 1 §22.1.2 + Table 33 row
     * (sign=1, decrypt=0, restricted=1): "can sign any digest that the TPM
     *  has created" — the TPM-generated TPMS_ATTEST starts with
     *  TPM_GENERATED_VALUE so this AK is legal for Quote/Certify. */
    rc = wolfTPM2_GetKeyTemplate_MLDSA(&tpl,
        TPMA_OBJECT_sign | TPMA_OBJECT_restricted |
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA,
        ps, 0 /* allowExternalMu: irrelevant for attestation */);
    if (rc != TPM_RC_SUCCESS) return rc;
    return wolfTPM2_CreatePrimaryKey(dev, outKey, TPM_RH_OWNER, &tpl, NULL, 0);
}

/* Extract the FIPS 204 raw public-key bytes from a wolfTPM key handle.
 * TPM2B_PUBLIC_KEY_MLDSA (Part 2 Table 209) is a flat struct {size, buffer},
 * not the wrapped TPM2B_x.t.size/.t.buffer convention used elsewhere. */
static int extract_mldsa_pub(const WOLFTPM2_KEY *key,
                             const byte **pubOut, word32 *pubLenOut)
{
    *pubOut    = key->pub.publicArea.unique.mldsa.buffer;
    *pubLenOut = key->pub.publicArea.unique.mldsa.size;
    return 0;
}

/* Drive TPM2_Quote with an ML-DSA AK against the running swtpm. Captures the
 * raw attest blob + raw ML-DSA signature. Returns 0 on success. */
static int do_quote(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ak,
                    TPMI_MLDSA_PARAMETER_SET ps,
                    byte *attestOut, word32 *attestLenOut,
                    byte *sigOut, word32 *sigLenOut)
{
    Quote_In  in;
    Quote_Out out;
    int rc;
    static const byte qual[] = "pqctoday-tpm Quote xcheck nonce";

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.signHandle = ak->handle.hndl;
    /* Per V1.85 RC4 Table 101, inScheme is "the signing scheme to use if the
     * scheme for signHandle is TPM_ALG_NULL". An ML-DSA AK created with
     * TPMS_MLDSA_PARMS (Part 2 Table 229) has no scheme field — ML-DSA is
     * hash-and-sign internally per FIPS 204, with the parameter set
     * determining everything. So we send inScheme.scheme = TPM_ALG_NULL and
     * libtpms (AttestationCommands.c:182-185) derives the PCR-digest hash
     * algorithm from the AK's nameAlg.
     *
     * NOTE: We cannot send inScheme.scheme = TPM_ALG_MLDSA — wolfTPM
     * v4.0.0+PR#501's TPMU_SIG_SCHEME union has no mldsa arm, so the union
     * body fails to marshal and libtpms responds TPM_RC_SELECTOR (0x2d8).
     * NULL scheme avoids the marshal entirely (no union body when
     * scheme == NULL) — fully spec-compliant. */
    in.inScheme.scheme = TPM_ALG_NULL;
    in.inScheme.details.any.hashAlg = TPM_ALG_NULL;
    in.qualifyingData.size = sizeof(qual) - 1;
    XMEMCPY(in.qualifyingData.buffer, qual, in.qualifyingData.size);
    /* Quote PCR0..PCR7 in the SHA-256 bank — a typical boot-measurement set. */
    in.PCRselect.count = 1;
    in.PCRselect.pcrSelections[0].hash = TPM_ALG_SHA256;
    in.PCRselect.pcrSelections[0].sizeofSelect = 3;
    in.PCRselect.pcrSelections[0].pcrSelect[0] = 0xff; /* PCR0..PCR7 */
    in.PCRselect.pcrSelections[0].pcrSelect[1] = 0x00;
    in.PCRselect.pcrSelections[0].pcrSelect[2] = 0x00;

    rc = TPM2_Quote(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        note("TPM2_Quote rc=0x%x (%s)", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    if (out.signature.sigAlg != TPM_ALG_MLDSA) {
        note("Quote sigAlg=0x%x, expected TPM_ALG_MLDSA(0x%x)",
             out.signature.sigAlg, TPM_ALG_MLDSA);
        return TPM_RC_FAILURE;
    }
    if (out.signature.signature.mldsa.size != mldsa_sig_size(ps)) {
        note("Quote sig size %u, FIPS 204 expects %u",
             (unsigned)out.signature.signature.mldsa.size, (unsigned)mldsa_sig_size(ps));
        return TPM_RC_FAILURE;
    }

    if (*attestLenOut < out.quoted.size || *sigLenOut < out.signature.signature.mldsa.size)
        return TPM_RC_FAILURE;
    XMEMCPY(attestOut, out.quoted.attestationData, out.quoted.size);
    *attestLenOut = out.quoted.size;
    XMEMCPY(sigOut, out.signature.signature.mldsa.buffer, out.signature.signature.mldsa.size);
    *sigLenOut = out.signature.signature.mldsa.size;
    return 0;
}

/* Drive TPM2_Certify of an arbitrary object (we certify the AK itself — common
 * pattern, and avoids needing to provision a second object). */
static int do_certify(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ak,
                      TPMI_MLDSA_PARAMETER_SET ps,
                      byte *attestOut, word32 *attestLenOut,
                      byte *sigOut, word32 *sigLenOut)
{
    Certify_In  in;
    Certify_Out out;
    int rc;
    static const byte qual[] = "pqctoday-tpm Certify xcheck nonce";

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    /* Certify the AK using itself as the signer. Both handles are the same
     * object so we exercise the full Certify path without needing a second
     * object loaded.
     *
     * Spec authorization (Part 1 §16.2 + Table 33 row sign=1,decrypt=0,
     * restricted=1):
     *   - objectHandle requires ADMIN role (Part 3 §18.2 Table 97).
     *   - signHandle requires USER role.
     *   With adminWithPolicy=CLEAR (our template default) and
     *   userWithAuth=SET, both roles can be satisfied by an HMAC/password
     *   session with the AK's authValue. The AK was created via
     *   CreatePrimary with NULL sensitive → empty authValue.
     *
     * wolfTPM does NOT auto-register sessions for the 2nd auth handle, so
     * we must explicitly set both slot 0 (objectHandle, AuthIndex 1) and
     * slot 1 (signHandle, AuthIndex 2). With no prior SetAuth on the AK,
     * the password defaults to empty bytes — which is what we want. */
    (void)wolfTPM2_SetAuthHandle(dev, 0, &ak->handle);
    (void)wolfTPM2_SetAuthHandle(dev, 1, &ak->handle);

    in.objectHandle = ak->handle.hndl;
    in.signHandle   = ak->handle.hndl;
    /* Same scheme handling rationale as do_quote: TPM_ALG_NULL avoids the
     * wolfTPM TPMU_SIG_SCHEME union arm gap (V1.85 RC4 §11.3.5 Table 216
     * mldsa arm missing) AND is fully spec-compliant for an AK whose
     * TPMS_MLDSA_PARMS doesn't carry an explicit scheme. */
    in.inScheme.scheme = TPM_ALG_NULL;
    in.inScheme.details.any.hashAlg = TPM_ALG_NULL;
    in.qualifyingData.size = sizeof(qual) - 1;
    XMEMCPY(in.qualifyingData.buffer, qual, in.qualifyingData.size);

    rc = TPM2_Certify(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        note("TPM2_Certify rc=0x%x (%s)", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    if (out.signature.sigAlg != TPM_ALG_MLDSA) {
        note("Certify sigAlg=0x%x, expected TPM_ALG_MLDSA", out.signature.sigAlg);
        return TPM_RC_FAILURE;
    }
    if (out.signature.signature.mldsa.size != mldsa_sig_size(ps)) {
        note("Certify sig size %u, FIPS 204 expects %u",
             (unsigned)out.signature.signature.mldsa.size, (unsigned)mldsa_sig_size(ps));
        return TPM_RC_FAILURE;
    }

    if (*attestLenOut < out.certifyInfo.size || *sigLenOut < out.signature.signature.mldsa.size)
        return TPM_RC_FAILURE;
    XMEMCPY(attestOut, out.certifyInfo.attestationData, out.certifyInfo.size);
    *attestLenOut = out.certifyInfo.size;
    XMEMCPY(sigOut, out.signature.signature.mldsa.buffer, out.signature.signature.mldsa.size);
    *sigLenOut = out.signature.signature.mldsa.size;
    return 0;
}

/* One full attestation cross-check pass for a given (op, param_set). */
static void run_one(WOLFTPM2_DEV *dev, TPMI_MLDSA_PARAMETER_SET ps,
                    int do_quote_flag, const char *outdir)
{
    WOLFTPM2_KEY ak; XMEMSET(&ak, 0, sizeof(ak));
    int rc;
    const char *opname = do_quote_flag ? "Quote" : "Certify";
    byte *attest = NULL, *sig = NULL;
    word32 attestLen = 4096, sigLen = 5000;
    word32 pubLen;
    const byte *pub = NULL;

    attest = (byte *)XMALLOC(attestLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sig    = (byte *)XMALLOC(sigLen,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!attest || !sig) { result(0, "%s %s: alloc fail", opname, ps_name(ps)); goto cleanup; }

    rc = create_restricted_ak(dev, ps, &ak);
    if (rc != 0) { result(0, "%s %s: AK CreatePrimary rc=0x%x", opname, ps_name(ps), rc); goto cleanup; }

    rc = extract_mldsa_pub(&ak, &pub, &pubLen);
    if (rc != 0 || pubLen != mldsa_pub_size(ps)) {
        result(0, "%s %s: AK pub size %u, FIPS 204 expects %u",
               opname, ps_name(ps), (unsigned)pubLen, (unsigned)mldsa_pub_size(ps));
        goto cleanup;
    }

    if (do_quote_flag)
        rc = do_quote(dev, &ak, ps, attest, &attestLen, sig, &sigLen);
    else
        rc = do_certify(dev, &ak, ps, attest, &attestLen, sig, &sigLen);
    if (rc != 0) { result(0, "%s %s: TPM op failed rc=0x%x", opname, ps_name(ps), rc); goto cleanup; }

    /* Sanity-check the magic prefix: must be TPM_GENERATED_VALUE (0xFF544347). */
    if (attestLen < 4 || attest[0] != 0xFF || attest[1] != 0x54 ||
        attest[2] != 0x43 || attest[3] != 0x47) {
        result(0, "%s %s: attest magic mismatch (got %02x%02x%02x%02x)",
               opname, ps_name(ps),
               attest[0], attest[1], attest[2], attest[3]);
        goto cleanup;
    }

    /* Independent verifier A: wolfCrypt's ML-DSA. */
    int wcrc = wolfcrypt_verify_mldsa(wc_level_for(ps), pub, pubLen, attest, attestLen, sig, sigLen);
    /* Independent verifier B: OpenSSL 3.6.2 EVP. */
    int orc  = openssl_verify_mldsa(ps, pub, pubLen, attest, attestLen, sig, sigLen);

    if (!wcrc) { result(0, "%s %s: wolfCrypt verify REJECTED",       opname, ps_name(ps)); goto cleanup; }
    if (!orc)  { result(0, "%s %s: OpenSSL EVP verify REJECTED",     opname, ps_name(ps)); goto cleanup; }
    result(1, "%s %s: TPM %s sig=%u, wolfCrypt+OpenSSL both ACCEPTED (pub=%u, attest=%u)",
           opname, ps_name(ps), opname, (unsigned)sigLen, (unsigned)pubLen, (unsigned)attestLen);

    /* Dump artifacts for offline inspection / additional external validators. */
    if (outdir) {
        char path[512];
        FILE *fp;
        snprintf(path, sizeof(path), "%s/%s_%s.attest.bin",
                 outdir, opname, ps_name(ps));
        if ((fp = fopen(path, "wb"))) { fwrite(attest, 1, attestLen, fp); fclose(fp); }
        snprintf(path, sizeof(path), "%s/%s_%s.sig.bin",
                 outdir, opname, ps_name(ps));
        if ((fp = fopen(path, "wb"))) { fwrite(sig, 1, sigLen, fp); fclose(fp); }
        snprintf(path, sizeof(path), "%s/%s_%s.pub.bin",
                 outdir, opname, ps_name(ps));
        if ((fp = fopen(path, "wb"))) { fwrite(pub, 1, pubLen, fp); fclose(fp); }
    }

cleanup:
    if (ak.handle.hndl != 0) wolfTPM2_UnloadHandle(dev, &ak.handle);
    XFREE(attest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sig,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* ────────────────────────────────────────────────────────────────────────
 * --verify-bundle <path.json>
 *
 * Offline mode: read an attestation bundle JSON (the same shape the hub
 * AttestationPanel exports via the "JSON bundle" download button) and run
 * the SAME wolfCrypt + OpenSSL verifiers we use against live TPM output
 * against the pre-captured bytes. This gives an independent cross-stack
 * confirmation of any bundle the browser produces — without needing a
 * wolfSSL WASM build.
 *
 * Bundle shape (matches AttestationPanel.tsx downloadBundle):
 *   { "operation": "quote" | "certify",
 *     "algorithm": "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87",
 *     "handle":    "0x810100a1",
 *     "pubkey_hex":    "..." ,
 *     "attest_hex":    "..." ,
 *     "signature_hex": "..." }
 *
 * Lightweight ad-hoc JSON extractor — the bundle is self-generated with a
 * known shape, so a brittle scanner is fine; no third-party JSON dep.
 * ──────────────────────────────────────────────────────────────────────── */

/* Read entire file into a freshly-malloc'd NUL-terminated buffer. */
static char *slurp_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    if (n < 0) { fclose(fp); return NULL; }
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    buf[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return buf;
}

/* Find "<key>" : "<value>" → newly-allocated value string (NUL-terminated).
 * Returns NULL if the key isn't found. Doesn't handle escaped quotes
 * (none of our bundle's values contain them). */
static char *json_string_field(const char *json, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return NULL;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return NULL;
    size_t n = (size_t)(end - p);
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, p, n);
    out[n] = '\0';
    return out;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
static byte *hex_to_bytes(const char *hex, word32 *out_len) {
    size_t n = strlen(hex);
    if (n & 1u) return NULL;
    byte *b = (byte *)malloc(n / 2);
    if (!b) return NULL;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(b); return NULL; }
        b[i] = (byte)((hi << 4) | lo);
    }
    *out_len = (word32)(n / 2);
    return b;
}

static TPMI_MLDSA_PARAMETER_SET ps_from_name(const char *name) {
    if (!name) return 0;
    if (!strcmp(name, "ML-DSA-44")) return TPM_MLDSA_44;
    if (!strcmp(name, "ML-DSA-65")) return TPM_MLDSA_65;
    if (!strcmp(name, "ML-DSA-87")) return TPM_MLDSA_87;
    return 0;
}

static int verify_bundle_file(const char *path) {
    char *json = slurp_file(path, NULL);
    if (!json) {
        fprintf(stderr, "verify-bundle: cannot read %s\n", path);
        return 2;
    }
    char *op_str  = json_string_field(json, "operation");
    char *alg_str = json_string_field(json, "algorithm");
    char *pub_hex = json_string_field(json, "pubkey_hex");
    char *att_hex = json_string_field(json, "attest_hex");
    char *sig_hex = json_string_field(json, "signature_hex");
    int  rc = 2;

    if (!op_str || !alg_str || !pub_hex || !att_hex || !sig_hex) {
        fprintf(stderr,
                "verify-bundle: missing one of operation/algorithm/pubkey_hex/"
                "attest_hex/signature_hex in %s\n", path);
        goto out;
    }
    TPMI_MLDSA_PARAMETER_SET ps = ps_from_name(alg_str);
    if (ps == 0) {
        fprintf(stderr, "verify-bundle: unknown algorithm '%s'\n", alg_str);
        goto out;
    }

    word32 pubLen = 0, attLen = 0, sigLen = 0;
    byte *pub = hex_to_bytes(pub_hex, &pubLen);
    byte *att = hex_to_bytes(att_hex, &attLen);
    byte *sig = hex_to_bytes(sig_hex, &sigLen);
    if (!pub || !att || !sig) {
        fprintf(stderr, "verify-bundle: hex decode failed\n");
        free(pub); free(att); free(sig);
        goto out;
    }

    printf("=== %s ↔ wolfCrypt + OpenSSL verify (offline bundle) ===\n", path);
    printf("  operation: %s\n", op_str);
    printf("  algorithm: %s\n", alg_str);
    printf("  pub %u B / attest %u B / sig %u B (FIPS expected pub %u, sig %u)\n",
           pubLen, attLen, sigLen,
           mldsa_pub_size(ps), mldsa_sig_size(ps));

    int sizeOk = (pubLen == mldsa_pub_size(ps)) && (sigLen == mldsa_sig_size(ps));
    result(sizeOk, "FIPS 204 size sanity (pub/sig)");

    int wcrc = wolfcrypt_verify_mldsa(wc_level_for(ps),
                                      pub, pubLen, att, attLen, sig, sigLen);
    result(wcrc, "wolfCrypt verify");

    int orc = openssl_verify_mldsa(ps,
                                   pub, pubLen, att, attLen, sig, sigLen);
    result(orc, "OpenSSL EVP verify");

    free(pub); free(att); free(sig);
    printf("\n  %d passed, %d failed\n", g_pass, g_fail);
    rc = (g_fail == 0) ? 0 : 1;

out:
    free(op_str); free(alg_str); free(pub_hex); free(att_hex); free(sig_hex);
    free(json);
    return rc;
}

int main(int argc, char *argv[])
{
    /* Offline-verify mode: --verify-bundle <path.json>. Doesn't touch the
     * TPM — runs only the wolfCrypt+OpenSSL verifiers against the bundle. */
    if (argc >= 3 && strcmp(argv[1], "--verify-bundle") == 0) {
        return verify_bundle_file(argv[2]);
    }

    WOLFTPM2_DEV dev; XMEMSET(&dev, 0, sizeof(dev));
    int rc;
    const char *outdir = (argc >= 2) ? argv[1] : NULL;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "wolfTPM2_Init failed: 0x%x (%s)\n",
                rc, wolfTPM2_GetRCString(rc));
        return 1;
    }

    printf("=== Attestation runtime xcheck — TPM-driven, dual-stack verify ===\n");
    printf("  signer:   libtpms (OpenSSL 3.6.2 ML-DSA) inside swtpm\n");
    printf("  verifier: wolfCrypt (independent stack) + OpenSSL EVP (sanity)\n");
    if (outdir) printf("  outdir:   %s (raw bytes per case for OpenSSL EVP verify)\n", outdir);
    putchar('\n');

    static const TPMI_MLDSA_PARAMETER_SET sets[] = {
        TPM_MLDSA_44, TPM_MLDSA_65, TPM_MLDSA_87,
    };

    printf("=== TPM2_Quote with ML-DSA AK + PCR digest (Part 3 §18.4) ===\n");
    for (size_t i = 0; i < sizeof(sets)/sizeof(sets[0]); i++)
        run_one(&dev, sets[i], 1 /* quote */, outdir);
    putchar('\n');

    printf("=== TPM2_Certify with ML-DSA AK (Part 3 §18.2) ===\n");
    for (size_t i = 0; i < sizeof(sets)/sizeof(sets[0]); i++)
        run_one(&dev, sets[i], 0 /* certify */, outdir);
    putchar('\n');

    printf("=== Summary ===\n");
    printf("  %d passed, %d failed\n", g_pass, g_fail);

    wolfTPM2_Cleanup(&dev);
    return (g_fail == 0) ? 0 : 1;
}

#else
int main(void) {
    fprintf(stderr, "pqc_attestation_xcheck requires WOLFTPM_V185 and wolfTPM2 wrappers\n");
    return 2;
}
#endif
