/*
 * tpm_bench.c — parameterized TPM2_CreatePrimary harness for the
 * pqctoday-sandbox scenario 36 "TPM 2.0 → PQC Migration".
 *
 * Drives the real libtpms engine directly (no swtpm socket, no tpm2-tools)
 * to run TPM2_CreatePrimary across four TPM key roles
 *
 *     EK     (Endorsement hierarchy, restricted decrypt)
 *     SRK    (Owner hierarchy,       restricted decrypt)
 *     AIK    (Owner hierarchy,       restricted sign)
 *     IDevID (Owner hierarchy,       non-restricted sign)
 *
 * and four algorithm choices (two classical, two PQC from TCG V1.85)
 *
 *     rsa2048   TPM_ALG_RSA    keyBits=2048    (classical baseline)
 *     p256      TPM_ALG_ECC    NIST P-256      (classical baseline)
 *     mlkem768  TPM_ALG_MLKEM  0x00A0 / MLKEM_768  (FIPS 203)
 *     mldsa65   TPM_ALG_MLDSA  0x00A1 / MLDSA_65   (FIPS 204)
 *
 * Output: one JSON object per CreatePrimary call on stdout, e.g.
 *     {"role":"AIK","alg":"mldsa65","alg_id":"0x00A1",...,"pub_hex":"..."}
 * followed by a single-line summary. With --trace, the raw TPM command
 * and response bytes are emitted to stderr as hex before each op — the
 * sandbox Flask shim forwards these as a live wire trace to the UI.
 *
 * NV strategy matches test_tpm_roundtrip.c: file-backed NV in a mkdtemp()
 * directory so libtpms_plat__NVEnable_NVChipFile() short-circuits on the
 * second call and manufactured state is preserved.
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ─── TPM 2.0 constants (TCG V1.85 Parts 1–2) ─────────────────────── */
#define TPM_ST_NO_SESSIONS              0x8001
#define TPM_ST_SESSIONS                 0x8002
#define TPM_CC_Startup                  0x00000144
#define TPM_CC_CreatePrimary            0x00000131
#define TPM_CC_FlushContext             0x00000165
#define TPM_CC_Quote                    0x00000158

#define TPM_RH_OWNER                    0x40000001
#define TPM_RH_ENDORSEMENT              0x4000000B
#define TPM_RS_PW                       0x40000009

#define TPM_ALG_RSA                     0x0001
#define TPM_ALG_KEYEDHASH               0x0008
#define TPM_ALG_SHA256                  0x000B
#define TPM_ALG_AES                     0x0006
#define TPM_ALG_NULL                    0x0010
#define TPM_ALG_RSASSA                  0x0014
#define TPM_ALG_RSAES                   0x0015
#define TPM_ALG_ECDSA                   0x0018
#define TPM_ALG_ECDH                    0x0019
#define TPM_ALG_ECC                     0x0023
#define TPM_ALG_SYMCIPHER               0x0025
#define TPM_ALG_CFB                     0x0043
#define TPM_ALG_MLKEM                   0x00A0  /* TCG V1.85 RC4 via wolfTPM PR #445 */
#define TPM_ALG_MLDSA                   0x00A1

#define TPM_ECC_NIST_P256               0x0003
#define TPM_MLDSA_65                    0x0002
#define TPM_MLKEM_768                   0x0002

#define TPMA_OBJECT_FIXEDTPM            0x00000002
#define TPMA_OBJECT_FIXEDPARENT         0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN 0x00000020
#define TPMA_OBJECT_USERWITHAUTH        0x00000040
#define TPMA_OBJECT_ADMINWITHPOLICY     0x00000080
#define TPMA_OBJECT_NODA                0x00000400
#define TPMA_OBJECT_RESTRICTED          0x00010000
#define TPMA_OBJECT_DECRYPT             0x00020000
#define TPMA_OBJECT_SIGN                0x00040000

/* ─── Options ──────────────────────────────────────────────────────── */
typedef enum { ALG_RSA2048, ALG_P256, ALG_MLDSA65, ALG_MLKEM768, ALG_UNKNOWN } alg_t;
typedef enum { ROLE_EK, ROLE_SRK, ROLE_AIK, ROLE_IDEVID, ROLE_UNKNOWN } role_t;

typedef struct {
    role_t role;
    alg_t  alg;
} run_t;

static int g_trace = 0;
static int g_first_json = 1;     /* for comma separation in the summary array */

static const char *alg_name(alg_t a) {
    switch (a) {
    case ALG_RSA2048:  return "rsa2048";
    case ALG_P256:     return "p256";
    case ALG_MLDSA65:  return "mldsa65";
    case ALG_MLKEM768: return "mlkem768";
    default:           return "?";
    }
}
static const char *alg_display(alg_t a) {
    switch (a) {
    case ALG_RSA2048:  return "RSA-2048";
    case ALG_P256:     return "ECC NIST-P256";
    case ALG_MLDSA65:  return "ML-DSA-65";
    case ALG_MLKEM768: return "ML-KEM-768";
    default:           return "?";
    }
}
static const char *role_name(role_t r) {
    switch (r) {
    case ROLE_EK:     return "EK";
    case ROLE_SRK:    return "SRK";
    case ROLE_AIK:    return "AIK";
    case ROLE_IDEVID: return "IDevID";
    default:          return "?";
    }
}
static const char *role_description(role_t r) {
    switch (r) {
    case ROLE_EK:
        return "Endorsement Key — TPM identity, enrolled in vendor CA, used for Credential Activation";
    case ROLE_SRK:
        return "Storage Root Key — wraps child keys in NV, not exportable";
    case ROLE_AIK:
        return "Attestation Identity Key — restricted signer for TPM2_Quote";
    case ROLE_IDEVID:
        return "Device Identity Key — IEEE 802.1AR onboarding, non-restricted signer";
    default:
        return "?";
    }
}
static alg_t parse_alg(const char *s) {
    if (!strcmp(s, "rsa2048"))  return ALG_RSA2048;
    if (!strcmp(s, "p256"))     return ALG_P256;
    if (!strcmp(s, "mldsa65"))  return ALG_MLDSA65;
    if (!strcmp(s, "mlkem768")) return ALG_MLKEM768;
    return ALG_UNKNOWN;
}
static role_t parse_role(const char *s) {
    if (!strcasecmp(s, "EK"))     return ROLE_EK;
    if (!strcasecmp(s, "SRK"))    return ROLE_SRK;
    if (!strcasecmp(s, "AIK"))    return ROLE_AIK;
    if (!strcasecmp(s, "IDevID")) return ROLE_IDEVID;
    return ROLE_UNKNOWN;
}
static int alg_is_pqc(alg_t a) {
    return a == ALG_MLDSA65 || a == ALG_MLKEM768;
}
static int role_is_signer(role_t r) {
    return r == ROLE_AIK || r == ROLE_IDEVID;
}

/* ─── Byte packing helpers ────────────────────────────────────────── */
static uint8_t *put_u16(uint8_t *p, uint16_t v) {
    *p++ = (v >> 8) & 0xff; *p++ = v & 0xff; return p;
}
static uint8_t *put_u32(uint8_t *p, uint32_t v) {
    *p++ = (v >> 24) & 0xff; *p++ = (v >> 16) & 0xff;
    *p++ = (v >> 8)  & 0xff; *p++ = v & 0xff;
    return p;
}
static uint16_t get_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | p[3];
}
static void hex_to_string(const uint8_t *buf, size_t len, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = h[(buf[i] >> 4) & 0xf];
        out[i * 2 + 1] = h[buf[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/* Milli-precision monotonic time. */
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* Emit a trace line to stderr if --trace. Format: one JSON object per line
 * so the Flask SSE shim can forward raw. */
static void trace(const char *phase, const char *role, const char *alg,
                  const uint8_t *buf, uint32_t len) {
    if (!g_trace) return;
    fprintf(stderr, "{\"trace\":\"%s\",\"role\":\"%s\",\"alg\":\"%s\",\"len\":%u,\"hex\":\"",
            phase, role, alg, len);
    for (uint32_t i = 0; i < len; i++) fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, "\"}\n");
    fflush(stderr);
}

/* ─── Attribute templates per (role, alg) ─────────────────────────── */

static uint32_t attrs_for(role_t r, alg_t a) {
    uint32_t base = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                  | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    switch (r) {
    case ROLE_EK:
        /* Restricted decrypt with admin-policy auth (the canonical EK template
         * per TCG EK Credential Profile). For sign-only algs (ML-DSA), this
         * combo is not valid — but the sandbox never pairs EK with MLDSA. */
        return base | TPMA_OBJECT_ADMINWITHPOLICY
                    | TPMA_OBJECT_RESTRICTED
                    | TPMA_OBJECT_DECRYPT;
    case ROLE_SRK:
        return base | TPMA_OBJECT_USERWITHAUTH
                    | TPMA_OBJECT_NODA
                    | TPMA_OBJECT_RESTRICTED
                    | TPMA_OBJECT_DECRYPT;
    case ROLE_AIK:
        /* Restricted signer — used for TPM2_Quote. */
        return base | TPMA_OBJECT_USERWITHAUTH
                    | TPMA_OBJECT_RESTRICTED
                    | TPMA_OBJECT_SIGN;
    case ROLE_IDEVID:
        /* Non-restricted signer — can sign arbitrary data (per IEEE 802.1AR). */
        return base | TPMA_OBJECT_USERWITHAUTH
                    | TPMA_OBJECT_SIGN;
    default:
        return base;
    }
    (void)a;
}

static uint32_t hierarchy_for(role_t r) {
    return (r == ROLE_EK) ? TPM_RH_ENDORSEMENT : TPM_RH_OWNER;
}

/* ─── TPMT_PUBLIC builder per algorithm ───────────────────────────── */

/* Write a TPMT_SYM_DEF_OBJECT. For restricted decrypt keys the spec mandates
 * AES-128-CFB; for sign-only keys NULL. */
static uint8_t *emit_sym_def_obj(uint8_t *p, int aes_128_cfb) {
    if (aes_128_cfb) {
        p = put_u16(p, TPM_ALG_AES);
        p = put_u16(p, 128);           /* keyBits.aes */
        p = put_u16(p, TPM_ALG_CFB);   /* mode.aes */
    } else {
        p = put_u16(p, TPM_ALG_NULL);
    }
    return p;
}

/* Build a TPMT_PUBLIC for the (role, alg) pair. Returns bytes written. */
static uint32_t build_tpmt_public(uint8_t *buf, role_t r, alg_t a) {
    uint8_t *p = buf;
    uint16_t alg_type = 0;
    switch (a) {
    case ALG_RSA2048:  alg_type = TPM_ALG_RSA;   break;
    case ALG_P256:     alg_type = TPM_ALG_ECC;   break;
    case ALG_MLDSA65:  alg_type = TPM_ALG_MLDSA; break;
    case ALG_MLKEM768: alg_type = TPM_ALG_MLKEM; break;
    default: return 0;
    }
    p = put_u16(p, alg_type);
    p = put_u16(p, TPM_ALG_SHA256);            /* nameAlg */
    p = put_u32(p, attrs_for(r, a));           /* objectAttributes */
    p = put_u16(p, 0);                          /* authPolicy TPM2B (empty) */

    int restricted_decrypt = (r == ROLE_EK || r == ROLE_SRK);

    /* parms + unique — algorithm specific. */
    switch (a) {
    case ALG_RSA2048: {
        p = emit_sym_def_obj(p, restricted_decrypt);
        /* TPMT_RSA_SCHEME: sign-role uses RSASSA(SHA256), decrypt-role uses NULL. */
        if (role_is_signer(r)) {
            p = put_u16(p, TPM_ALG_RSASSA);
            p = put_u16(p, TPM_ALG_SHA256);
        } else {
            p = put_u16(p, TPM_ALG_NULL);
        }
        p = put_u16(p, 2048);                   /* keyBits */
        p = put_u32(p, 0);                      /* exponent=0 → default 65537 */
        /* unique: TPM2B_PUBLIC_KEY_RSA (empty for keygen). */
        p = put_u16(p, 0);
        break;
    }
    case ALG_P256: {
        p = emit_sym_def_obj(p, restricted_decrypt);
        /* TPMT_ECC_SCHEME */
        if (role_is_signer(r)) {
            p = put_u16(p, TPM_ALG_ECDSA);
            p = put_u16(p, TPM_ALG_SHA256);
        } else {
            p = put_u16(p, TPM_ALG_NULL);
        }
        p = put_u16(p, TPM_ECC_NIST_P256);      /* curveID */
        p = put_u16(p, TPM_ALG_NULL);            /* kdf (TPMT_KDF_SCHEME NULL) */
        /* unique: TPMS_ECC_POINT { x TPM2B=0, y TPM2B=0 }. */
        p = put_u16(p, 0);
        p = put_u16(p, 0);
        break;
    }
    case ALG_MLDSA65: {
        /* TPMS_MLDSA_PARMS (V1.85 RC4 Table 229): { parameterSet, allowExternalMu }.
         * allowExternalMu = YES so the IDevID role can use TPM2_SignDigest. */
        p = put_u16(p, TPM_MLDSA_65);
        *p++ = 1;                                /* allowExternalMu = YES */
        /* unique: TPM2B_PUBLIC_KEY_MLDSA (empty for keygen). */
        p = put_u16(p, 0);
        break;
    }
    case ALG_MLKEM768: {
        /* TPMS_MLKEM_PARMS (V1.85 RC4 Table 231): { symmetric, parameterSet }.
         * Restricted-decrypt EK requires AES-128-CFB; otherwise TPM_ALG_NULL. */
        int restricted_decrypt = (r == ROLE_EK || r == ROLE_SRK);
        p = emit_sym_def_obj(p, restricted_decrypt);
        p = put_u16(p, TPM_MLKEM_768);
        p = put_u16(p, 0);
        break;
    }
    default: return 0;
    }
    return (uint32_t)(p - buf);
}

/* ─── TPM2_CreatePrimary command builder ──────────────────────────── */

static uint32_t build_create_primary(uint8_t *cmd, role_t r, alg_t a) {
    uint8_t *p = cmd;
    p = put_u16(p, TPM_ST_SESSIONS);
    uint8_t *size_ptr = p;
    p = put_u32(p, 0);                          /* size placeholder */
    p = put_u32(p, TPM_CC_CreatePrimary);
    p = put_u32(p, hierarchy_for(r));           /* primaryHandle */
    /* auth area: 9 bytes for empty-password session. */
    p = put_u32(p, 9);
    p = put_u32(p, TPM_RS_PW);
    p = put_u16(p, 0);                          /* nonce size = 0 */
    *p++ = 0;                                   /* sessionAttributes = 0 */
    p = put_u16(p, 0);                          /* hmac size = 0 */
    /* inSensitive: size=4, userAuth.size=0, data.size=0 */
    p = put_u16(p, 4);
    p = put_u16(p, 0);
    p = put_u16(p, 0);
    /* inPublic: TPM2B_PUBLIC */
    uint8_t *pub_size_ptr = p;
    p = put_u16(p, 0);                          /* placeholder */
    uint8_t *pub_start = p;
    uint32_t pub_len = build_tpmt_public(p, r, a);
    p += pub_len;
    put_u16(pub_size_ptr, (uint16_t)(p - pub_start));
    /* outsideInfo TPM2B_DATA (empty). */
    p = put_u16(p, 0);
    /* creationPCR TPML_PCR_SELECTION count=0. */
    p = put_u32(p, 0);

    uint32_t total = (uint32_t)(p - cmd);
    put_u32(size_ptr, total);
    return total;
}

/* Parse CreatePrimary response → (pub_hex, pk_size, out_pub_size, param_set). */
typedef struct {
    uint32_t rc;
    uint32_t new_handle;          /* outHandle (transient, must be flushed) */
    uint32_t out_pub_bytes;       /* outPublic (TPM2B_PUBLIC contents size). */
    uint32_t name_bytes;
    uint16_t out_type;
    uint32_t out_attrs;
    uint16_t parameter_set;       /* for PQC algs, else 0 */
    uint16_t curve_id;            /* for ECC, else 0 */
    uint16_t key_bits;            /* for RSA, else 0 */
    uint32_t unique_bytes;        /* pk length */
    char     unique_hex[16384];   /* pk bytes hex-encoded */
} cp_resp_t;

static int parse_create_primary_resp(const uint8_t *resp, uint32_t resp_len, cp_resp_t *out) {
    memset(out, 0, sizeof(*out));
    if (resp_len < 10) return -1;
    out->rc = get_u32(resp + 6);
    if (out->rc != 0) return 0;

    const uint8_t *q   = resp + 10;
    const uint8_t *end = resp + resp_len;
    out->new_handle = get_u32(q);
    q += 4;                                   /* new handle */
    if (q + 4 > end) return -1;
    q += 4;                                   /* parameterSize (sessions present) */
    if (q + 2 > end) return -1;
    uint16_t pub_sz = get_u16(q); q += 2;
    out->out_pub_bytes = pub_sz;
    if (q + pub_sz > end) return -1;
    const uint8_t *pub_start = q;

    out->out_type = get_u16(q); q += 2;
    q += 2;                                   /* nameAlg */
    out->out_attrs = get_u32(q); q += 4;
    uint16_t auth_pol_sz = get_u16(q); q += 2 + auth_pol_sz;

    switch (out->out_type) {
    case TPM_ALG_RSA: {
        /* sym (NULL = 2 B, AES-128-CFB = 6 B) */
        uint16_t sym = get_u16(q); q += 2;
        if (sym != TPM_ALG_NULL) q += 4;
        /* scheme */
        uint16_t sch = get_u16(q); q += 2;
        if (sch != TPM_ALG_NULL) q += 2; /* hashAlg */
        out->key_bits = get_u16(q); q += 2;
        q += 4;                              /* exponent */
        uint16_t uniq = get_u16(q); q += 2;
        out->unique_bytes = uniq;
        if (q + uniq > end || uniq > sizeof(out->unique_hex) / 2 - 1) return -1;
        hex_to_string(q, uniq, out->unique_hex);
        break;
    }
    case TPM_ALG_ECC: {
        uint16_t sym = get_u16(q); q += 2;
        if (sym != TPM_ALG_NULL) q += 4;
        uint16_t sch = get_u16(q); q += 2;
        if (sch != TPM_ALG_NULL) q += 2;
        out->curve_id = get_u16(q); q += 2;
        q += 2;                              /* kdf (NULL) */
        /* unique: TPMS_ECC_POINT { x TPM2B, y TPM2B } */
        uint16_t x_sz = get_u16(q); q += 2;
        if (q + x_sz > end) return -1;
        const uint8_t *x = q; q += x_sz;
        uint16_t y_sz = get_u16(q); q += 2;
        if (q + y_sz > end) return -1;
        const uint8_t *y = q; q += y_sz;
        out->unique_bytes = (uint32_t)x_sz + y_sz;
        if ((size_t)(x_sz + y_sz) + 1 > sizeof(out->unique_hex) / 2) return -1;
        hex_to_string(x, x_sz, out->unique_hex);
        hex_to_string(y, y_sz, out->unique_hex + x_sz * 2);
        break;
    }
    case TPM_ALG_MLDSA: {
        /* TPMS_MLDSA_PARMS (V1.85 Table 229): parameterSet(2) + allowExternalMu(1) */
        out->parameter_set = get_u16(q); q += 2;
        q += 1; /* skip allowExternalMu */
        uint16_t uniq = get_u16(q); q += 2;
        out->unique_bytes = uniq;
        if (q + uniq > end || uniq > sizeof(out->unique_hex) / 2 - 1) return -1;
        hex_to_string(q, uniq, out->unique_hex);
        break;
    }
    case TPM_ALG_MLKEM: {
        /* TPMS_MLKEM_PARMS (V1.85 Table 231): symmetric(TPMT_SYM_DEF_OBJECT) + parameterSet(2)
         * TPMT_SYM_DEF_OBJECT = algorithm(2); if not NULL, also keyBits(2)+mode(2). */
        uint16_t sym_k = get_u16(q); q += 2;
        if (sym_k != TPM_ALG_NULL) q += 4;  /* skip keyBits + mode for AES-128-CFB */
        out->parameter_set = get_u16(q); q += 2;
        uint16_t uniq_k = get_u16(q); q += 2;
        out->unique_bytes = uniq_k;
        if (q + uniq_k > end || uniq_k > sizeof(out->unique_hex) / 2 - 1) return -1;
        hex_to_string(q, uniq_k, out->unique_hex);
        break;
    }
    default: return -1;
    }

    (void)pub_start;
    return 0;
}

/* Flush a transient object handle so the TPM doesn't run out of object
 * memory (it has ~3 transient slots — exhausted after 3 CreatePrimary
 * calls otherwise, yielding TPM_RC_OBJECT_MEMORY=0x902).
 *
 * Buffers match the rest of tpm_bench — libtpms does not strictly honor
 * the respbufsize hint and may write up to its internal max response
 * size, overflowing a tight stack buffer. */
static void flush_handle(uint32_t handle) {
    static uint8_t cmd[1024];
    static uint8_t resp[16384];
    uint32_t resp_len = sizeof(resp);
    uint8_t *p = cmd;
    p = put_u16(p, TPM_ST_NO_SESSIONS);
    p = put_u32(p, 0);
    p = put_u32(p, TPM_CC_FlushContext);
    p = put_u32(p, handle);
    uint32_t len = (uint32_t)(p - cmd);
    put_u32(cmd + 2, len);
    trace("cmd", "flush", "-", cmd, len);
    unsigned char *rb = resp;
    uint32_t rs = 0;
    TPMLIB_Process(&rb, &rs, &resp_len, cmd, len);
    trace("resp", "flush", "-", resp, rs);
}

/* ─── Single op runner ────────────────────────────────────────────── */

static int run_one(run_t r) {
    uint8_t  cmd[2048];
    uint8_t  resp[16384];
    uint32_t cmd_len = build_create_primary(cmd, r.role, r.alg);
    uint32_t resp_len = sizeof(resp);

    trace("cmd", role_name(r.role), alg_name(r.alg), cmd, cmd_len);

    unsigned char *rb = resp;
    uint32_t rs = 0;
    double t0 = now_ms();
    int io_rc = TPMLIB_Process(&rb, &rs, &resp_len, cmd, cmd_len);
    double dt = now_ms() - t0;
    uint32_t rl = rs;

    trace("resp", role_name(r.role), alg_name(r.alg), resp, rl);

    cp_resp_t cr;
    int parse_rc = parse_create_primary_resp(resp, rl, &cr);

    /* Emit one JSON object on stdout. Wrapped in a comma-separated array
     * by the caller (run_all). */
    if (!g_first_json) printf(",\n");
    g_first_json = 0;

    printf("    {");
    printf("\"role\":\"%s\",", role_name(r.role));
    printf("\"role_description\":\"%s\",", role_description(r.role));
    printf("\"alg\":\"%s\",", alg_name(r.alg));
    printf("\"alg_display\":\"%s\",", alg_display(r.alg));
    printf("\"alg_id\":\"0x%04X\",",
           (r.alg == ALG_RSA2048) ? TPM_ALG_RSA :
           (r.alg == ALG_P256)    ? TPM_ALG_ECC :
           (r.alg == ALG_MLDSA65) ? TPM_ALG_MLDSA :
           (r.alg == ALG_MLKEM768)? TPM_ALG_MLKEM : 0);
    printf("\"hierarchy\":\"%s\",",
           (hierarchy_for(r.role) == TPM_RH_ENDORSEMENT) ? "endorsement" : "owner");
    printf("\"hierarchy_handle\":\"0x%08X\",", hierarchy_for(r.role));
    printf("\"object_attributes\":\"0x%08X\",", attrs_for(r.role, r.alg));
    printf("\"is_pqc\":%s,", alg_is_pqc(r.alg) ? "true" : "false");
    printf("\"is_signer\":%s,", role_is_signer(r.role) ? "true" : "false");
    printf("\"keygen_ms\":%.3f,", dt);
    printf("\"io_rc\":%d,", io_rc);
    printf("\"response_rc\":\"0x%08X\",", cr.rc);
    printf("\"ok\":%s,", (io_rc == 0 && cr.rc == 0 && parse_rc == 0) ? "true" : "false");
    printf("\"command_size\":%u,", cmd_len);
    printf("\"response_size\":%u,", rl);
    printf("\"outPublic_size\":%u,", cr.out_pub_bytes);
    printf("\"pk_bytes\":%u,", cr.unique_bytes);
    if (r.alg == ALG_RSA2048)  printf("\"rsa_key_bits\":%u,", cr.key_bits);
    if (r.alg == ALG_P256)     printf("\"ecc_curve_id\":\"0x%04X\",", cr.curve_id);
    if (alg_is_pqc(r.alg))     printf("\"parameter_set\":\"0x%04X\",", cr.parameter_set);
    if (cr.rc == 0 && cr.unique_bytes > 0) {
        /* Truncate very large hex to keep the JSON payload sane; full hex is
         * available via the trace stream. */
        const size_t MAX_HEX_CHARS = 512 * 2;
        if (strlen(cr.unique_hex) > MAX_HEX_CHARS) {
            char clip[MAX_HEX_CHARS + 4];
            memcpy(clip, cr.unique_hex, MAX_HEX_CHARS);
            clip[MAX_HEX_CHARS] = '.';
            clip[MAX_HEX_CHARS+1] = '.';
            clip[MAX_HEX_CHARS+2] = '.';
            clip[MAX_HEX_CHARS+3] = '\0';
            printf("\"pk_hex_preview\":\"%s\",", clip);
        } else {
            printf("\"pk_hex_preview\":\"%s\",", cr.unique_hex);
        }
        printf("\"pk_hex_full\":\"%s\",", cr.unique_hex);
    } else {
        printf("\"pk_hex_preview\":\"\",");
        printf("\"pk_hex_full\":\"\",");
    }
    printf("\"standard_ref\":\"TCG TPM 2.0 Library V1.85 RC4 Part 2 — %s\"",
           alg_is_pqc(r.alg)
             ? (r.alg == ALG_MLDSA65 ? "Table 206 (TPMS_MLDSA_PARMS)"
                                     : "Table 210 (TPMS_MLKEM_PARMS)")
             : "Parts 2-3 (RSA/ECC primary templates)");
    printf("}");

    fflush(stdout);

    /* Flush the transient handle to free object memory for the next op. */
    if (io_rc == 0 && cr.rc == 0 && cr.new_handle != 0) {
        flush_handle(cr.new_handle);
    }
    return (io_rc == 0 && cr.rc == 0 && parse_rc == 0) ? 0 : 1;
}

/* ─── TPM2_Quote + OpenSSL attestation verify ─────────────────────── */

/* Hex-decode a NUL-terminated hex string into out[]. Returns 0 on success.
 * out_len receives the byte count (strlen(hex)/2). */
static int hex_decode(const char *hex, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = strlen(hex);
    if (n & 1u) return -1;
    *out_len = n / 2;
    if (*out_len > cap) return -1;
    for (size_t i = 0; i < *out_len; i++) {
        int hi = 0, lo = 0;
        char h = hex[2 * i], l = hex[2 * i + 1];
        if (h >= '0' && h <= '9') hi = h - '0';
        else if (h >= 'a' && h <= 'f') hi = h - 'a' + 10;
        else if (h >= 'A' && h <= 'F') hi = h - 'A' + 10;
        else return -1;
        if (l >= '0' && l <= '9') lo = l - '0';
        else if (l >= 'a' && l <= 'f') lo = l - 'a' + 10;
        else if (l >= 'A' && l <= 'F') lo = l - 'A' + 10;
        else return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* OpenSSL EVP_DigestVerify for ML-DSA-65. Returns 1 on accept, 0 on reject.
 * Independent of the libtpms signer — different EVP_PKEY instance, same
 * FIPS 204 implementation (both use OpenSSL 3.6.2 but on separate code paths). */
static int openssl_verify_mldsa65(const uint8_t *pub, size_t pub_len,
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t *sig, size_t sig_len)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY     *pkey = NULL;
    EVP_MD_CTX   *mdctx = NULL;
    int ok = 0;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, pub_len);
    params[1] = OSSL_PARAM_construct_end();

    gctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (!gctx) goto done;
    if (EVP_PKEY_fromdata_init(gctx) <= 0) goto done;
    if (EVP_PKEY_fromdata(gctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) goto done;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto done;
    if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) goto done;
    ok = (EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len) == 1);
done:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gctx);
    return ok;
}

/* Build TPM2_Quote command (Part 3 §18.4).
 * Quotes PCR0..PCR7 in the SHA-256 bank using aik_handle. */
static uint32_t build_tpm2_quote(uint8_t *cmd, uint32_t aik_handle,
                                  const uint8_t *nonce, uint16_t nonce_len)
{
    uint8_t *p = cmd;
    p = put_u16(p, TPM_ST_SESSIONS);
    uint8_t *sz = p; p += 4;           /* size placeholder */
    p = put_u32(p, TPM_CC_Quote);
    p = put_u32(p, aik_handle);
    /* auth area: 9-byte empty-password session */
    p = put_u32(p, 9);
    p = put_u32(p, TPM_RS_PW);
    p = put_u16(p, 0);
    *p++ = 0;
    p = put_u16(p, 0);
    /* qualifyingData: TPM2B_DATA */
    p = put_u16(p, nonce_len);
    memcpy(p, nonce, nonce_len); p += nonce_len;
    /* inScheme: TPM_ALG_NULL — libtpms derives hash from nameAlg (FIPS 204
     * per pqc_attestation_xcheck.c §do_quote: NULL avoids union body). */
    p = put_u16(p, TPM_ALG_NULL);
    /* PCRselect: count=1, SHA-256 bank, PCR0..PCR7 (sizeofSelect=3). */
    p = put_u32(p, 1);
    p = put_u16(p, TPM_ALG_SHA256);
    *p++ = 3;
    *p++ = 0xff;                       /* pcrSelect[0]: PCR0..PCR7 */
    *p++ = 0x00;
    *p++ = 0x00;
    uint32_t total = (uint32_t)(p - cmd);
    put_u32(sz, total);
    return total;
}

typedef struct {
    uint32_t rc;
    uint8_t  attest[2048];
    uint16_t attest_size;
    uint16_t sig_alg;
    uint8_t  sig[4096];
    uint16_t sig_size;
} quote_resp_t;

/* Parse TPM2_Quote response. On success fills *out and returns 0. */
static int parse_tpm2_quote_resp(const uint8_t *resp, uint32_t resp_len,
                                  quote_resp_t *out)
{
    memset(out, 0, sizeof(*out));
    if (resp_len < 10) return -1;
    out->rc = get_u32(resp + 6);
    if (out->rc != 0) return 0;

    const uint8_t *q   = resp + 10;
    const uint8_t *end = resp + resp_len;
    if (q + 4 > end) return -1;
    q += 4;                            /* parameterSize (sessions present) */

    /* quoted: TPM2B_ATTEST {size(2), data[size]} */
    if (q + 2 > end) return -1;
    out->attest_size = get_u16(q); q += 2;
    if (out->attest_size > (uint16_t)sizeof(out->attest)) return -1;
    if (q + out->attest_size > end) return -1;
    memcpy(out->attest, q, out->attest_size);
    q += out->attest_size;

    /* signature: TPMT_SIGNATURE — sigAlg(2) then TPMS_SIGNATURE_MLDSA {size(2),buf} */
    if (q + 2 > end) return -1;
    out->sig_alg = get_u16(q); q += 2;
    if (q + 2 > end) return -1;
    out->sig_size = get_u16(q); q += 2;
    if (out->sig_size > (uint16_t)sizeof(out->sig)) return -1;
    if (q + out->sig_size > end) return -1;
    memcpy(out->sig, q, out->sig_size);
    return 0;
}

/* Full attestation sequence: CreatePrimary(AIK, ML-DSA-65) → TPM2_Quote →
 * OpenSSL verify. Emits a JSON bundle to stdout and returns 0 on pass. */
static int run_attestation_mode(void)
{
    static const uint8_t NONCE[] = "pqctoday-sandbox-tpm-quote-nonce";
    static uint8_t cmd[8192], resp[65536];
    uint32_t resp_len;

    /* CreatePrimary: AIK / ML-DSA-65 */
    resp_len = sizeof(resp);
    uint32_t cmd_len = build_create_primary(cmd, ROLE_AIK, ALG_MLDSA65);
    trace("cmd", "aik_create", "mldsa65", cmd, cmd_len);
    unsigned char *rb = resp;
    uint32_t rs = 0;
    int io_rc = TPMLIB_Process(&rb, &rs, &resp_len, cmd, cmd_len);
    trace("resp", "aik_create", "mldsa65", resp, rs);

    cp_resp_t cr;
    int parse_rc = parse_create_primary_resp(resp, rs, &cr);
    if (io_rc != 0 || cr.rc != 0 || parse_rc != 0) {
        fprintf(stderr,
                "{\"error\":\"CreatePrimary(AIK,MLDSA65) failed\","
                "\"tpm_rc\":\"0x%08X\"}\n", cr.rc);
        return 1;
    }
    uint32_t aik_handle = cr.new_handle;

    /* Decode raw public key bytes for OpenSSL verify. */
    static uint8_t pub_bytes[2048];
    size_t pub_len = 0;
    if (hex_decode(cr.unique_hex, pub_bytes, sizeof(pub_bytes), &pub_len) != 0
            || pub_len == 0) {
        flush_handle(aik_handle);
        fprintf(stderr, "{\"error\":\"hex decode of AIK public key failed\"}\n");
        return 1;
    }

    /* TPM2_Quote using the AIK handle */
    resp_len = sizeof(resp);
    cmd_len = build_tpm2_quote(cmd, aik_handle,
                               NONCE, (uint16_t)(sizeof(NONCE) - 1));
    trace("cmd", "quote", "mldsa65", cmd, cmd_len);
    rb = resp; rs = 0;
    io_rc = TPMLIB_Process(&rb, &rs, &resp_len, cmd, cmd_len);
    trace("resp", "quote", "mldsa65", resp, rs);

    quote_resp_t qr;
    parse_rc = parse_tpm2_quote_resp(resp, rs, &qr);
    flush_handle(aik_handle);

    if (io_rc != 0 || qr.rc != 0 || parse_rc != 0) {
        fprintf(stderr,
                "{\"error\":\"TPM2_Quote failed\","
                "\"tpm_rc\":\"0x%08X\"}\n", qr.rc);
        return 1;
    }

    /* OpenSSL EVP_DigestVerify — independent of the libtpms signer. */
    int verified = openssl_verify_mldsa65(
        pub_bytes, pub_len,
        qr.attest, qr.attest_size,
        qr.sig, qr.sig_size);

    /* TPM_GENERATED_VALUE = 0xFF544347 must prefix every TPMS_ATTEST. */
    int magic_ok = (qr.attest_size >= 4 &&
                    qr.attest[0] == 0xFF && qr.attest[1] == 0x54 &&
                    qr.attest[2] == 0x43 && qr.attest[3] == 0x47);
    int pk_ok  = (pub_len == 1952);
    int sig_ok = (qr.sig_size == 3309);
    int pass   = (magic_ok && verified && pk_ok && sig_ok);

    printf("{\n");
    printf("  \"schema\": \"pqctoday.tpm.attestation/1\",\n");
    printf("  \"operation\": \"TPM2_Quote\",\n");
    printf("  \"standard\": \"TCG TPM 2.0 Library V1.85 RC4 Part 3 §18.4\",\n");
    printf("  \"algorithm\": \"ML-DSA-65\",\n");
    printf("  \"aik\": {\n");
    printf("    \"role\": \"AIK\",\n");
    printf("    \"alg\": \"mldsa65\",\n");
    printf("    \"pk_bytes\": %zu,\n", pub_len);
    printf("    \"pk_spec\": \"FIPS 204 §7 Table 2: ML-DSA-65 pk = 1952 B\",\n");
    printf("    \"pk_size_ok\": %s\n", pk_ok ? "true" : "false");
    printf("  },\n");
    printf("  \"quote\": {\n");
    printf("    \"attest_bytes\": %u,\n", (unsigned)qr.attest_size);
    printf("    \"magic_ok\": %s,\n", magic_ok ? "true" : "false");
    printf("    \"magic_ref\": \"TPM_GENERATED_VALUE = 0xFF544347 (Part 2 §10.12.1)\",\n");
    printf("    \"sig_alg\": \"0x%04X\",\n", qr.sig_alg);
    printf("    \"sig_alg_name\": \"%s\",\n",
           (qr.sig_alg == TPM_ALG_MLDSA) ? "TPM_ALG_MLDSA" : "UNKNOWN");
    printf("    \"sig_bytes\": %u,\n", (unsigned)qr.sig_size);
    printf("    \"sig_spec\": \"FIPS 204 §7 Table 2: ML-DSA-65 sig = 3309 B\",\n");
    printf("    \"sig_size_ok\": %s\n", sig_ok ? "true" : "false");
    printf("  },\n");
    printf("  \"verification\": {\n");
    printf("    \"verifier\": \"OpenSSL 3.6.2 EVP_DigestVerify (independent of libtpms signer)\",\n");
    printf("    \"result\": %s,\n", verified ? "true" : "false");
    printf("    \"spec_ref\": \"FIPS 204 §3.2 + Part 1 §22.1.2 (restricted AIK)\"\n");
    printf("  },\n");
    printf("  \"pcr_selection\": {\"bank\": \"SHA-256\", \"pcrs\": \"PCR0..PCR7\"},\n");
    printf("  \"nonce\": \"pqctoday-sandbox-tpm-quote-nonce\",\n");
    printf("  \"pass\": %s\n", pass ? "true" : "false");
    printf("}\n");

    return pass ? 0 : 1;
}

/* ─── Main / argparse ─────────────────────────────────────────────── */

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [--trace] [--attestation] [--run role:alg]...\n"
        "\n"
        "  --trace                Emit raw TPM command/response hex on stderr\n"
        "                         as single-line JSON trace events (one per op).\n"
        "  --attestation          Run TPM2_Quote with ML-DSA-65 AIK and verify\n"
        "                         via OpenSSL EVP_DigestVerify. Emits a JSON\n"
        "                         attestation bundle and exits (skips the matrix).\n"
        "  --run ROLE:ALG         Queue a TPM2_CreatePrimary. Repeatable.\n"
        "                         ROLE ∈ {EK, SRK, AIK, IDevID}\n"
        "                         ALG  ∈ {rsa2048, p256, mldsa65, mlkem768}\n"
        "\n"
        "If no --run is given, the default 8-op migration matrix runs:\n"
        "     EK classical  (rsa2048)   → EK PQC  (mlkem768)\n"
        "     SRK classical (rsa2048)   → SRK PQC (mlkem768)\n"
        "     AIK classical (rsa2048)   → AIK PQC (mldsa65)\n"
        "     IDevID classical (p256)   → IDevID PQC (mldsa65)\n",
        argv0);
}

int main(int argc, char **argv) {
    run_t queue[32];
    int   queue_n = 0;
    int   g_attestation = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--trace")) {
            g_trace = 1;
        } else if (!strcmp(argv[i], "--attestation")) {
            g_attestation = 1;
        } else if (!strcmp(argv[i], "--run") && i + 1 < argc) {
            char spec[64];
            strncpy(spec, argv[++i], sizeof(spec) - 1);
            spec[sizeof(spec) - 1] = '\0';
            char *sep = strchr(spec, ':');
            if (!sep) { usage(argv[0]); return 2; }
            *sep = '\0';
            role_t r = parse_role(spec);
            alg_t  a = parse_alg(sep + 1);
            if (r == ROLE_UNKNOWN || a == ALG_UNKNOWN) { usage(argv[0]); return 2; }
            if (queue_n >= (int)(sizeof(queue) / sizeof(queue[0]))) {
                fprintf(stderr, "too many --run entries\n"); return 2;
            }
            queue[queue_n++] = (run_t){ r, a };
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            usage(argv[0]); return 2;
        }
    }
    /* Default migration matrix. */
    if (queue_n == 0) {
        queue[queue_n++] = (run_t){ ROLE_EK,     ALG_RSA2048  };
        queue[queue_n++] = (run_t){ ROLE_EK,     ALG_MLKEM768 };
        queue[queue_n++] = (run_t){ ROLE_SRK,    ALG_RSA2048  };
        queue[queue_n++] = (run_t){ ROLE_SRK,    ALG_MLKEM768 };
        queue[queue_n++] = (run_t){ ROLE_AIK,    ALG_RSA2048  };
        queue[queue_n++] = (run_t){ ROLE_AIK,    ALG_MLDSA65  };
        queue[queue_n++] = (run_t){ ROLE_IDEVID, ALG_P256     };
        queue[queue_n++] = (run_t){ ROLE_IDEVID, ALG_MLDSA65  };
    }

    /* Prep a temp dir + chdir so libtpms writes NVChip there. */
    char tmpdir[] = "/tmp/tpm-bench-XXXXXX";
    if (mkdtemp(tmpdir) == NULL) { perror("mkdtemp"); return 1; }
    char origcwd[4096];
    if (getcwd(origcwd, sizeof(origcwd)) == NULL) { perror("getcwd"); return 1; }
    if (chdir(tmpdir) != 0) { perror("chdir"); return 1; }

    TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (TPMLIB_MainInit() != TPM_SUCCESS) {
        fprintf(stderr, "{\"error\":\"TPMLIB_MainInit failed\"}\n");
        return 1;
    }
    trace("init", "-", "-", (const uint8_t *)"tpm-init", 8);

    /* TPM2_Startup(CLEAR). Buffer sizes match test_tpm_roundtrip.c so
     * libtpms has headroom (Startup response itself is only 10 bytes but
     * libtpms has been observed to reject undersized response buffers). */
    {
        static uint8_t cmd[1024];
        static uint8_t resp[16384];
        uint32_t resp_len = sizeof(resp);
        uint8_t *p = cmd;
        p = put_u16(p, TPM_ST_NO_SESSIONS);
        p = put_u32(p, 0);
        p = put_u32(p, TPM_CC_Startup);
        p = put_u16(p, 0);
        uint32_t len = (uint32_t)(p - cmd);
        put_u32(cmd + 2, len);
        trace("cmd", "startup", "-", cmd, len);
        unsigned char *rb = resp;
        uint32_t rs = 0;
        TPMLIB_Process(&rb, &rs, &resp_len, cmd, len);
        trace("resp", "startup", "-", resp, rs);
    }

    /* If --attestation mode: run Quote sequence and exit early. */
    if (g_attestation) {
        int rc = run_attestation_mode();
        TPMLIB_Terminate();
        if (chdir(origcwd) == 0) {
            char nvpath[4096 + 16];
            snprintf(nvpath, sizeof(nvpath), "%s/NVChip", tmpdir);
            (void)remove(nvpath);
            (void)rmdir(tmpdir);
        }
        return rc;
    }

    /* ─── Emit the JSON envelope ─────────────────────────────────── */
    printf("{\n");
    printf("  \"schema\": \"pqctoday.tpm.bench/1\",\n");
    printf("  \"standard\": \"TCG TPM 2.0 Library V1.85 RC4\",\n");
    printf("  \"standard_url\": \"https://trustedcomputinggroup.org/resource/tpm-library-specification/\",\n");
    printf("  \"engine\": {\n");
    printf("    \"library\": \"libtpms\",\n");
    printf("    \"libtpms_upstream\": \"https://github.com/stefanberger/libtpms\",\n");
    printf("    \"swtpm_upstream\": \"https://github.com/stefanberger/swtpm\",\n");
    printf("    \"upstream_maintainer\": \"Stefan Berger (IBM)\",\n");
    printf("    \"fork\": \"https://github.com/pqctoday/pqctoday-tpm\",\n");
    printf("    \"pqc_additions\": {\n");
    printf("      \"TPM_ALG_MLKEM\": \"0x00A0\",\n");
    printf("      \"TPM_ALG_MLDSA\": \"0x00A1\",\n");
    printf("      \"TPM_ALG_HASH_MLDSA\": \"0x00A2\",\n");
    printf("      \"TPM_BUFFER_MAX_before\": 4096,\n");
    printf("      \"TPM_BUFFER_MAX_after\": 8192\n");
    printf("    }\n");
    printf("  },\n");
    printf("  \"ops\": [\n");

    int total_ok = 0;
    for (int i = 0; i < queue_n; i++) {
        if (run_one(queue[i]) == 0) total_ok++;
    }
    printf("\n  ],\n");
    printf("  \"summary\": {\"ops_total\":%d,\"ops_ok\":%d}\n", queue_n, total_ok);
    printf("}\n");

    TPMLIB_Terminate();

    /* Cleanup temp NV. */
    if (chdir(origcwd) == 0) {
        char nvpath[4096 + 16];
        snprintf(nvpath, sizeof(nvpath), "%s/NVChip", tmpdir);
        (void)remove(nvpath);
        (void)rmdir(tmpdir);
    }
    return (total_ok == queue_n) ? 0 : 1;
}
