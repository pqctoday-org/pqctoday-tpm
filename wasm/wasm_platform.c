/* wasm_platform.c — Emscripten WASM platform layer for pqctoday-tpm
 *
 * Replaces: Cancel.c, Entropy.c, PowerPlat.c, NVMem.c
 * Kept as-is: Clock.c, LocalityPlat.c, PPPlat.c, PlatformACT.c,
 *             PlatformData.c, PlatformPCR.c, Power.c, PP.c,
 *             Unique.c, VendorInfo.c, ExtraData.c
 *
 * NV backing: in-memory s_NV[]; export via tpm_wasm_get_nv / tpm_wasm_set_nv
 * for JS-side persistence (localStorage / IndexedDB).
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/rand.h>

/* Platform.h must come first — defines BOOL, FALSE, TRUE, LIB_EXPORT,
 * s_isCanceled, s_locality, s_physicalPresence, s_powerLost, s_NV, etc. */
#include "Platform.h"
#include "_TPM_Init_fp.h"

/* emscripten.h after Platform.h to avoid macro conflicts */
#include <emscripten.h>

/* ── NV state variables ──────────────────────────────────────────────────── */
/* s_NvIsAvailable, s_NV_unrecoverable, s_NV_recoverable are declared extern
 * in PlatformData.h and instantiated by PlatformData.c — no redeclaration. */
static BOOL s_NeedsManufacture = TRUE; /* not in PlatformData.h; owned here */

/* ── Cancel ─────────────────────────────────────────────────────────────── */

LIB_EXPORT int _plat__IsCanceled(void)   { return s_isCanceled; }
LIB_EXPORT void _plat__SetCancel(void)   { s_isCanceled = TRUE; }
LIB_EXPORT void _plat__ClearCancel(void) { s_isCanceled = FALSE; }

/* ── Entropy ─────────────────────────────────────────────────────────────── */

LIB_EXPORT int32_t _plat__GetEntropy(unsigned char *entropy, uint32_t amount)
{
    if (amount == 0)
        return 0;
    /* OpenSSL RAND_bytes uses Emscripten's crypto.getRandomValues() under the hood */
    if (RAND_bytes(entropy, (int)amount) == 1)
        return (int32_t)amount;
    /* Fallback: EM_ASM direct call to crypto.getRandomValues */
    EM_ASM({
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(HEAPU8.subarray($0, $0 + $1));
        }
    }, entropy, amount);
    return (int32_t)amount;
}

/* ── Power ───────────────────────────────────────────────────────────────── */

LIB_EXPORT int _plat__Signal_PowerOn(void)
{
    _plat__TimerReset();
    s_powerLost = TRUE;
    return 0;
}

LIB_EXPORT int _plat__WasPowerLost(void)
{
    int v = s_powerLost;
    s_powerLost = FALSE;
    return v;
}

LIB_EXPORT int _plat__Signal_Reset(void)
{
    s_locality   = 0;
    s_isCanceled = FALSE;
    _TPM_Init();
    return 0;
}

LIB_EXPORT void _plat__Signal_PowerOff(void)
{
    _plat__NVDisable((void *)FALSE, 0);
}

/* ── NV Memory ───────────────────────────────────────────────────────────── */

LIB_EXPORT void _plat__NvErrors(int recoverable, int unrecoverable)
{
    s_NV_unrecoverable = unrecoverable;
    s_NV_recoverable   = recoverable;
}

LIB_EXPORT int _plat__NVEnable(void *platParameter, size_t paramSize)
{
    (void)platParameter; (void)paramSize;
    s_NV_unrecoverable = FALSE;
    s_NV_recoverable   = FALSE;
    /* s_NV is zero-initialised at startup; s_NeedsManufacture stays TRUE
       until the caller (TPMLIB_MainInit) populates it, or tpm_wasm_set_nv
       loads previously saved state. */
    s_NvIsAvailable = TRUE;
    return (int)s_NV_recoverable;
}

LIB_EXPORT int _plat__NVEnable_NVChipFile(void *platParameter)
{
    return _plat__NVEnable(platParameter, 0);
}

LIB_EXPORT void _plat__NVDisable(void *platParameter, size_t paramSize)
{
    (void)platParameter; (void)paramSize;
    s_NvIsAvailable = FALSE;
}

LIB_EXPORT int _plat__GetNvReadyState(void)
{
    if (!s_NvIsAvailable)  return 1; /* NV_WRITEFAILURE */
    if (s_NV_unrecoverable) return -1;
    return 0; /* NV_READY */
}

LIB_EXPORT int _plat__NvMemoryRead(unsigned int startOffset,
                                    unsigned int size, void *data)
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if (startOffset + size > NV_MEMORY_SIZE) return -1;
    memcpy(data, &s_NV[startOffset], size);
    return 0;
}

LIB_EXPORT int _plat__NvGetChangedStatus(unsigned int startOffset,
                                          unsigned int size, void *data)
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if (startOffset + size > NV_MEMORY_SIZE) return 0;
    return (memcmp(&s_NV[startOffset], data, size) != 0);
}

LIB_EXPORT int _plat__NvMemoryWrite(unsigned int startOffset,
                                     unsigned int size, void *data)
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if (startOffset + size > NV_MEMORY_SIZE) return -1;
    memcpy(&s_NV[startOffset], data, size);
    return 0;
}

LIB_EXPORT int _plat__NvMemoryClear(unsigned int startOffset,
                                     unsigned int size)
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if (startOffset + size > NV_MEMORY_SIZE) return -1;
    memset(&s_NV[startOffset], 0xff, size);
    return 0;
}

LIB_EXPORT int _plat__NvMemoryMove(unsigned int sourceOffset,
                                    unsigned int destOffset,
                                    unsigned int size)
{
    assert(sourceOffset + size <= NV_MEMORY_SIZE);
    assert(destOffset   + size <= NV_MEMORY_SIZE);
    if (sourceOffset + size > NV_MEMORY_SIZE) return -1;
    if (destOffset   + size > NV_MEMORY_SIZE) return -1;
    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);
    if (sourceOffset > destOffset)
        memset(&s_NV[destOffset + size], 0, sourceOffset - destOffset);
    else if (destOffset > sourceOffset)
        memset(&s_NV[sourceOffset], 0, destOffset - sourceOffset);
    return 0;
}

LIB_EXPORT int _plat__NvCommit(void)
{
    /* NV is already in memory; JS caller reads it via tpm_wasm_get_nv() */
    return 0;
}

LIB_EXPORT void _plat__TearDown(void) {}

LIB_EXPORT void _plat__SetNvAvail(void)   { s_NvIsAvailable = TRUE;  }
LIB_EXPORT void _plat__ClearNvAvail(void) { s_NvIsAvailable = FALSE; }

LIB_EXPORT int _plat__NVNeedsManufacture(void)
{
    return s_NeedsManufacture ? TRUE : FALSE;
}

/* ── Fatal error ─────────────────────────────────────────────────────────── */
/* _plat__Fail is defined in RunCommand.c (longjmp into s_jumpBuffer).
 * No definition here — that file is kept in the WASM build. */

/* ── libtpms state persistence stubs ─────────────────────────────────────── */
/* tpm_nvfile.c is excluded because it uses POSIX file I/O.
 * libtpms uses these for its internal state blobs (tpm_volatilestate etc.).
 * In WASM, we rely on the host calling tpm_wasm_get_nv/set_nv for the raw 
 * s_NV buffer, so we stub these to pretend no file state exists on load,
 * and ignore writes. */

#include "tpm_types.h"
#include "libtpms/tpm_error.h"

TPM_RESULT TPM_NVRAM_LoadData(unsigned char **data, uint32_t *length,
                              uint32_t tpm_number, const char *name)
{
    (void)data; (void)length; (void)tpm_number; (void)name;
    return TPM_RETRY; /* Forces TPM to initialize as unmanufactured / blank */
}

TPM_RESULT TPM_NVRAM_StoreData(const unsigned char *data, uint32_t length,
                               uint32_t tpm_number, const char *name)
{
    (void)data; (void)length; (void)tpm_number; (void)name;
    return TPM_SUCCESS;
}

TPM_RESULT TPM_NVRAM_DeleteName(uint32_t tpm_number, const char *name,
                                TPM_BOOL mustExist)
{
    (void)tpm_number; (void)name; (void)mustExist;
    return TPM_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PQC Crypto Bridge — EM_JS dispatchers to softhsm-wasm (Issue #9)
 *
 * These functions are called from CryptMlKem.c / CryptMlDsa.c inside
 * #ifdef __EMSCRIPTEN__ blocks.  They invoke JS functions registered on
 * Module._pqcBridge by the host application (pqctoday-hub tpmBridge.ts).
 *
 * Return convention:
 *   >= 0  success (value = output byte count where applicable)
 *   -1    no bridge registered — caller falls back to placeholder
 *   -2    bridge returned an error
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ML-KEM keygen: derive (pk, sk) from a 64-byte seed.
 * On success, writes pk to pkOut[pkOutMax] and sk to skOut[skOutMax].
 * Returns pk byte count or negative on error. */
EM_JS(int, pqc_bridge_mlkem_keygen, (
    uint16_t paramSet,
    const uint8_t *seed, uint32_t seedLen,
    uint8_t *pkOut, uint32_t pkOutMax,
    uint8_t *skOut, uint32_t skOutMax
), {
    if (!Module._pqcBridge || !Module._pqcBridge.mlkemKeygen) return -1;
    return Module._pqcBridge.mlkemKeygen(paramSet, seed, seedLen,
                                          pkOut, pkOutMax, skOut, skOutMax);
});

/* ML-KEM encapsulate: given a public key, produce (ciphertext, sharedSecret).
 * Returns 0 on success, negative on error. */
EM_JS(int, pqc_bridge_mlkem_encap, (
    uint16_t paramSet,
    const uint8_t *pk, uint32_t pkLen,
    uint8_t *ctOut, uint32_t ctOutMax,
    uint8_t *ssOut, uint32_t ssOutMax
), {
    if (!Module._pqcBridge || !Module._pqcBridge.mlkemEncap) return -1;
    return Module._pqcBridge.mlkemEncap(paramSet, pk, pkLen,
                                         ctOut, ctOutMax, ssOut, ssOutMax);
});

/* ML-KEM decapsulate: given private key + ciphertext, recover sharedSecret.
 * Returns 0 on success, negative on error. */
EM_JS(int, pqc_bridge_mlkem_decap, (
    uint16_t paramSet,
    const uint8_t *sk, uint32_t skLen,
    const uint8_t *ct, uint32_t ctLen,
    uint8_t *ssOut, uint32_t ssOutMax
), {
    if (!Module._pqcBridge || !Module._pqcBridge.mlkemDecap) return -1;
    return Module._pqcBridge.mlkemDecap(paramSet, sk, skLen,
                                         ct, ctLen, ssOut, ssOutMax);
});

/* ML-DSA sign: given private key + digest, produce signature.
 * Returns signature byte count on success, negative on error. */
EM_JS(int, pqc_bridge_mldsa_sign, (
    uint16_t paramSet,
    const uint8_t *sk, uint32_t skLen,
    const uint8_t *digest, uint32_t digestLen,
    uint8_t *sigOut, uint32_t sigOutMax
), {
    if (!Module._pqcBridge || !Module._pqcBridge.mldsaSign) return -1;
    return Module._pqcBridge.mldsaSign(paramSet, sk, skLen,
                                        digest, digestLen, sigOut, sigOutMax);
});

/* ML-DSA keygen: derive (pk, sk) from a seed.
 * Returns pk byte count on success, negative on error. */
EM_JS(int, pqc_bridge_mldsa_keygen, (
    uint16_t paramSet,
    const uint8_t *seed, uint32_t seedLen,
    uint8_t *pkOut, uint32_t pkOutMax,
    uint8_t *skOut, uint32_t skOutMax
), {
    if (!Module._pqcBridge || !Module._pqcBridge.mldsaKeygen) return -1;
    return Module._pqcBridge.mldsaKeygen(paramSet, seed, seedLen,
                                          pkOut, pkOutMax, skOut, skOutMax);
});

/* ═══════════════════════════════════════════════════════════════════════════
 * Public WASM API — called from JS via cwrap / ccall
 * ═══════════════════════════════════════════════════════════════════════════ */

#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"
#include "libtpms/tpm_library.h"
#include "libtpms/tpm_error.h"

/* Startup TPM2 command bytes:
 * TPM_ST_NO_SESSIONS(8001) size(12) TPM_CC_Startup(144) TPM_SU_CLEAR(0000) */
static const uint8_t kStartupClear[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
    0x00, 0x00, 0x01, 0x44,
    0x00, 0x00
};

/* tpm_wasm_startup — initialise and manufacture if needed, then TPM2_Startup.
 * profile: TCG profile string, e.g. "default-v1" (NULL → use default).
 * Returns 0 on success, non-zero on error. */
EMSCRIPTEN_KEEPALIVE
int tpm_wasm_startup(const char *profile)
{
    TPM_RESULT rc;

    struct libtpms_callbacks cbs = {
        .sizeOfStruct = sizeof(struct libtpms_callbacks),
        .tpm_nvram_init = NULL,
        .tpm_nvram_loaddata = TPM_NVRAM_LoadData,
        .tpm_nvram_storedata = TPM_NVRAM_StoreData,
        .tpm_nvram_deletename = TPM_NVRAM_DeleteName,
    };
    rc = TPMLIB_RegisterCallbacks(&cbs);
    if (rc != TPM_SUCCESS) {
        printf("DEBUG: TPMLIB_RegisterCallbacks failed: %d\n", rc);
        return (int)rc;
    }

    printf("DEBUG: calling TPMLIB_ChooseTPMVersion\n");
    rc = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (rc != TPM_SUCCESS) {
        printf("DEBUG: TPMLIB_ChooseTPMVersion failed: %d\n", rc);
        return (int)rc;
    }

    TPMLIB_SetBufferSize(8192, NULL, NULL);

    /* Activate the default-v1 profile so that V1.85 PQC commands
     * (Encapsulate 0x1A7, Decapsulate 0x1A8, SignDigest 0x1A6, etc.)
     * are included in the runtime command set.  Without this call the TPM
     * manufactures with the "null" legacy profile (commands ≤ 0x197 only),
     * and every V1.85 command returns TPM_RC_COMMAND_CODE (0x143). */
    rc = TPMLIB_SetProfile("{\"Name\":\"default-v1\"}");
    if (rc != TPM_SUCCESS) {
        printf("DEBUG: TPMLIB_SetProfile failed: %d (continuing with null profile)\n", rc);
    }

    printf("DEBUG: calling TPMLIB_MainInit\n");
    rc = TPMLIB_MainInit();
    if (rc != TPM_SUCCESS) return (int)rc;

    /* After MainInit, NV is manufactured and s_NV is populated */
    s_NeedsManufacture = FALSE;

    /* Send TPM2_Startup(SU_CLEAR) */
    unsigned char *resp   = NULL;
    uint32_t respLen      = 0;
    uint32_t respBufSize  = 0;
    rc = TPMLIB_Process(&resp, &respLen, &respBufSize,
                        (unsigned char *)kStartupClear,
                        (uint32_t)sizeof(kStartupClear));
    if (resp) free(resp);
    return (int)rc;
}

/* tpm_wasm_process — send a raw TPM2 command, write response into resp_buf.
 * Returns response length on success, -1 on library error. */
EMSCRIPTEN_KEEPALIVE
int tpm_wasm_process(const uint8_t *cmd, uint32_t cmdlen,
                     uint8_t *resp_buf, uint32_t resp_buf_size)
{
    unsigned char *resp  = NULL;
    uint32_t respLen     = 0;
    uint32_t respBufSize = 0;

    TPM_RESULT rc = TPMLIB_Process(&resp, &respLen, &respBufSize,
                                   (unsigned char *)cmd, cmdlen);
    if (rc != TPM_SUCCESS) {
        if (resp) free(resp);
        return -1;
    }
    uint32_t copy = (respLen < resp_buf_size) ? respLen : resp_buf_size;
    memcpy(resp_buf, resp, copy);
    if (resp) free(resp);
    return (int)copy;
}

/* tpm_wasm_get_nv_size — returns NV_MEMORY_SIZE so JS can allocate correctly */
EMSCRIPTEN_KEEPALIVE
uint32_t tpm_wasm_get_nv_size(void)
{
    return (uint32_t)NV_MEMORY_SIZE;
}

/* tpm_wasm_get_nv — copy current NV state into caller-allocated buf[size].
 * Returns bytes copied, or 0 if buf is too small. */
EMSCRIPTEN_KEEPALIVE
uint32_t tpm_wasm_get_nv(uint8_t *buf, uint32_t size)
{
    if (size < NV_MEMORY_SIZE) return 0;
    memcpy(buf, s_NV, NV_MEMORY_SIZE);
    return (uint32_t)NV_MEMORY_SIZE;
}

/* tpm_wasm_set_nv — restore NV state from buf[size].
 * Call BEFORE tpm_wasm_startup if resuming from saved state.
 * Returns 0 on success, -1 if size mismatch. */
EMSCRIPTEN_KEEPALIVE
int tpm_wasm_set_nv(const uint8_t *buf, uint32_t size)
{
    if (size != NV_MEMORY_SIZE) return -1;
    memcpy(s_NV, buf, NV_MEMORY_SIZE);
    s_NeedsManufacture = FALSE;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * V2.7 RC1 PQC EK provisioning — Phase C in-process port
 *
 * Mirrors the native swtpm_setup flow (swtpm_tpm2_create_pqc_eks +
 * swtpm_tpm2_pqc_provision_v2p7_ekcert_nvram in
 * swtpm/src/swtpm_setup/swtpm.c), with three deltas:
 *
 *   1. GLib dropped — swap g_autofree → goto-cleanup blocks, g_malloc → malloc.
 *   2. transfer() socket call → direct TPMLIB_Process (same process).
 *   3. No file output — cert DER lands in NV slots only.
 *
 * Line refs to the native source are inline (pqctoday-tpm v0.6.0 baseline)
 * so future divergences are easy to spot during ports.
 * ═══════════════════════════════════════════════════════════════════════════ */

#include <endian.h>
#include <stdarg.h>
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bio.h>

#include "tcg_pqc_ek_constants.h"  /* PolicyB digests + V2.7 NV index defines */

/* ── TPM2 protocol constants (duplicated from swtpm.c:395-505) ───────────── */
#define WASM_TPM2_ST_NO_SESSIONS  0x8001
#define WASM_TPM2_ST_SESSIONS     0x8002

#define WASM_TPM2_CC_EVICTCONTROL    0x00000120u
#define WASM_TPM2_CC_NV_DEFINESPACE  0x0000012au
#define WASM_TPM2_CC_CREATEPRIMARY   0x00000131u
#define WASM_TPM2_CC_NV_WRITE        0x00000137u
#define WASM_TPM2_CC_FLUSHCONTEXT    0x00000165u

#define WASM_TPM2_RH_OWNER           0x40000001u
#define WASM_TPM2_RS_PW              0x40000009u
#define WASM_TPM2_RH_ENDORSEMENT     0x4000000bu
#define WASM_TPM2_RH_PLATFORM        0x4000000cu

#define WASM_TPM2_ALG_AES    0x0006
#define WASM_TPM2_ALG_SHA256 0x000b
#define WASM_TPM2_ALG_SHA384 0x000c
#define WASM_TPM2_ALG_SHA512 0x000d
#define WASM_TPM2_ALG_CFB    0x0043
#define WASM_TPM2_ALG_MLKEM  0x00A0
#define WASM_TPM2_ALG_MLDSA  0x00A1

#define WASM_TPM2_MLKEM_512  0x0001
#define WASM_TPM2_MLKEM_768  0x0002
#define WASM_TPM2_MLKEM_1024 0x0003
#define WASM_TPM2_MLDSA_44   0x0001
#define WASM_TPM2_MLDSA_65   0x0002
#define WASM_TPM2_MLDSA_87   0x0003

#define WASM_TPMA_NV_PLATFORMCREATE 0x40000000u
#define WASM_TPMA_NV_AUTHREAD       0x40000u
#define WASM_TPMA_NV_NO_DA          0x2000000u
#define WASM_TPMA_NV_PPWRITE        0x1u
#define WASM_TPMA_NV_PPREAD         0x10000u
#define WASM_TPMA_NV_OWNERREAD      0x20000u
#define WASM_TPMA_NV_WRITEDEFINE    0x2000u

/* Persistent EK handles — mirror swtpm.c:496-505. */
#define WASM_TPM2_EK_MLKEM768_HANDLE       0x810100A0u
#define WASM_TPM2_V2P7_EK_MLKEM512_HANDLE  0x810100B0u
#define WASM_TPM2_V2P7_EK_MLKEM1024_HANDLE 0x810100B2u
#define WASM_TPM2_V2P7_EK_MLDSA44_HANDLE   0x810100B4u
#define WASM_TPM2_V2P7_EK_MLDSA65_HANDLE   0x810100B5u
#define WASM_TPM2_V2P7_EK_MLDSA87_HANDLE   0x810100B6u

#define WASM_V2P7_EK_KEYFLAGS_STORAGE 0x000300B2u
#define WASM_V2P7_EK_KEYFLAGS_SIGNING 0x000500B2u

/* AS2BE / AS4BE — swtpm.c:52-53. */
#define WASM_AS2BE(VAL) (uint8_t)(((VAL) >> 8) & 0xff), (uint8_t)((VAL) & 0xff)
#define WASM_AS4BE(VAL) WASM_AS2BE((VAL) >> 16), WASM_AS2BE(VAL)

/* TPM command/auth structs — swtpm.c:58-68 + 524-538. */
struct wasm_tpm_req_header {
    uint16_t tag;
    uint32_t size;
    uint32_t ordinal;
} __attribute__((packed));

struct wasm_tpm2_authblock {
    uint32_t auth;
    uint16_t nonceSize;
    uint8_t continueSession;
    uint16_t pwdSize;
} __attribute__((packed));

#define WASM_TPM_REQ_HEADER_INIT(TAG, SIZE, ORD) \
    { .tag = htobe16(TAG), .size = htobe32(SIZE), .ordinal = htobe32(ORD), }

#define WASM_TPM2_AUTHBLOCK_INIT(AUTH) \
    { .auth = htobe32(AUTH), .nonceSize = htobe16(0), \
      .continueSession = 0, .pwdSize = htobe16(0), }

/* ── glib-stripped helpers ──────────────────────────────────────────────── */

/* memconcat — swtpm_utils.c:163-196 with g_malloc/g_realloc → malloc/realloc. */
static ssize_t wasm_memconcat(unsigned char **buffer, ...)
{
    va_list ap;
    ssize_t offset = 0;
    size_t allocated = 128;
    unsigned char *p;

    *buffer = (unsigned char *)malloc(allocated);
    if (!*buffer) return -1;
    p = *buffer;

    va_start(ap, buffer);
    while (1) {
        unsigned char *i = va_arg(ap, unsigned char *);
        size_t len;
        if (i == NULL) break;
        len = va_arg(ap, size_t);
        if ((size_t)offset + len > allocated) {
            unsigned char *r;
            allocated = allocated + offset + len;
            r = (unsigned char *)realloc(*buffer, allocated);
            if (!r) { free(*buffer); *buffer = NULL; va_end(ap); return -1; }
            *buffer = r; p = *buffer;
        }
        memcpy(&p[offset], i, len);
        offset += len;
    }
    va_end(ap);
    return offset;
}

/* In-process TPM transport: replaces transfer() (swtpm.c socket call).
 * Returns 0 on TPM success, positive TPM RC on TPM error, -1 on lib failure.
 * Caller-supplied resp_out / resp_out_max receives the full response bytes
 * including the 10-byte header; resp_len returns the actual length. */
static int wasm_tpm_transfer(const void *req, size_t reqlen,
                             unsigned char *resp_out, size_t resp_out_max,
                             size_t *resp_len)
{
    unsigned char *resp  = NULL;
    uint32_t respLen     = 0;
    uint32_t respBufSize = 0;
    TPM_RESULT rc = TPMLIB_Process(&resp, &respLen, &respBufSize,
                                   (unsigned char *)req, (uint32_t)reqlen);
    if (rc != TPM_SUCCESS) {
        if (resp) free(resp);
        return -1;
    }
    int tpm_rc = 0;
    if (respLen >= 10) {
        tpm_rc = ((int)resp[6] << 24) | ((int)resp[7] << 16)
               | ((int)resp[8] << 8)  |  (int)resp[9];
    }
    if (resp_out && respLen <= resp_out_max) {
        memcpy(resp_out, resp, respLen);
        if (resp_len) *resp_len = respLen;
    } else if (resp_len) {
        *resp_len = respLen;
    }
    if (resp) free(resp);
    return tpm_rc;
}

/* ── TPM command primitives ─────────────────────────────────────────────── */

/* swtpm_tpm2_flushcontext — swtpm.c:798-810. */
static int wasm_tpm2_flushcontext(uint32_t handle)
{
    struct __attribute__((packed)) {
        struct wasm_tpm_req_header hdr;
        uint32_t flushHandle;
    } req = {
        .hdr = WASM_TPM_REQ_HEADER_INIT(WASM_TPM2_ST_NO_SESSIONS, sizeof(req),
                                        WASM_TPM2_CC_FLUSHCONTEXT),
        .flushHandle = htobe32(handle),
    };
    return wasm_tpm_transfer(&req, sizeof(req), NULL, 0, NULL);
}

/* swtpm_tpm2_evictcontrol — swtpm.c:813-833. */
static int wasm_tpm2_evictcontrol(uint32_t curr_handle, uint32_t perm_handle)
{
    struct __attribute__((packed)) {
        struct wasm_tpm_req_header hdr;
        uint32_t auth;
        uint32_t objectHandle;
        uint32_t authblockLen;
        struct wasm_tpm2_authblock authblock;
        uint32_t persistentHandle;
    } req = {
        .hdr = WASM_TPM_REQ_HEADER_INIT(WASM_TPM2_ST_SESSIONS, sizeof(req),
                                        WASM_TPM2_CC_EVICTCONTROL),
        .auth = htobe32(WASM_TPM2_RH_OWNER),
        .objectHandle = htobe32(curr_handle),
        .authblockLen = htobe32(sizeof(req.authblock)),
        .authblock = WASM_TPM2_AUTHBLOCK_INIT(WASM_TPM2_RS_PW),
        .persistentHandle = htobe32(perm_handle),
    };
    return wasm_tpm_transfer(&req, sizeof(req), NULL, 0, NULL);
}

/* swtpm_tpm2_nvdefinespace — swtpm.c:2135-2171. */
static int wasm_tpm2_nvdefinespace(uint32_t nvindex, uint32_t nvindexattrs,
                                   uint16_t data_len)
{
    struct wasm_tpm_req_header hdr =
        WASM_TPM_REQ_HEADER_INIT(WASM_TPM2_ST_SESSIONS, 0,
                                 WASM_TPM2_CC_NV_DEFINESPACE);
    struct wasm_tpm2_authblock authblock = WASM_TPM2_AUTHBLOCK_INIT(WASM_TPM2_RS_PW);
    unsigned char nvpublic_static[14];
    unsigned char *req = NULL;
    ssize_t reqlen;
    int rc;

    /* TPMS_NV_PUBLIC: { nvIndex(4), nameAlg(2), attributes(4),
     *                   authPolicy.size(2), dataSize(2) } */
    const unsigned char nvpublic_bytes[14] = {
        WASM_AS4BE(nvindex), WASM_AS2BE(WASM_TPM2_ALG_SHA256),
        WASM_AS4BE(nvindexattrs),
        WASM_AS2BE(0), WASM_AS2BE(data_len),
    };
    memcpy(nvpublic_static, nvpublic_bytes, sizeof(nvpublic_static));

    const unsigned char auth_prefix[8] = {
        WASM_AS4BE(WASM_TPM2_RH_PLATFORM), WASM_AS4BE(sizeof(authblock)),
    };
    const unsigned char nvpublic_len_prefix[4] = {
        WASM_AS2BE(0),                                     /* empty auth */
        WASM_AS2BE(sizeof(nvpublic_static)),               /* TPM2B_NV_PUBLIC size */
    };
    reqlen = wasm_memconcat(&req,
                            (unsigned char *)&hdr, sizeof(hdr),
                            (unsigned char *)auth_prefix, (size_t)8,
                            (unsigned char *)&authblock, sizeof(authblock),
                            (unsigned char *)nvpublic_len_prefix, (size_t)4,
                            nvpublic_static, sizeof(nvpublic_static),
                            (unsigned char *)NULL);
    if (reqlen < 0) return -1;
    ((struct wasm_tpm_req_header *)req)->size = htobe32((uint32_t)reqlen);

    rc = wasm_tpm_transfer(req, (size_t)reqlen, NULL, 0, NULL);
    free(req);
    return rc;
}

/* swtpm_tpm2_nv_write — swtpm.c:2173-2212 (chunked at 1024 B). */
static int wasm_tpm2_nv_write(uint32_t nvindex,
                              const unsigned char *data, size_t data_len)
{
    struct wasm_tpm_req_header hdr =
        WASM_TPM_REQ_HEADER_INIT(WASM_TPM2_ST_SESSIONS, 0,
                                 WASM_TPM2_CC_NV_WRITE);
    struct wasm_tpm2_authblock authblock = WASM_TPM2_AUTHBLOCK_INIT(WASM_TPM2_RS_PW);
    size_t offset = 0;
    int rc;

    while (offset < data_len) {
        size_t txlen = data_len - offset;
        if (txlen > 1024) txlen = 1024;

        const unsigned char prefix[12] = {
            WASM_AS4BE(WASM_TPM2_RH_PLATFORM),
            WASM_AS4BE(nvindex),
            WASM_AS4BE(sizeof(authblock)),
        };
        const unsigned char txlen_prefix[2] = { WASM_AS2BE(txlen) };
        const unsigned char offset_prefix[2] = { WASM_AS2BE(offset) };

        unsigned char *req = NULL;
        ssize_t reqlen = wasm_memconcat(&req,
                                        (unsigned char *)&hdr, sizeof(hdr),
                                        (unsigned char *)prefix, (size_t)12,
                                        (unsigned char *)&authblock, sizeof(authblock),
                                        (unsigned char *)txlen_prefix, (size_t)2,
                                        (unsigned char *)&data[offset], txlen,
                                        (unsigned char *)offset_prefix, (size_t)2,
                                        (unsigned char *)NULL);
        if (reqlen < 0) return -1;
        ((struct wasm_tpm_req_header *)req)->size = htobe32((uint32_t)reqlen);
        rc = wasm_tpm_transfer(req, (size_t)reqlen, NULL, 0, NULL);
        free(req);
        if (rc != 0) return rc;
        offset += txlen;
    }
    return 0;
}

/* ── PQC CreatePrimary ──────────────────────────────────────────────────── */

/* swtpm_tpm2_createprimary_pqc — swtpm.c:1167-1259, GLib stripped.
 * pubkey_out (caller-allocated, max pubkey_out_max bytes) receives the raw
 * pubkey bytes on success. *pubkey_out_len gets the count. curr_handle_out
 * gets the transient handle. */
static int wasm_tpm2_createprimary_pqc(uint32_t primaryhandle,
                                       uint16_t algid, uint16_t hashalg,
                                       uint32_t keyflags,
                                       const unsigned char *authpolicy, size_t authpolicy_len,
                                       const unsigned char *parms, size_t parms_len,
                                       uint16_t exp_pksize,
                                       size_t off, uint32_t *curr_handle_out,
                                       unsigned char *pubkey_out, size_t pubkey_out_max,
                                       size_t *pubkey_out_len)
{
    struct wasm_tpm_req_header hdr =
        WASM_TPM_REQ_HEADER_INIT(WASM_TPM2_ST_SESSIONS, 0,
                                 WASM_TPM2_CC_CREATEPRIMARY);
    struct wasm_tpm2_authblock authblock = WASM_TPM2_AUTHBLOCK_INIT(WASM_TPM2_RS_PW);
    unsigned char *public = NULL;
    unsigned char *createprimary = NULL;
    ssize_t public_len = 0;
    ssize_t createprimary_len = 0;
    unsigned char tpmresp[4096];
    size_t tpmresp_len = 0;
    int rc;

    /* TPMT_PUBLIC: type, nameAlg, objAttrs, authPolicy.size + bytes, parms,
     * unique.size=0 */
    const unsigned char pub_prefix[10] = {
        WASM_AS2BE(algid), WASM_AS2BE(hashalg),
        WASM_AS4BE(keyflags),
        WASM_AS2BE(authpolicy_len),
    };
    const unsigned char unique_zero[2] = { WASM_AS2BE(0) };
    public_len = wasm_memconcat(&public,
                                (unsigned char *)pub_prefix, (size_t)10,
                                (unsigned char *)authpolicy, authpolicy_len,
                                (unsigned char *)parms, parms_len,
                                (unsigned char *)unique_zero, (size_t)2,
                                (unsigned char *)NULL);
    if (public_len < 0) { rc = -1; goto cleanup; }

    /* CreatePrimary: hdr + auth(4) + authblockLen(4) + authblock + inSensitive(2,4,2)
     * + TPM2B_PUBLIC{size(2), public[]} + outsideInfo(4) + creationPCR(2,4) */
    const unsigned char cp_auth_prefix[8] = {
        WASM_AS4BE(primaryhandle), WASM_AS4BE(sizeof(authblock)),
    };
    const unsigned char cp_inSens_pubLen[8] = {
        WASM_AS2BE(4),               /* inSensitive size: 4 = 2(authValue.size=0)+2(data.size=0) */
        WASM_AS4BE(0),               /* authValue.size + data.size both 0 */
        WASM_AS2BE(public_len),      /* TPM2B_PUBLIC size */
    };
    const unsigned char cp_tail[6] = {
        WASM_AS4BE(0),               /* outsideInfo size */
        WASM_AS2BE(0),               /* creationPCR.count = 0 */
    };
    createprimary_len = wasm_memconcat(&createprimary,
                                       (unsigned char *)&hdr, sizeof(hdr),
                                       (unsigned char *)cp_auth_prefix, (size_t)8,
                                       (unsigned char *)&authblock, sizeof(authblock),
                                       (unsigned char *)cp_inSens_pubLen, (size_t)8,
                                       public, (size_t)public_len,
                                       (unsigned char *)cp_tail, (size_t)6,
                                       (unsigned char *)NULL);
    if (createprimary_len < 0) { rc = -1; goto cleanup; }
    ((struct wasm_tpm_req_header *)createprimary)->size =
        htobe32((uint32_t)createprimary_len);

    rc = wasm_tpm_transfer(createprimary, (size_t)createprimary_len,
                           tpmresp, sizeof(tpmresp), &tpmresp_len);
    if (rc != 0) goto cleanup;

    /* Parse out: response handle at offset 10 (after 10-byte header). */
    if (tpmresp_len < 14) { rc = -1; goto cleanup; }
    if (curr_handle_out) {
        *curr_handle_out = ((uint32_t)tpmresp[10] << 24) |
                           ((uint32_t)tpmresp[11] << 16) |
                           ((uint32_t)tpmresp[12] << 8)  |
                            (uint32_t)tpmresp[13];
    }

    /* Pubkey size at byte `off` (BE16), bytes follow. */
    if (tpmresp_len < off + 2) { rc = -1; goto cleanup; }
    uint16_t pksize = ((uint16_t)tpmresp[off] << 8) | (uint16_t)tpmresp[off + 1];
    if (pksize != exp_pksize) {
        printf("wasm createprimary_pqc: pksize %u != expected %u at off %zu\n",
               (unsigned)pksize, (unsigned)exp_pksize, off);
        rc = -1; goto cleanup;
    }
    if (tpmresp_len < off + 2 + pksize) { rc = -1; goto cleanup; }
    if (pubkey_out && pubkey_out_len) {
        if ((size_t)pksize > pubkey_out_max) { rc = -1; goto cleanup; }
        memcpy(pubkey_out, &tpmresp[off + 2], pksize);
        *pubkey_out_len = pksize;
    }
    rc = 0;

cleanup:
    free(public);
    free(createprimary);
    return rc;
}

/* ── Six V2.7 EK creators (mirror swtpm.c:1289-1425) ────────────────────── */

#define WASM_DEF_EK_MLKEM(N, NAMEALG, AESBITS, POLICYB, POLICY_LEN, PKSIZE, PARMSET) \
static int wasm_create_ek_mlkem##N(uint32_t *curr, unsigned char *pub,           \
                                   size_t pub_max, size_t *pub_len) {            \
    const unsigned char parms[] = {                                              \
        WASM_AS2BE(WASM_TPM2_ALG_AES), WASM_AS2BE(AESBITS),                      \
        WASM_AS2BE(WASM_TPM2_ALG_CFB), WASM_AS2BE(PARMSET),                      \
    };                                                                            \
    size_t off = 30 + (POLICY_LEN) + sizeof(parms);                              \
    return wasm_tpm2_createprimary_pqc(WASM_TPM2_RH_ENDORSEMENT,                 \
        WASM_TPM2_ALG_MLKEM, NAMEALG, WASM_V2P7_EK_KEYFLAGS_STORAGE,             \
        (POLICYB), (POLICY_LEN), parms, sizeof(parms), (PKSIZE),                 \
        off, curr, pub, pub_max, pub_len);                                       \
}

WASM_DEF_EK_MLKEM(512,  WASM_TPM2_ALG_SHA256, 128, tcg_policyB_sha256,
                  TCG_POLICYB_SHA256_SIZE,  800, WASM_TPM2_MLKEM_512)
WASM_DEF_EK_MLKEM(768,  WASM_TPM2_ALG_SHA384, 256, tcg_policyB_sha384,
                  TCG_POLICYB_SHA384_SIZE, 1184, WASM_TPM2_MLKEM_768)
WASM_DEF_EK_MLKEM(1024, WASM_TPM2_ALG_SHA512, 256, tcg_policyB_sha512,
                  TCG_POLICYB_SHA512_SIZE, 1568, WASM_TPM2_MLKEM_1024)

#define WASM_DEF_EK_MLDSA(N, NAMEALG, POLICYB, POLICY_LEN, PKSIZE, PARMSET) \
static int wasm_create_ek_mldsa##N(uint32_t *curr, unsigned char *pub,      \
                                   size_t pub_max, size_t *pub_len) {       \
    const unsigned char parms[] = { WASM_AS2BE(PARMSET), 0x00 };            \
    size_t off = 30 + (POLICY_LEN) + sizeof(parms);                         \
    return wasm_tpm2_createprimary_pqc(WASM_TPM2_RH_ENDORSEMENT,            \
        WASM_TPM2_ALG_MLDSA, NAMEALG, WASM_V2P7_EK_KEYFLAGS_SIGNING,        \
        (POLICYB), (POLICY_LEN), parms, sizeof(parms), (PKSIZE),            \
        off, curr, pub, pub_max, pub_len);                                  \
}

WASM_DEF_EK_MLDSA(44, WASM_TPM2_ALG_SHA256, tcg_policyB_sha256,
                  TCG_POLICYB_SHA256_SIZE, 1312, WASM_TPM2_MLDSA_44)
WASM_DEF_EK_MLDSA(65, WASM_TPM2_ALG_SHA384, tcg_policyB_sha384,
                  TCG_POLICYB_SHA384_SIZE, 1952, WASM_TPM2_MLDSA_65)
WASM_DEF_EK_MLDSA(87, WASM_TPM2_ALG_SHA512, tcg_policyB_sha512,
                  TCG_POLICYB_SHA512_SIZE, 2592, WASM_TPM2_MLDSA_87)

/* ── X.509 cert builder (mirror swtpm.c swtpm_pqc_build_cert_der) ───────── */

/* Caller frees *out_der with OPENSSL_free. */
static int wasm_pqc_build_cert_der(const char *subject_keytype,
                                   const char *subject_cn,
                                   const unsigned char *subject_pub,
                                   size_t subject_pub_len,
                                   unsigned char **out_der, int *out_der_len)
{
    EVP_PKEY *issuer_key = NULL;
    EVP_PKEY *subject_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    X509 *cert = NULL;
    X509_NAME *issuer_name = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int ret = -1;

    *out_der = NULL;
    *out_der_len = 0;

    /* Ephemeral ML-DSA-65 issuer key. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (!ctx) goto out;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto out;
    if (EVP_PKEY_keygen(ctx, &issuer_key) <= 0) goto out;
    EVP_PKEY_CTX_free(ctx); ctx = NULL;

    /* Subject pubkey from raw bytes. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, subject_keytype, NULL);
    if (!ctx) goto out;
    {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, (void *)subject_pub, subject_pub_len);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata_init(ctx) <= 0) goto out;
        if (EVP_PKEY_fromdata(ctx, &subject_key, EVP_PKEY_PUBLIC_KEY, params) <= 0)
            goto out;
    }

    cert = X509_new();
    if (!cert) goto out;
    if (X509_set_version(cert, 2) != 1) goto out;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1) goto out;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), 0)) goto out;
    if (!X509_gmtime_adj(X509_getm_notAfter(cert), (long)10 * 365 * 24 * 3600))
        goto out;
    if (X509_set_pubkey(cert, subject_key) != 1) goto out;

    {
        X509_NAME *subj = X509_get_subject_name(cert);
        if (X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                (const unsigned char *)subject_cn, -1, -1, 0) != 1) goto out;
        if (X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
                (const unsigned char *)"pqctoday-tpm", -1, -1, 0) != 1) goto out;
    }

    issuer_name = X509_NAME_new();
    if (!issuer_name) goto out;
    if (X509_NAME_add_entry_by_txt(issuer_name, "CN", MBSTRING_ASC,
            (const unsigned char *)"pqctoday-tpm PQC EK CA (ephemeral)",
            -1, -1, 0) != 1) goto out;
    if (X509_NAME_add_entry_by_txt(issuer_name, "O", MBSTRING_ASC,
            (const unsigned char *)"pqctoday-tpm", -1, -1, 0) != 1) goto out;
    if (X509_set_issuer_name(cert, issuer_name) != 1) goto out;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) goto out;
    if (EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, issuer_key, NULL) <= 0)
        goto out;
    if (X509_sign_ctx(cert, md_ctx) == 0) goto out;

    *out_der_len = i2d_X509(cert, out_der);
    if (*out_der_len <= 0 || *out_der == NULL) {
        *out_der = NULL; *out_der_len = 0; goto out;
    }
    ret = 0;

out:
    EVP_MD_CTX_free(md_ctx);
    X509_NAME_free(issuer_name);
    X509_free(cert);
    EVP_PKEY_free(subject_key);
    EVP_PKEY_free(issuer_key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ── V2.7 §5.3.1 NV cert writer (mirror swtpm.c provisioning helper) ────── */

struct wasm_v2p7_ek_spec {
    const char *keytype;     /* OpenSSL EVP keytype name */
    const char *cn;          /* Subject CN */
    uint32_t    nvindex;     /* §5.3.1 NV cert slot */
    uint32_t    handle;      /* persistent EK handle */
    uint16_t    pub_len;     /* FIPS pubkey size */
    int (*creator)(uint32_t *, unsigned char *, size_t, size_t *);
};

/* Status accumulator (read out via tpm_wasm_get_v2p7_status). */
static uint8_t s_v2p7_status[6] = {0,0,0,0,0,0};  /* 0=untried, 1=ok, 2=fail */
static char s_v2p7_log[1024] = {0};

static void wasm_v2p7_log(const char *fmt, ...)
{
    va_list ap;
    char tmp[256];
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    printf("[V2.7 prov] %s\n", tmp);
    /* Also keep an in-memory tail log so JS can surface failures. */
    size_t cur = strlen(s_v2p7_log);
    size_t add = strlen(tmp);
    if (cur + add + 2 < sizeof(s_v2p7_log)) {
        memcpy(s_v2p7_log + cur, tmp, add);
        s_v2p7_log[cur + add] = '\n';
        s_v2p7_log[cur + add + 1] = '\0';
    }
}

/* Provision one EK: CreatePrimary + EvictControl + Flush + build cert +
 * NV_DefineSpace + NV_Write. Returns 0 on full success, nonzero otherwise.
 * Best-effort: cert/NV failures don't abort. */
static int wasm_provision_one_v2p7_ek(const struct wasm_v2p7_ek_spec *s,
                                      size_t slot_idx)
{
    uint32_t curr_handle = 0;
    unsigned char pub[3072];
    size_t pub_len = 0;
    unsigned char *cert_der = NULL;
    int cert_der_len = 0;
    int rc;

    const uint32_t nv_attrs = WASM_TPMA_NV_PLATFORMCREATE |
                              WASM_TPMA_NV_AUTHREAD |
                              WASM_TPMA_NV_OWNERREAD |
                              WASM_TPMA_NV_PPREAD |
                              WASM_TPMA_NV_PPWRITE |
                              WASM_TPMA_NV_NO_DA |
                              WASM_TPMA_NV_WRITEDEFINE;

    rc = s->creator(&curr_handle, pub, sizeof(pub), &pub_len);
    if (rc != 0) {
        wasm_v2p7_log("%s CreatePrimary failed rc=0x%x", s->keytype, rc);
        s_v2p7_status[slot_idx] = 2;
        return rc;
    }
    if (pub_len != s->pub_len) {
        wasm_v2p7_log("%s pubkey size %zu != expected %u", s->keytype,
                      pub_len, s->pub_len);
        wasm_tpm2_flushcontext(curr_handle);
        s_v2p7_status[slot_idx] = 2;
        return -1;
    }

    /* Persist the EK at its V2.7 persistent handle.  TPM_RC_NV_DEFINED or
     * similar means the handle was already persistent from a prior run —
     * benign. */
    int evict_rc = wasm_tpm2_evictcontrol(curr_handle, s->handle);
    if (evict_rc != 0) {
        wasm_v2p7_log("%s EvictControl 0x%08x rc=0x%x (best-effort)",
                      s->keytype, s->handle, evict_rc);
    }
    wasm_tpm2_flushcontext(curr_handle);

    /* Build the V2.7 X.509 EK cert. */
    rc = wasm_pqc_build_cert_der(s->keytype, s->cn, pub, pub_len,
                                 &cert_der, &cert_der_len);
    if (rc != 0 || cert_der == NULL || cert_der_len <= 0) {
        wasm_v2p7_log("%s cert build failed", s->keytype);
        s_v2p7_status[slot_idx] = 2;
        return -1;
    }

    /* Write to §5.3.1 NV slot. */
    rc = wasm_tpm2_nvdefinespace(s->nvindex, nv_attrs,
                                 (uint16_t)cert_der_len);
    if (rc != 0) {
        wasm_v2p7_log("%s NV_DefineSpace 0x%08x rc=0x%x", s->keytype,
                      s->nvindex, rc);
        OPENSSL_free(cert_der);
        s_v2p7_status[slot_idx] = 2;
        return rc;
    }
    rc = wasm_tpm2_nv_write(s->nvindex, cert_der, (size_t)cert_der_len);
    if (rc != 0) {
        wasm_v2p7_log("%s NV_Write 0x%08x rc=0x%x", s->keytype,
                      s->nvindex, rc);
        OPENSSL_free(cert_der);
        s_v2p7_status[slot_idx] = 2;
        return rc;
    }

    wasm_v2p7_log("%s @0x%08x  EK + cert (%d B) → NV 0x%08x  OK",
                  s->keytype, s->handle, cert_der_len, s->nvindex);
    OPENSSL_free(cert_der);
    s_v2p7_status[slot_idx] = 1;
    return 0;
}

/* tpm_wasm_provision_v2p7 — call once after tpm_wasm_startup.  Provisions
 * the 6 V2.7 EKs + cert NV slots in-process.  Returns 0 if at least one
 * slot succeeded (so a partial-PQC-build TPM still surfaces what it has),
 * negative if every slot failed. */
EMSCRIPTEN_KEEPALIVE
int tpm_wasm_provision_v2p7(void)
{
    /* Reset the status accumulator on re-entry (idempotent). */
    memset(s_v2p7_status, 0, sizeof(s_v2p7_status));
    s_v2p7_log[0] = '\0';

    const struct wasm_v2p7_ek_spec slots[6] = {
        { "ML-KEM-512",  "TPM EK (ML-KEM-512)",
           TCG_NV_EKCERT_MLKEM_512,  WASM_TPM2_V2P7_EK_MLKEM512_HANDLE,
           800,  wasm_create_ek_mlkem512  },
        { "ML-KEM-768",  "TPM EK (ML-KEM-768)",
           TCG_NV_EKCERT_MLKEM_768,  WASM_TPM2_EK_MLKEM768_HANDLE,
          1184, wasm_create_ek_mlkem768  },
        { "ML-KEM-1024", "TPM EK (ML-KEM-1024)",
           TCG_NV_EKCERT_MLKEM_1024, WASM_TPM2_V2P7_EK_MLKEM1024_HANDLE,
          1568, wasm_create_ek_mlkem1024 },
        { "ML-DSA-44",   "TPM EK (ML-DSA-44)",
           TCG_NV_EKCERT_MLDSA_44,   WASM_TPM2_V2P7_EK_MLDSA44_HANDLE,
          1312, wasm_create_ek_mldsa44   },
        { "ML-DSA-65",   "TPM EK (ML-DSA-65)",
           TCG_NV_EKCERT_MLDSA_65,   WASM_TPM2_V2P7_EK_MLDSA65_HANDLE,
          1952, wasm_create_ek_mldsa65   },
        { "ML-DSA-87",   "TPM EK (ML-DSA-87)",
           TCG_NV_EKCERT_MLDSA_87,   WASM_TPM2_V2P7_EK_MLDSA87_HANDLE,
          2592, wasm_create_ek_mldsa87   },
    };

    int ok_count = 0;
    for (size_t i = 0; i < 6; i++) {
        (void)wasm_provision_one_v2p7_ek(&slots[i], i);
        if (s_v2p7_status[i] == 1) ok_count++;
    }
    wasm_v2p7_log("V2.7 provisioning complete: %d/6 OK", ok_count);
    return (ok_count > 0) ? 0 : -1;
}

/* tpm_wasm_get_v2p7_status — copy the 6-byte status array (one byte per
 * EK slot, indexes match the array above; 0=untried, 1=ok, 2=fail). */
EMSCRIPTEN_KEEPALIVE
int tpm_wasm_get_v2p7_status(uint8_t *out, uint32_t out_max)
{
    if (out_max < 6) return -1;
    memcpy(out, s_v2p7_status, 6);
    return 6;
}

/* tpm_wasm_get_v2p7_log — copy the human-readable tail log (NUL-terminated).
 * Returns bytes copied excluding NUL. */
EMSCRIPTEN_KEEPALIVE
int tpm_wasm_get_v2p7_log(char *out, uint32_t out_max)
{
    if (!out || out_max == 0) return -1;
    size_t cur = strlen(s_v2p7_log);
    size_t copy = (cur + 1 <= out_max) ? cur : (out_max - 1);
    memcpy(out, s_v2p7_log, copy);
    out[copy] = '\0';
    return (int)copy;
}
