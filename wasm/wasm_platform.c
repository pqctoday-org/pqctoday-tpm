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
