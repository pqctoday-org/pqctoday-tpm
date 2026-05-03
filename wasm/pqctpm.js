/**
 * pqctpm.js — Async JS wrapper for the pqctoday-tpm WASM module.
 *
 * Usage:
 *   import { createPqcTpm } from './pqctpm.js';
 *
 *   const tpm = await createPqcTpm({ wasmPath: '/dist/pqctpm.wasm' });
 *   // or resume from saved state:
 *   const saved = localStorage.getItem('pqctpm-nv');
 *   const tpm = await createPqcTpm({ nvState: saved ? b64ToBytes(saved) : null });
 *
 *   const resp = tpm.process(buildStartup(TPM_SU_CLEAR));
 *   console.log('RC:', getResponseCode(resp));
 *
 *   // persist NV after sensitive operations
 *   localStorage.setItem('pqctpm-nv', bytesToB64(tpm.getNvState()));
 *   tpm.terminate();
 */

// PqcTpmModule is the Emscripten-generated factory injected by pqctpm.js (dist)
// Import it as a side-effect, then use the factory below.

const TPM_SUCCESS   = 0;
const TPMLIB_TPM_VERSION_2 = 2;

/**
 * @typedef {Object} PqcTpm
 * @property {(cmd: Uint8Array) => Uint8Array} process - Send a raw TPM2 command, get response.
 * @property {() => Uint8Array} getNvState - Export NV state bytes for persistence.
 * @property {(data: Uint8Array) => void} setNvState - Restore NV state (before startup).
 * @property {() => number} nvSize - NV_MEMORY_SIZE in bytes.
 * @property {() => void} terminate - Shut down the TPM library.
 */

/**
 * createPqcTpm — load the WASM module and return a ready-to-use TPM handle.
 *
 * @param {Object}      [opts]
 * @param {string}      [opts.wasmPath]  URL/path to pqctpm.wasm (default: ./pqctpm.wasm)
 * @param {string}      [opts.profile]   TCG profile string (default: 'default-v1')
 * @param {Uint8Array}  [opts.nvState]   Saved NV bytes to resume from (optional)
 * @returns {Promise<PqcTpm>}
 */
export async function createPqcTpm(opts = {}) {
  const {
    wasmPath = './pqctpm.wasm',
    profile  = 'default-v1',
    nvState  = null,
  } = opts;

  // Load the Emscripten module factory (pqctpm.js from dist/). The script must
  // be loaded by the caller before createPqcTpm is called, OR import it here:
  if (typeof PqcTpmModule === 'undefined') {
    throw new Error(
      'PqcTpmModule not found. Load dist/pqctpm.js before calling createPqcTpm().'
    );
  }

  const mod = await PqcTpmModule({
    locateFile: (f) => (f.endsWith('.wasm') ? wasmPath : f),
  });

  // ── cwrap helpers ──────────────────────────────────────────────────────────
  const startup    = mod.cwrap('tpm_wasm_startup',     'number', ['string']);
  const processRaw = mod.cwrap('tpm_wasm_process',     'number', ['number', 'number', 'number', 'number']);
  const getNvSize  = mod.cwrap('tpm_wasm_get_nv_size', 'number', []);
  const getNvRaw   = mod.cwrap('tpm_wasm_get_nv',      'number', ['number', 'number']);
  const setNvRaw   = mod.cwrap('tpm_wasm_set_nv',      'number', ['number', 'number']);
  const terminate  = mod.cwrap('TPMLIB_Terminate',     null,     []);

  const NV_SIZE = getNvSize();

  // ── Optionally restore NV before startup ──────────────────────────────────
  if (nvState) {
    if (nvState.byteLength !== NV_SIZE) {
      throw new Error(
        `nvState size mismatch: got ${nvState.byteLength}, need ${NV_SIZE}`
      );
    }
    const nvPtr = mod._malloc(NV_SIZE);
    mod.HEAPU8.set(nvState, nvPtr);
    const rc = setNvRaw(nvPtr, NV_SIZE);
    mod._free(nvPtr);
    if (rc !== 0) throw new Error(`tpm_wasm_set_nv failed: ${rc}`);
  }

  // ── Startup (manufacture + TPM2_Startup(SU_CLEAR)) ────────────────────────
  const startRc = startup(profile);
  if (startRc !== TPM_SUCCESS) {
    throw new Error(`tpm_wasm_startup failed: 0x${startRc.toString(16)}`);
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Send raw TPM2 command bytes; returns response as Uint8Array. */
  function process(cmd) {
    const cmdBuf  = mod._malloc(cmd.byteLength);
    const respBuf = mod._malloc(4096);
    mod.HEAPU8.set(cmd, cmdBuf);

    const respLen = processRaw(cmdBuf, cmd.byteLength, respBuf, 4096);
    mod._free(cmdBuf);

    if (respLen < 0) {
      mod._free(respBuf);
      throw new Error('TPMLIB_Process failed');
    }
    const resp = mod.HEAPU8.slice(respBuf, respBuf + respLen);
    mod._free(respBuf);
    return resp;
  }

  /** Export current NV state for persistence. */
  function getNvState() {
    const ptr = mod._malloc(NV_SIZE);
    const copied = getNvRaw(ptr, NV_SIZE);
    if (copied === 0) { mod._free(ptr); throw new Error('tpm_wasm_get_nv failed'); }
    const out = mod.HEAPU8.slice(ptr, ptr + NV_SIZE);
    mod._free(ptr);
    return out;
  }

  return { process, getNvState, nvSize: NV_SIZE, terminate };
}

// ── Helper utilities ─────────────────────────────────────────────────────────

/** Extract RC from a TPM2 response buffer. */
export function getResponseCode(resp) {
  if (resp.byteLength < 10) return -1;
  return (resp[6] << 24) | (resp[7] << 16) | (resp[8] << 8) | resp[9];
}

/** Build a TPM2_Startup command. su: 0x0000 = SU_CLEAR, 0x0001 = SU_STATE */
export function buildStartup(su = 0x0000) {
  return new Uint8Array([
    0x80, 0x01,                   // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0C,       // size = 12
    0x00, 0x00, 0x01, 0x44,       // TPM_CC_Startup
    (su >> 8) & 0xff, su & 0xff,  // TPM_SU
  ]);
}

export const TPM_SU_CLEAR = 0x0000;
export const TPM_SU_STATE = 0x0001;

/** Base64 ↔ Uint8Array for localStorage persistence */
export function bytesToB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
export function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
