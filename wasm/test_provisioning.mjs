/**
 * test_provisioning.mjs — Node-level test of the WASM provisioning flow.
 *
 * Equivalent discipline to the native test scripts under tests/compliance/:
 * exercise the actual C code paths added in wasm/wasm_platform.c
 * (tpm_wasm_provision_v2p7 + wasm_provision_one_v2p7_ek + the 6 EK creators
 * + the 3 AK creators), assert on observable post-conditions, without
 * needing a browser.
 *
 * The minimal stub bridge registered below mirrors what
 * pqctoday-hub/src/wasm/pqcCryptoBridge.ts implements in production today:
 * paramSet=2 only (ML-KEM-768 + ML-DSA-65). This catches the failure-mode
 * bug class (libtpms entering g_inFailureMode on un-bridged paramsets)
 * BEFORE any browser session sees it.
 *
 * Run: cd wasm && node test_provisioning.mjs
 * Exits 0 on all-green, 1 on any assertion failure.
 */
import { webcrypto } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import PqcTpmModule from './dist/pqctpm.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const WASM_PATH = join(__dirname, 'dist', 'pqctpm.wasm')

// ── Minimal stub bridge ──────────────────────────────────────────────────
// Matches pqcCryptoBridge.ts production coverage: ML-KEM-768 (paramSet=2)
// and ML-DSA-65 (paramSet=2). All other paramsets return -1 (the contract
// for "bridge does not handle this paramset"), which lets the C side
// detect and SKIP — NOT fall through to libtpms's placeholder validation
// path which trips g_inFailureMode.
//
// pubkeys must be the right FIPS size. Using DRBG-filled bytes is fine
// for provisioning — the test doesn't drive signing.
const MLKEM_768_PK = 1184
const MLDSA_65_PK = 1952

function drbg(size) {
  const out = new Uint8Array(size)
  webcrypto.getRandomValues(out)
  return out
}

function makeStubBridge(module) {
  return {
    mlkemKeygen(paramSet, _seed, _seedLen, pkOut, pkOutMax, skOut, skOutMax) {
      if (paramSet !== 2) return -1  // not implemented
      if (pkOutMax < MLKEM_768_PK || skOutMax < 64) return -2
      module.HEAPU8.set(drbg(MLKEM_768_PK), pkOut)
      module.HEAPU8.set(drbg(64), skOut)
      return MLKEM_768_PK
    },
    mlkemEncap() { return -1 },   // not exercised by provisioning
    mlkemDecap() { return -1 },
    mldsaKeygen(paramSet, _seed, _seedLen, pkOut, pkOutMax, skOut, skOutMax) {
      if (paramSet !== 2) return -1
      if (pkOutMax < MLDSA_65_PK || skOutMax < 64) return -2
      module.HEAPU8.set(drbg(MLDSA_65_PK), pkOut)
      module.HEAPU8.set(drbg(64), skOut)
      return MLDSA_65_PK
    },
    mldsaSign() { return -1 },    // not exercised by provisioning
  }
}

// ── Test runner ──────────────────────────────────────────────────────────
let pass = 0
let fail = 0

function assert(cond, label) {
  if (cond) {
    console.log(`  [PASS] ${label}`)
    pass++
  } else {
    console.log(`  [FAIL] ${label}`)
    fail++
  }
}

function u16be(v) { return [(v >>> 8) & 0xff, v & 0xff] }
function u32be(v) {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
}

function buildGetRandom(nBytes) {
  // TPM_ST_NO_SESSIONS, size=12, TPM_CC_GetRandom (0x17b), bytesRequested
  return new Uint8Array([
    ...u16be(0x8001),
    ...u32be(12),
    ...u32be(0x0000017b),
    ...u16be(nBytes),
  ])
}

function buildReadPublic(handle) {
  // TPM_ST_NO_SESSIONS, size=14, TPM_CC_ReadPublic (0x173), handle
  return new Uint8Array([
    ...u16be(0x8001),
    ...u32be(14),
    ...u32be(0x00000173),
    ...u32be(handle),
  ])
}

async function run() {
  console.log('=== WASM provisioning test — Node-side ===')
  console.log('  driver:    tpm_wasm_provision_v2p7 + helpers in wasm_platform.c')
  console.log('  bridge:    stub matching hub pqcCryptoBridge.ts coverage')
  console.log('             (ML-KEM-768 + ML-DSA-65 only)\n')

  globalThis.PqcTpmModule = PqcTpmModule
  const module = await PqcTpmModule({
    locateFile: () => WASM_PATH,
    print: () => {},
    printErr: () => {},
  })

  // 1. Startup
  const startup = module.cwrap('tpm_wasm_startup', 'number', ['string'])
  const startupRc = startup('')
  assert(startupRc === 0, `tpm_wasm_startup → rc=${startupRc} (expect 0)`)
  if (startupRc !== 0) { summary(); process.exit(1) }

  // 2. Register bridge BEFORE provisioning (matches hub init order)
  module._pqcBridge = makeStubBridge(module)
  assert(module._pqcBridge && typeof module._pqcBridge.mlkemKeygen === 'function',
         'stub bridge registered on Module._pqcBridge')

  // 3. Provision V2.7 EKs + AKs
  const provision = module.cwrap('tpm_wasm_provision_v2p7', 'number', [])
  const provisionRc = provision()
  assert(provisionRc === 0,
         `tpm_wasm_provision_v2p7 → rc=${provisionRc} (expect 0; ≥1 slot OK)`)

  // 4. Read status array
  const statusPtr = module._malloc(6)
  const getStatus = module.cwrap('tpm_wasm_get_v2p7_status', 'number',
                                 ['number', 'number'])
  const statusLen = getStatus(statusPtr, 6)
  const status = Array.from(module.HEAPU8.subarray(statusPtr, statusPtr + 6))
  module._free(statusPtr)
  assert(statusLen === 6, `get_v2p7_status returned ${statusLen} (expect 6)`)

  // Index map: 0=ML-KEM-512, 1=ML-KEM-768, 2=ML-KEM-1024,
  //            3=ML-DSA-44,  4=ML-DSA-65,  5=ML-DSA-87
  //
  // After the bridge architecture change (2026-05-13 v0.7.x):
  //   - C side calls CreatePrimary for ALL 6 paramsets — no pre-filter.
  //   - Bridge is invoked for each; if it returns -1, libtpms falls back to
  //     a DRBG-filled placeholder of the right FIPS pubkey size. CreatePrimary
  //     still succeeds; status=1.
  //   - In production (browser + softhsmv3-wasm), all 6 return real PQC pubkeys.
  //   - In this Node stub, only paramSet=2 returns real bytes; the other 4
  //     get libtpms placeholders. Structural success either way.
  //
  // So all 6 status=1 is the correct invariant here. The stronger
  // assertion — "are these REAL PQC keys?" — can only be made in the
  // browser end-to-end test (Quote → liboqs verify), not Node-only.
  for (let i = 0; i < 6; i++) {
    const labels = ['ML-KEM-512','ML-KEM-768','ML-KEM-1024','ML-DSA-44','ML-DSA-65','ML-DSA-87']
    assert(status[i] === 1,
      `${labels[i]} status=${status[i]} (expect 1=CreatePrimary succeeded with FIPS-sized pubkey, real-from-bridge or placeholder-from-libtpms-fallback)`)
  }

  // 5. TPM must NOT be in failure mode after provisioning. This is the
  //    regression-catching assertion for the failure-mode bug we hit
  //    earlier today — un-bridged paramsets MUST be skipped, never
  //    fall through to libtpms placeholder validation.
  const processCmd = module.cwrap('tpm_wasm_process', 'number',
                                  ['number', 'number', 'number', 'number'])
  function send(cmd, respMax = 4096) {
    const cmdPtr = module._malloc(cmd.length)
    module.HEAPU8.set(cmd, cmdPtr)
    const respPtr = module._malloc(respMax)
    const respLen = processCmd(cmdPtr, cmd.length, respPtr, respMax)
    const resp = new Uint8Array(module.HEAPU8.subarray(respPtr, respPtr + respLen))
    module._free(cmdPtr)
    module._free(respPtr)
    if (resp.length < 10) return { rc: -1, body: new Uint8Array(0) }
    const rc = (resp[6] << 24) | (resp[7] << 16) | (resp[8] << 8) | resp[9]
    return { rc, body: resp }
  }

  const gr = send(buildGetRandom(16))
  assert(gr.rc === 0,
         `TPM2_GetRandom after provisioning → rc=0x${gr.rc.toString(16)} (expect 0 — TPM NOT in failure mode)`)

  // 6. AK ML-DSA-65 must be persistent at 0x810100A1.
  const rp = send(buildReadPublic(0x810100a1), 4096)
  assert(rp.rc === 0,
         `TPM2_ReadPublic(0x810100A1 = ML-DSA-65 AK) → rc=0x${rp.rc.toString(16)} (expect 0; AK persisted)`)
  if (rp.rc === 0 && rp.body.length >= 32) {
    // outPublic TPM2B starts at offset 10; size(2), then TPMT_PUBLIC
    const outPubSize = (rp.body[10] << 8) | rp.body[11]
    // TPMT_PUBLIC: type(2)+nameAlg(2)+attrs(4)+authPolicy.size(2)+
    //              parms(3 = parmSet(2)+allowExternalMu(1)) +
    //              unique.size(2) starts at offset 13 within TPMT_PUBLIC
    const tpmtStart = 12  // after outPub.size
    const apSize = (rp.body[tpmtStart + 8] << 8) | rp.body[tpmtStart + 9]
    const uniqueSizeOff = tpmtStart + 10 + apSize + 3  // parms = 3 bytes
    const pkSize = (rp.body[uniqueSizeOff] << 8) | rp.body[uniqueSizeOff + 1]
    assert(pkSize === 1952,
           `ML-DSA-65 AK unique.size = ${pkSize} (expect 1952 per FIPS 204)`)
    assert(outPubSize > 0 && outPubSize < 4096,
           `ML-DSA-65 AK outPub.size = ${outPubSize} (sane range)`)
  }

  // 7. ML-KEM-768 EK must be persistent at 0x810100A0 (V2.7 reuses the
  //    pre-V2.7 ML-KEM-768 handle to keep the V1.85 compliance suite working).
  const rp2 = send(buildReadPublic(0x810100a0), 4096)
  assert(rp2.rc === 0,
         `TPM2_ReadPublic(0x810100A0 = ML-KEM-768 EK) → rc=0x${rp2.rc.toString(16)} (expect 0)`)

  // 8. TPM2_Quote with ML-DSA-65 AK at 0x810100A1 — same command the hub
  //    AttestationPanel.tsx emits. The stub bridge returns -1 from
  //    mldsaSign here (no real Rust crate in Node); we still expect the
  //    TPM to either (a) return a placeholder-signed Quote with RC=0, or
  //    (b) return a clean TPM error like TPM_RC_HANDLE or
  //    TPM_RC_AUTH_TYPE — but NOT TPM_RC_FAILURE (0x101) which would
  //    indicate a regression on the failure-mode trap we fixed today.
  function buildQuote(signHandle, qualifying, hashAlg, pcrBitmap) {
    const session = [...u32be(0x40000009), ...u16be(0), 0, ...u16be(0)] // empty pwd
    const inSchemeNull = u16be(0x0010)
    const pcrSel = [
      ...u32be(1),
      ...u16be(hashAlg),
      3,
      pcrBitmap[0], pcrBitmap[1], pcrBitmap[2],
    ]
    const body = [
      ...u32be(signHandle),
      ...u32be(session.length),
      ...session,
      ...u16be(qualifying.length),
      ...qualifying,
      ...inSchemeNull,
      ...pcrSel,
    ]
    return new Uint8Array([
      ...u16be(0x8002),         // TPM_ST_SESSIONS
      ...u32be(10 + body.length),
      ...u32be(0x00000158),     // TPM_CC_Quote
      ...body,
    ])
  }
  const qData = new Uint8Array([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
  ])
  const quote = send(
    buildQuote(0x810100a1, qData, 0x000b /* SHA256 */, [0x8f, 0, 0]),
    8192
  )
  assert(quote.rc !== 0x101,
         `TPM2_Quote(ML-DSA-65 AK) → rc=0x${quote.rc.toString(16)} — must NOT be 0x101 (failure mode) ${quote.rc === 0x101 ? '✗' : '✓'}`)
  // For the stub-bridge case (Node, no Rust ml-dsa), sign returns -1 →
  // libtpms placeholder fallback → Quote may succeed (rc=0 with garbage
  // sig) OR return a clean TPM error. Either is fine for this test —
  // the regression we care about is 0x101 specifically.
  console.log(`  [INFO] Quote rc=0x${quote.rc.toString(16)} (rc=0 OK with placeholder sig, or any non-0x101 TPM RC OK)`)

  // 9. Sanity: another GetRandom after Quote to confirm the TPM is STILL
  //    operational. Catches any failure-mode trip that Quote might induce.
  const gr2 = send(buildGetRandom(8))
  assert(gr2.rc === 0,
         `TPM2_GetRandom after Quote → rc=0x${gr2.rc.toString(16)} (TPM still operational)`)

  summary()
}

function summary() {
  console.log(`\n=== Summary: ${pass} passed, ${fail} failed ===`)
  process.exit(fail === 0 ? 0 : 1)
}

run().catch((e) => {
  console.error('FATAL:', e)
  process.exit(2)
})
