/**
 * test_v185_capabilities.mjs — regression guard for the TCG TPM 2.0 Library
 * v185 Errata v1 (2026-03-12) version-capability constants.
 *
 * VendorInfo.h previously hardcoded TPM_SPEC_VERSION=183 and
 * PLATFORM_VERSION=0x00000106 (PC Client Platform TPM Profile v1.06) even
 * though this engine implements the V185 PQC command set and the current
 * published PTP is v1.07 — a stale-metadata bug found during the 2026-07-24
 * spec-alignment audit (see pqctoday-priv/plans/tpm-v185-errata-remediation-plan-2026-07-24.md).
 * Errata section 2.1 also retires TPM_SPEC_DAY_OF_YEAR in favor of
 * TPM_SPEC_ERRATA (same TPM_PT_DAY_OF_YEAR capability slot, new meaning) and
 * requires TPM_SPEC_YEAR to be zero.
 *
 * This test calls the real TPM2_GetCapability wire command (no mocking) and
 * asserts the fixed values, so this exact class of drift can't silently
 * regress again.
 *
 * Run: cd wasm && node test_v185_capabilities.mjs
 * Exits 0 on all-green, 1 on any assertion failure.
 */
import { createPqcTpm, getResponseCode } from './pqctpm.js';
import PqcTpmModule from './dist/pqctpm.js';
global.PqcTpmModule = PqcTpmModule;

const TPM_CC_GetCapability = 0x0000017a;
const TPM_CAP_TPM_PROPERTIES = 0x00000006;

// PT_FIXED = PT_GROUP(0x100) * 1
const TPM_PT_FAMILY_INDICATOR = 0x100;
const TPM_PT_REVISION = 0x102;
const TPM_PT_DAY_OF_YEAR = 0x103; // now reports TPM_SPEC_ERRATA per Errata v1 section 2.1
const TPM_PT_YEAR = 0x104;
const TPM_PT_PS_FAMILY_INDICATOR = 0x123;
const TPM_PT_PS_REVISION = 0x125;
const TPM_PT_PS_YEAR = 0x127;

function buildGetCapability(property, count) {
  const cmd = new Uint8Array(22);
  const dv = new DataView(cmd.buffer);
  dv.setUint16(0, 0x8001); // TPM_ST_NO_SESSIONS
  dv.setUint32(2, 22); // commandSize
  dv.setUint32(6, TPM_CC_GetCapability);
  dv.setUint32(10, TPM_CAP_TPM_PROPERTIES);
  dv.setUint32(14, property);
  dv.setUint32(18, count);
  return cmd;
}

/** Parse a TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES) response into a Map<property, value>. */
function parseProperties(resp) {
  // header(10) + moreData(1) + capability(4) + count(4) + count * {property(4), value(4)}
  const dv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  const count = dv.getUint32(15);
  const out = new Map();
  for (let i = 0; i < count; i++) {
    const off = 19 + i * 8;
    out.set(dv.getUint32(off), dv.getUint32(off + 4));
  }
  return out;
}

let failed = false;
function expect(label, actual, expected) {
  const actualHex = `0x${(actual >>> 0).toString(16)}`;
  const expectedHex = `0x${(expected >>> 0).toString(16)}`;
  if (actual === expected) {
    console.log(`  ok   ${label} = ${actualHex}`);
  } else {
    console.error(`  FAIL ${label}: expected ${expectedHex}, got ${actualHex}`);
    failed = true;
  }
}

async function run() {
  const tpm = await createPqcTpm({ wasmPath: './dist/pqctpm.wasm' });

  const libResp = tpm.process(buildGetCapability(TPM_PT_FAMILY_INDICATOR, 5));
  if (getResponseCode(libResp) !== 0) {
    console.error('FAIL: GetCapability(TPM_PT_FAMILY_INDICATOR) returned RC', getResponseCode(libResp));
    process.exit(1);
  }
  const libProps = parseProperties(libResp);

  const psResp = tpm.process(buildGetCapability(TPM_PT_PS_FAMILY_INDICATOR, 5));
  if (getResponseCode(psResp) !== 0) {
    console.error('FAIL: GetCapability(TPM_PT_PS_FAMILY_INDICATOR) returned RC', getResponseCode(psResp));
    process.exit(1);
  }
  const psProps = parseProperties(psResp);

  console.log('TCG TPM 2.0 Library v185 Errata v1 capability constants:');
  expect('TPM_PT_REVISION (Library version, x100)', libProps.get(TPM_PT_REVISION), 185);
  expect('TPM_PT_YEAR (shall be zero, Errata 2.1)', libProps.get(TPM_PT_YEAR), 0);
  expect('TPM_PT_DAY_OF_YEAR (now TPM_SPEC_ERRATA, Errata 2.1)', libProps.get(TPM_PT_DAY_OF_YEAR), 1);
  expect('TPM_PT_PS_REVISION (PC Client PTP version, x100)', psProps.get(TPM_PT_PS_REVISION), 0x00000107);
  expect('TPM_PT_PS_YEAR', psProps.get(TPM_PT_PS_YEAR), 0);

  tpm.terminate();

  if (failed) {
    console.error('\n✗ version-capability regression detected');
    process.exit(1);
  }
  console.log('\n✓ all v185 Errata v1 version-capability constants correct');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
