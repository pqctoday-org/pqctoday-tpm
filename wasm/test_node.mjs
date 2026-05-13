import { createPqcTpm, buildStartup } from './pqctpm.js';
import url from 'url';

// Load Emscripten factory into global scope
import PqcTpmModule from './dist/pqctpm.js';
global.PqcTpmModule = PqcTpmModule;

async function run() {
    const mod = await PqcTpmModule({ locateFile: () => './dist/pqctpm.wasm' });
    mod.ccall('TPMLIB_SetDebugFD', null, ['number'], [1]);
    mod.ccall('TPMLIB_SetDebugLevel', null, ['number'], [5]);

    const startup = mod.cwrap('tpm_wasm_startup', 'number', ['string']);
    const rc = startup('default-v1');
    console.log("Startup RC:", rc);
    if (rc !== 0) process.exit(1);

    // V2.7 provisioning smoke. tpm_wasm_provision_v2p7 will fail to do real
    // crypto without the JS PQC bridge (no softhsmv3-wasm linked in Node test),
    // but it must not crash and must return a status array.
    const provision = mod.cwrap('tpm_wasm_provision_v2p7', 'number', []);
    const provisionRc = provision();
    console.log("V2.7 provision RC:", provisionRc, "(non-zero expected without bridge)");

    const status = mod._malloc(6);
    const getStatus = mod.cwrap('tpm_wasm_get_v2p7_status', 'number',
                                ['number', 'number']);
    const statusLen = getStatus(status, 6);
    if (statusLen !== 6) {
        console.error("FAIL: get_v2p7_status returned", statusLen);
        process.exit(1);
    }
    const statusBytes = Array.from(mod.HEAPU8.subarray(status, status + 6));
    console.log("V2.7 status array:", statusBytes,
                "(0=untried, 1=ok, 2=fail; expect 6× 2 without bridge)");
    mod._free(status);

    const logBuf = mod._malloc(1024);
    const getLog = mod.cwrap('tpm_wasm_get_v2p7_log', 'number',
                             ['number', 'number']);
    const logLen = getLog(logBuf, 1024);
    const logStr = mod.UTF8ToString(logBuf);
    console.log("V2.7 tail log (" + logLen + " bytes):");
    console.log(logStr.split('\n').map(l => '  ' + l).join('\n'));
    mod._free(logBuf);

    console.log("✓ tpm_wasm_provision_v2p7 entry point reachable, status + log readable");
}

run().catch(console.error);
