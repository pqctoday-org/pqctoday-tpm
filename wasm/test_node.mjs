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
}

run().catch(console.error);
