cmake_minimum_required(VERSION 3.16)
project(pqctpm C)

# ── Require Emscripten ──────────────────────────────────────────────────────
if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "This CMakeLists is for Emscripten only. Run via emcmake.")
endif()

# ── OpenSSL WASM path (pass -DOPENSSL_WASM_DIR=... or use default) ──────────
if(NOT DEFINED OPENSSL_WASM_DIR)
    set(OPENSSL_WASM_DIR "${CMAKE_SOURCE_DIR}/../../pqctoday-hsm/deps/openssl-wasm"
        CACHE PATH "Path to Emscripten-built OpenSSL (contains include/ and lib/)")
endif()
if(NOT EXISTS "${OPENSSL_WASM_DIR}/lib/libcrypto.a")
    message(FATAL_ERROR "libcrypto.a not found at ${OPENSSL_WASM_DIR}/lib/ — "
            "set -DOPENSSL_WASM_DIR=<path>")
endif()

# ── Collect libtpms sources ─────────────────────────────────────────────────
set(LIBTPMS_TOP "${CMAKE_SOURCE_DIR}/../libtpms/src")
set(LIBTPMS_SRC "${LIBTPMS_TOP}/tpm2")

# tpm2/ layer — all .c files except those replaced by wasm_platform.c
file(GLOB ALL_LIBTPMS_TPM2 "${LIBTPMS_SRC}/*.c")
set(PLATFORM_EXCLUDES
    Cancel.c
    Entropy.c
    NVMem.c
    PowerPlat.c
)
set(LIBTPMS_SOURCES "")
foreach(f ${ALL_LIBTPMS_TPM2})
    get_filename_component(fname "${f}" NAME)
    list(FIND PLATFORM_EXCLUDES "${fname}" idx)
    if(idx EQUAL -1)
        list(APPEND LIBTPMS_SOURCES "${f}")
    endif()
endforeach()

# src/ layer — public API + TPM2 interface only.
# wasm/config.h (first in INC_DIRS) sets WITH_TPM1=0, so TPM12Interface is
# never referenced and we can safely exclude the tpm12 source tree.
file(GLOB ALL_LIBTPMS_TOP "${LIBTPMS_TOP}/*.c")
set(TOP_EXCLUDES
    tpm_nvfile.c          # POSIX file I/O — NV handled by wasm_platform.c
    tpm_tpm12_interface.c # TPM 1.2 disabled (WITH_TPM1=0 in wasm/config.h)
    tpm_tpm12_tis.c       # TPM 1.2 disabled
)
foreach(f ${ALL_LIBTPMS_TOP})
    get_filename_component(fname "${f}" NAME)
    list(FIND TOP_EXCLUDES "${fname}" idx)
    if(idx EQUAL -1)
        list(APPEND LIBTPMS_SOURCES "${f}")
    endif()
endforeach()

# ── Include paths ────────────────────────────────────────────────────────────
# IMPORTANT: ${CMAKE_SOURCE_DIR} (wasm/) must come FIRST so that wasm/config.h
# shadows libtpms/config.h and sets WITH_TPM1=0.
set(INC_DIRS
    "${CMAKE_SOURCE_DIR}"             # wasm/config.h overrides libtpms/config.h
    "${LIBTPMS_SRC}"
    "${LIBTPMS_SRC}/crypto/openssl"
    "${LIBTPMS_SRC}/crypto"
    "${CMAKE_SOURCE_DIR}/../libtpms/src"
    "${CMAKE_SOURCE_DIR}/../libtpms"
    "${CMAKE_SOURCE_DIR}/../libtpms/include"
    "${CMAKE_SOURCE_DIR}/../libtpms/include/libtpms"
    "${OPENSSL_WASM_DIR}/include"
)

# ── Compile flags ────────────────────────────────────────────────────────────
set(CFLAGS_COMMON
    -O2
    -fno-exceptions
    -Wno-deprecated-declarations
    # Suppress known benign warnings in the upstream libtpms code
    -Wno-implicit-function-declaration
    -Wno-int-conversion
    # WASM is 32-bit; tpm_radix.h doesn't recognise wasm32 in its arch list
    -DRADIX_BITS=32
    # Enable libtpms callbacks
    -DTPM_LIBTPMS_CALLBACKS
    -DTPM_NV_DISK
)

# Force-include tpm_library_conf.h for all translation units (defines TPM_BUFFER_MAX etc.)
# Must be two separate items — CMake passes each list element as a separate flag.
list(APPEND CFLAGS_COMMON
    -include
    "${CMAKE_SOURCE_DIR}/../libtpms/src/tpm_library_conf.h"
)

# ── Emscripten link flags ────────────────────────────────────────────────────
# Exported functions: TPMLIB public API + our WASM helpers.
# Leading underscore required by emscripten for C symbols.
set(EXPORTED_FUNCTIONS
    "_TPMLIB_ChooseTPMVersion"
    "_TPMLIB_MainInit"
    "_TPMLIB_Terminate"
    "_TPMLIB_Process"
    "_TPMLIB_SetProfile"
    "_TPMLIB_WasManufactured"
    "_TPMLIB_SetBufferSize"
    "_tpm_wasm_startup"
    "_tpm_wasm_process"
    "_tpm_wasm_get_nv"
    "_tpm_wasm_set_nv"
    "_tpm_wasm_get_nv_size"
    "_malloc"
    "_free"
)
string(JOIN "," EXP_LIST ${EXPORTED_FUNCTIONS})
set(EXPORTED_FUNCTIONS_JSON "[\"${EXP_LIST}\"]")
string(REPLACE "," "\",\"" EXPORTED_FUNCTIONS_JSON "${EXPORTED_FUNCTIONS_JSON}")

set(EM_LINK_FLAGS
    "SHELL:-s WASM=1"
    "SHELL:-s ALLOW_MEMORY_GROWTH=1"
    "SHELL:-s INITIAL_MEMORY=33554432"
    "SHELL:-s MAXIMUM_MEMORY=268435456"
    "SHELL:-s MODULARIZE=1"
    "SHELL:-s EXPORT_NAME='PqcTpmModule'"
    "SHELL:-s EXPORTED_FUNCTIONS=${EXPORTED_FUNCTIONS_JSON}"
    "SHELL:-s EXPORTED_RUNTIME_METHODS=['ccall','cwrap','HEAPU8','getValue','setValue','UTF8ToString','stringToUTF8','lengthBytesUTF8']"
    "SHELL:-s NO_EXIT_RUNTIME=1"
    "SHELL:-s FILESYSTEM=0"
    "SHELL:-s ASSERTIONS=0"
    "SHELL:-s ERROR_ON_UNDEFINED_SYMBOLS=0"
)

# ── Build target ─────────────────────────────────────────────────────────────
add_executable(pqctpm
    ${LIBTPMS_SOURCES}
    "${CMAKE_SOURCE_DIR}/wasm_platform.c"
)

target_include_directories(pqctpm PRIVATE ${INC_DIRS})
target_compile_options(pqctpm PRIVATE ${CFLAGS_COMMON})
target_link_libraries(pqctpm "${OPENSSL_WASM_DIR}/lib/libcrypto.a")
target_link_options(pqctpm PRIVATE ${EM_LINK_FLAGS})

# Output names: pqctpm.js + pqctpm.wasm
set_target_properties(pqctpm PROPERTIES
    OUTPUT_NAME "pqctpm"
    SUFFIX ".js"
)
