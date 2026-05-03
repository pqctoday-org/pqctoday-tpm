#!/usr/bin/env bash
# build.sh — Emscripten WASM build for pqctoday-tpm
#
# Usage:
#   ./wasm/build.sh                          # uses sibling pqctoday-hsm OpenSSL WASM
#   OPENSSL_WASM_DIR=/path/to/openssl-wasm ./wasm/build.sh
#   ./wasm/build.sh --clean                  # wipe build dir first
#
# Output: wasm/dist/pqctpm.js + wasm/dist/pqctpm.wasm

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WASM_DIR="$REPO_ROOT/wasm"
BUILD_DIR="$WASM_DIR/build"
DIST_DIR="$WASM_DIR/dist"

# Default OpenSSL WASM path — sibling repo pqctoday-hsm
OPENSSL_WASM_DIR="${OPENSSL_WASM_DIR:-$REPO_ROOT/../pqctoday-hsm/deps/openssl-wasm}"

# ── Checks ──────────────────────────────────────────────────────────────────
if ! command -v emcc &>/dev/null; then
    echo "error: emcc not found. Install Emscripten: https://emscripten.org/docs/getting_started/downloads.html" >&2
    exit 1
fi

if [[ ! -f "$OPENSSL_WASM_DIR/lib/libcrypto.a" ]]; then
    echo "error: libcrypto.a not found at $OPENSSL_WASM_DIR/lib/" >&2
    echo "  Set OPENSSL_WASM_DIR or build pqctoday-hsm WASM first (./build-wasm)" >&2
    exit 1
fi

echo "emcc:         $(emcc --version 2>&1 | head -1)"
echo "OpenSSL WASM: $OPENSSL_WASM_DIR"
echo "Build dir:    $BUILD_DIR"
echo "Output:       $DIST_DIR/pqctpm.{js,wasm}"
echo

# ── Clean ────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    echo "Cleaning $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR" "$DIST_DIR"

# ── CMake configure ──────────────────────────────────────────────────────────
(
  cd "$BUILD_DIR"
  emcmake cmake "$WASM_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_WASM_DIR="$OPENSSL_WASM_DIR" \
    -DCMAKE_VERBOSE_MAKEFILE=OFF
)

# ── Build ────────────────────────────────────────────────────────────────────
NCPU="${NPROC:-$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 4)}"
emmake make -C "$BUILD_DIR" -j"$NCPU"

# ── Copy outputs ─────────────────────────────────────────────────────────────
cp "$BUILD_DIR/pqctpm.js"   "$DIST_DIR/"
cp "$BUILD_DIR/pqctpm.wasm" "$DIST_DIR/"

echo
echo "Build complete:"
ls -lh "$DIST_DIR/pqctpm.js" "$DIST_DIR/pqctpm.wasm"
