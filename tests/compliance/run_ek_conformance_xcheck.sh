#!/usr/bin/env bash
# ============================================================================
# pqctoday-tpm — V2.7 RC1 PQC EK Template conformance cross-check.
#
# Compares the marshalled TPMT_PUBLIC of each provisioned PQC EK (read back
# via wolfTPM TPM2_ReadPublic) against hand-encoded V2.7 RC1 Table 13/14
# reference byte vectors.
#
# This is the STRUCTURAL conformance test that the crypto-only xcheck suites
# (wolftpm-xcheck, attestation-xcheck) do not cover: it proves the EK
# templates the TPM emits are byte-exact to TCG EK Credential Profile V2.7.
#
# Spec authority: TCG EK Credential Profile Version 2.7 RC1 (2025-11-07).
# Reference vectors: tests/compliance/vectors/v2p7-ek-templates/
# Reference doc:     docs/TPMdocextract.md §17
#
# RED state (expected today, May 2026): ML-KEM-768 EK at 0x810100A0 FAILS
# because its template predates V2.7 (SHA-256 nameAlg, empty authPolicy,
# AES-128 instead of 256). Phase B step 4 fixes it; this script then goes
# green.
# ============================================================================

set -u
section() { printf '\n=== %s ===\n' "$1"; }
pass()    { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail()    { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
PASS=0
FAIL=0

WORKSPACE="${WORKSPACE:-/workspace}"

# Auto-detect sudo need: Docker container runs as root, GH Actions runner does not.
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

cd "$WORKSPACE"

# ── Install libtpms + swtpm from workspace (pre-built by host) ──────────────
section "Setup — install pqctoday-tpm libtpms + swtpm"

( cd libtpms && $SUDO make install >/dev/null 2>&1 && $SUDO ldconfig ) \
    && pass "libtpms installed and ldconfig'd" \
    || { fail "libtpms install failed"; exit 1; }

( cd swtpm && $SUDO make install >/dev/null 2>&1 ) \
    && pass "swtpm installed" \
    || { fail "swtpm install failed"; exit 1; }

# ── Provision TPM state under default-v1 (PQC EKs created here) ─────────────
section "Setup — TPM state with default-v1 profile"

STATEDIR=$(mktemp -d)
swtpm_setup --tpm2 --tpm-state "$STATEDIR" --profile-name default-v1 \
            --logfile /tmp/swtpm_setup_ek.log --overwrite >/dev/null 2>&1 \
    && pass "swtpm_setup --profile-name default-v1 (state in $STATEDIR)" \
    || { fail "swtpm_setup failed:"; sed 's/^/         /' /tmp/swtpm_setup_ek.log; exit 1; }

# ── Start swtpm on TCP 2321/2322 ────────────────────────────────────────────
section "Start swtpm socket"

pkill -f "swtpm socket" 2>/dev/null || true; sleep 1
swtpm socket --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl   type=tcp,port=2322 \
    --tpmstate dir="$STATEDIR" \
    --flags not-need-init \
    --log file=/tmp/swtpm_ek.log,level=20 \
    --daemon
sleep 1
if ss -tln 2>/dev/null | grep -qE "2321|2322"; then
    pass "swtpm listening on TCP 2321/2322"
else
    fail "swtpm socket not listening"
    exit 1
fi

# Always kill swtpm on exit.
SWTPM_PID=$(pgrep -f "swtpm socket.*port=2321" | head -1 || true)
trap '[[ -n "${SWTPM_PID:-}" ]] && kill "$SWTPM_PID" 2>/dev/null || true' EXIT

# ── Build the EK conformance client ─────────────────────────────────────────
section "Build ek_conformance_xcheck client"

CLIENT=/tmp/ek_conformance_xcheck
if ! gcc -I/opt/build/wolftpm -I/opt/wolfssl/include -I"$WORKSPACE" \
        -DWOLFTPM_V185 -O2 -Wall \
        tests/compliance/clients/ek_conformance_xcheck.c \
        /opt/build/wolftpm/hal/tpm_io.c \
        -L/opt/build/wolftpm/src/.libs -Wl,-rpath,/opt/build/wolftpm/src/.libs -lwolftpm \
        /opt/wolfssl/lib/libwolfssl.a \
        -L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64 \
        -lssl -lcrypto -lm -lpthread \
        -o "$CLIENT" 2>/tmp/ek_build.log; then
    fail "client build failed:"
    sed 's/^/         /' /tmp/ek_build.log
    exit 1
fi
pass "ek_conformance_xcheck built ($(stat -c%s $CLIENT) bytes)"

# ── Drive the conformance check ─────────────────────────────────────────────
section "Drive V2.7 RC1 EK template byte-exact conformance"

if ! LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/build/wolftpm/src/.libs \
        "$CLIENT" 2>&1 | tee /tmp/ek_run.log; then
    : # Per-case FAILs are already printed; client exit non-zero just means
      # FAIL count > 0, surfaced in the script tally below.
fi

client_pass=$(grep -c '^  \[PASS\] ' /tmp/ek_run.log) || true
client_fail=$(grep -c '^  \[FAIL\] ' /tmp/ek_run.log) || true
client_skip=$(grep -c '^  \[SKIP\] ' /tmp/ek_run.log) || true
PASS=$((PASS + client_pass))
FAIL=$((FAIL + client_fail))

# ── Summary ──────────────────────────────────────────────────────────────────
section "V2.7 RC1 EK conformance summary"
echo "  TPM:      libtpms (OpenSSL 3.6.2) inside swtpm"
echo "  client:   wolfTPM v4.0.0 TPM2_ReadPublic + Packet marshal"
echo "  refs:     tests/compliance/vectors/v2p7-ek-templates/ (Tables 13/14)"
echo
echo "  $PASS passed, $FAIL failed   (clients: $client_pass PASS, $client_fail FAIL, $client_skip SKIP)"

exit $(( FAIL > 0 ? 1 : 0 ))
