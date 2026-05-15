#!/usr/bin/env bash
# ============================================================================
# pqctoday-tpm — V2.7 RC1 PQC EK Certificate NV-slot conformance cross-check.
#
# For each of the 6 mandatory V2.7 §5.3.1 PQC EK cert NV indices, reads the
# X.509 cert from NV, parses with OpenSSL, and byte-matches the SPKI
# AlgorithmIdentifier OID against the V2.7 §6.2.x reference.
#
# RED state today (Phase C step 1): NV slots are EMPTY because Phase C
# steps 2-4 (cert generation + NV write path) haven't landed yet.
# Test must report 6 FAIL with "NV slot not provisioned".
# When Phase C steps 2-4 land, the same test goes 6/6 PASS.
#
# Spec authority:
#   docs/standards/TCG-EK-Credential-Profile-...-V2p7-RC1.pdf §5.3.1 + §6.2.x
#   docs/TPMdocextract.md §17.1 (NV indices), §17.6 (NIST CSOR OIDs)
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

# ── Install libtpms + swtpm ──────────────────────────────────────────────────
section "Setup — install pqctoday-tpm libtpms + swtpm"
( cd libtpms && $SUDO make install >/dev/null 2>&1 && $SUDO ldconfig ) \
    && pass "libtpms installed and ldconfig'd" \
    || { fail "libtpms install failed"; exit 1; }
( cd swtpm && $SUDO make install >/dev/null 2>&1 ) \
    && pass "swtpm installed" \
    || { fail "swtpm install failed"; exit 1; }

# ── Provision TPM state ─────────────────────────────────────────────────────
section "Setup — TPM state with default-v1 profile"
STATEDIR=$(mktemp -d)
swtpm_setup --tpm2 --tpm-state "$STATEDIR" --profile-name default-v1 \
            --logfile /tmp/swtpm_setup_cert.log --overwrite >/dev/null 2>&1 \
    && pass "swtpm_setup --profile-name default-v1" \
    || { fail "swtpm_setup failed:"; sed 's/^/         /' /tmp/swtpm_setup_cert.log; exit 1; }

# ── Start swtpm ─────────────────────────────────────────────────────────────
section "Start swtpm socket"
pkill -f "swtpm socket" 2>/dev/null || true; sleep 1
swtpm socket --tpm2 \
    --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
    --tpmstate dir="$STATEDIR" --flags not-need-init \
    --log file=/tmp/swtpm_cert.log,level=20 --daemon
sleep 1
ss -tln 2>/dev/null | grep -qE "2321|2322" \
    && pass "swtpm listening on TCP 2321/2322" \
    || { fail "swtpm socket not listening"; exit 1; }
SWTPM_PID=$(pgrep -f "swtpm socket.*port=2321" | head -1 || true)
trap '[[ -n "${SWTPM_PID:-}" ]] && kill "$SWTPM_PID" 2>/dev/null || true' EXIT

# ── Build the client ────────────────────────────────────────────────────────
section "Build ek_cert_conformance_xcheck client"
CLIENT=/tmp/ek_cert_conformance_xcheck
if ! gcc -I/opt/build/wolftpm -I/opt/wolfssl/include -I"$WORKSPACE" -I/opt/openssl/include \
        -DWOLFTPM_V185 -O2 -Wall \
        tests/compliance/clients/ek_cert_conformance_xcheck.c \
        /opt/build/wolftpm/hal/tpm_io.c \
        -L/opt/build/wolftpm/src/.libs -Wl,-rpath,/opt/build/wolftpm/src/.libs -lwolftpm \
        /opt/wolfssl/lib/libwolfssl.a \
        -L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64 \
        -lssl -lcrypto -lm -lpthread \
        -o "$CLIENT" 2>/tmp/ekcert_build.log; then
    fail "client build failed:"
    sed 's/^/         /' /tmp/ekcert_build.log
    exit 1
fi
pass "ek_cert_conformance_xcheck built ($(stat -c%s $CLIENT) bytes)"

# ── Drive ───────────────────────────────────────────────────────────────────
section "Drive V2.7 RC1 EK cert NV-slot conformance"
LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/build/wolftpm/src/.libs \
    "$CLIENT" 2>&1 | tee /tmp/ekcert_run.log || true

client_pass=$(grep -c '^  \[PASS\] ' /tmp/ekcert_run.log) || true
client_fail=$(grep -c '^  \[FAIL\] ' /tmp/ekcert_run.log) || true
PASS=$((PASS + client_pass))
FAIL=$((FAIL + client_fail))

section "V2.7 RC1 EK cert conformance summary"
echo "  TPM:    libtpms (OpenSSL 3.6.2) inside swtpm"
echo "  reader: wolfTPM v4.0.0 TPM2_NV_Read + OpenSSL d2i_X509"
echo "  refs:   tests/compliance/vectors/v2p7-ek-cert-oids/ (V2.7 §6.2.x)"
echo
echo "  $PASS passed, $FAIL failed   (clients: $client_pass PASS, $client_fail FAIL)"

exit $(( FAIL > 0 ? 1 : 0 ))
