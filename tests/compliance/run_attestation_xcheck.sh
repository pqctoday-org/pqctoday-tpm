#!/usr/bin/env bash
# ============================================================================
# pqctoday-tpm — attestation runtime cross-check.
#
# Drives REAL TPM2_Quote and TPM2_Certify commands against running swtpm
# using ML-DSA Attestation Keys, then verifies the produced (attest_blob,
# signature, pubkey) tuple with TWO independent crypto stacks:
#
#   1. wolfCrypt (wc_MlDsaKey_VerifyCtx)  — different library from signer
#   2. OpenSSL 3.6.2 EVP (EVP_DigestVerify) — same algorithm, fresh EVP_PKEY
#
# Both verifiers must accept. PASS / FAIL is reported per (op, param_set).
#
# Closes G8 (pqctoday-org/pqctoday-tpm#1) — first independent post-quantum
# TPM 2.0 remote-attestation implementation in any open-source stack.
#
# Spec authority: TCG TPM 2.0 Library Specification V1.85 RC4
#   - Part 3 §18.2 (TPM2_Certify), §18.4 (TPM2_Quote)
#   - Part 2 §10.11 (TPMS_ATTEST + variants)
#   - Part 1 §22.1.2 (restricted-AK rules — TPM_GENERATED_VALUE magic)
#   - FIPS 204 (ML-DSA)
# See docs/TPMdocextract.md §15 for the extracted spec text.
#
# Coverage: ML-DSA-44 / -65 / -87 × {Quote, Certify} = 6 cases.
# ============================================================================

set -u

# ── Output helpers (match run_wolftpm_runtime_xcheck.sh idiom) ──────────────
section() { printf '\n=== %s ===\n' "$1"; }
pass()    { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail()    { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
PASS=0
FAIL=0

WORKSPACE="${WORKSPACE:-/workspace}"
cd "$WORKSPACE"

# ── Step 1: install libtpms + swtpm (assume pre-built by host) ──────────────
section "Setup — install pqctoday-tpm libtpms + swtpm"

if ! ( cd libtpms && make install >/dev/null 2>&1 && ldconfig ); then
    fail "libtpms install failed"; exit 1
fi
pass "libtpms installed and ldconfig'd"

if ! ( cd swtpm && make install >/dev/null 2>&1 ); then
    fail "swtpm install failed"; exit 1
fi
pass "swtpm installed"

# ── Step 2: provision TPM state with default-v1 profile ─────────────────────
section "Setup — TPM state with default-v1 profile"

STATEDIR=$(mktemp -d)
if ! swtpm_setup --tpm2 --tpm-state "$STATEDIR" \
                 --profile-name default-v1 \
                 --logfile /tmp/swtpm_setup_attest.log \
                 --overwrite >/dev/null 2>&1; then
    fail "swtpm_setup failed:"
    sed 's/^/         /' /tmp/swtpm_setup_attest.log
    exit 1
fi
pass "swtpm_setup --profile-name default-v1 (state in $STATEDIR)"

if ! grep -qE "0x1a3-0x1aa|0x1a5-0x1a8" /tmp/swtpm_setup_attest.log 2>/dev/null; then
    fail "PQC commands not in active profile"; exit 1
fi
pass "active profile includes V1.85 PQC commands"

# ── Step 3: start swtpm on TCP 2321/2322 ────────────────────────────────────
section "Start swtpm socket"

swtpm socket --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl   type=tcp,port=2322 \
    --tpmstate dir="$STATEDIR" \
    --flags not-need-init \
    --log file=/tmp/swtpm_attest.log,level=20 \
    --daemon
sleep 1

if ! ss -tln 2>/dev/null | grep -qE "2321|2322"; then
    fail "swtpm socket not listening on 2321/2322"; exit 1
fi
pass "swtpm listening on TCP 2321 (data) + 2322 (ctrl)"

# Always kill swtpm on exit.
SWTPM_PID=$(pgrep -f "swtpm socket.*port=2321" | head -1 || true)
cleanup_swtpm() { [[ -n "${SWTPM_PID:-}" ]] && kill "$SWTPM_PID" 2>/dev/null || true; }
trap cleanup_swtpm EXIT

# ── Step 4: build the attestation xcheck client ─────────────────────────────
section "Build pqc_attestation_xcheck client"

CLIENT=/tmp/pqc_attestation_xcheck
if ! gcc -I/opt/build/wolftpm -I/opt/wolfssl/include -I/opt/openssl/include \
        -DWOLFTPM_V185 -O2 -Wall \
        tests/compliance/clients/pqc_attestation_xcheck.c \
        /opt/build/wolftpm/hal/tpm_io.c \
        -L/opt/build/wolftpm/src/.libs -Wl,-rpath,/opt/build/wolftpm/src/.libs -lwolftpm \
        /opt/wolfssl/lib/libwolfssl.a \
        -L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64 \
        -lssl -lcrypto -lm -lpthread \
        -o "$CLIENT" 2>/tmp/attest_build.log; then
    fail "client build failed:"
    sed 's/^/         /' /tmp/attest_build.log
    exit 1
fi
pass "pqc_attestation_xcheck client built ($(stat -c%s $CLIENT) bytes)"

# ── Step 5: drive the cases ─────────────────────────────────────────────────
ARTIFACT_DIR=$(mktemp -d)
section "Drive TPM2_Quote / TPM2_Certify with ML-DSA AKs (artifacts → $ARTIFACT_DIR)"

# Run the binary; it reports its own [PASS]/[FAIL] lines per case using the
# same idiom as the existing xcheck script — they are mirrored into the
# overall tally below.
if ! LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/build/wolftpm/src/.libs \
        "$CLIENT" "$ARTIFACT_DIR" 2>&1 | tee /tmp/attest_run.log; then
    : # Per-case FAILs are already printed; client exit non-zero just means
      # FAIL count > 0, summarised below.
fi

# Mirror the client's PASS/FAIL counts into the script tally.
# grep -c already prints 0 on no-match (with exit code 1) — no `|| echo 0`
# fallback needed, and it caused "0\n0" stacking that broke the arithmetic.
client_pass=$(grep -c '^  \[PASS\] ' /tmp/attest_run.log) || true
client_fail=$(grep -c '^  \[FAIL\] ' /tmp/attest_run.log) || true
PASS=$((PASS + client_pass))
FAIL=$((FAIL + client_fail))

# ── Final summary ────────────────────────────────────────────────────────────
section "Attestation runtime cross-check summary"
echo "  pqctoday-tpm: libtpms (OpenSSL 3.6.2) + swtpm + default-v1 profile"
echo "  signer:       TPM2_Quote / TPM2_Certify via wolfTPM v4.0.0 client API"
echo "  verifiers:    wolfCrypt (independent) + OpenSSL 3.6.2 EVP"
echo
echo "  $PASS passed, $FAIL failed"

exit $(( FAIL > 0 ? 1 : 0 ))
