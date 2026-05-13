# pqctoday-tpm — top-level convenience targets
#
# The real build systems are autotools (libtpms, swtpm) and CMake (cross-val
# harness, future WASM). This Makefile wraps common developer-facing targets.

.PHONY: help crossval crossval-build crossval-run crossval-softhsm compliance compliance-softhsm docker-dev docker-xcheck wolftpm-xcheck attestation-xcheck ek-conformance-xcheck ek-cert-conformance-xcheck clean

help:
	@echo "pqctoday-tpm — developer targets"
	@echo
	@echo "  make docker-dev     Build the pqctoday-tpm-dev Docker image"
	@echo "  make docker-xcheck  Build the pqctoday-tpm-xcheck image (wolfSSL + wolfTPM PQC)"
	@echo "  make compliance     Run the TCG V1.85 PQC compliance test suite"
	@echo "  make crossval       Run the PQC cross-validation harness in Docker"
	@echo "  make crossval-build Build the harness without running it"
	@echo "  make wolftpm-xcheck Runtime cross-check: wolfTPM PR #445 ↔ pqctoday-tpm"
	@echo "  make attestation-xcheck  Runtime TPM2_Quote/Certify with ML-DSA AK (dual-verified)"
	@echo "  make ek-conformance-xcheck  V2.7 RC1 PQC EK template byte-exact conformance"
	@echo "  make clean          Clean build artifacts under tests/crossval/build"
	@echo

docker-dev:
	docker build -f docker/Dockerfile.dev -t pqctoday-tpm-dev .

# Cross-check image: dev + pinned wolfSSL (PQC) + pinned wolfTPM (--enable-pqc).
# Pins: WOLFSSL_REF + WOLFTPM_REF defaults baked into the Dockerfile; override
# on the command line when bumping upstream:
#   make docker-xcheck WOLFSSL_REF=<sha> WOLFTPM_REF=<sha>
WOLFSSL_REF ?=
WOLFTPM_REF ?=
docker-xcheck: docker-dev
	docker build -f docker/Dockerfile.xcheck \
	    $(if $(WOLFSSL_REF),--build-arg WOLFSSL_REF=$(WOLFSSL_REF),) \
	    $(if $(WOLFTPM_REF),--build-arg WOLFTPM_REF=$(WOLFTPM_REF),) \
	    -t pqctoday-tpm-xcheck .

# Runtime cross-check: drives wolfTPM's PQC clients against our libtpms+swtpm,
# asserts FIPS 203/204 sizes and Round-trip OK on Encap/Decap. Phase 4 sequence
# commands are documented as expected-stub until they land.
wolftpm-xcheck: docker-xcheck
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-xcheck \
	    bash tests/compliance/run_wolftpm_runtime_xcheck.sh

# Attestation runtime cross-check: drives real TPM2_Quote / TPM2_Certify
# commands against running swtpm using ML-DSA AKs (44/65/87), then verifies
# the produced (attest, signature, pubkey) with TWO independent crypto stacks
# (wolfCrypt and OpenSSL 3.6.2 EVP). Closes G8 (#1) — first independent PQC
# remote-attestation in any open-source TPM 2.0 stack.
attestation-xcheck: docker-xcheck
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-xcheck \
	    bash tests/compliance/run_attestation_xcheck.sh

# Structural conformance: byte-exact TPMT_PUBLIC vs V2.7 RC1 Tables 13/14
# (Issue #2 — TCG IWG PQC EK Credential Profile). wolfTPM client reads each
# PQC EK back via TPM2_ReadPublic and diffs the marshalled bytes against the
# hand-encoded reference vectors in tests/compliance/vectors/v2p7-ek-templates/.
# Goes RED today (Phase B step 3 in progress); turns green after Phase B step 4.
ek-conformance-xcheck: docker-xcheck
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-xcheck \
	    bash tests/compliance/run_ek_conformance_xcheck.sh

# X.509 EK cert conformance: for each V2.7 §5.3.1 NV cert index, read the
# cert with TPM2_NV_Read, parse with OpenSSL d2i_X509, byte-match the SPKI
# AlgorithmIdentifier OID against V2.7 §6.2.x NIST CSOR references.
# RED today (Phase C step 1 — slots not yet populated); turns green after
# Phase C steps 2-4 (cert generation + NV write path).
ek-cert-conformance-xcheck: docker-xcheck
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-xcheck \
	    bash tests/compliance/run_ek_cert_conformance_xcheck.sh

crossval-build:
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make clean > /dev/null 2>&1 && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             cmake -S tests/crossval -B tests/crossval/build \
	                 -DCMAKE_PREFIX_PATH=/opt/openssl \
	                 -DOPENSSL_ROOT_DIR=/opt/openssl && \
	             cmake --build tests/crossval/build -j$$(nproc)'

# Location of the softhsmv3 sibling repo (built dylibs live under build-pqctoday/).
# Override with SOFTHSMV3_DIR=... make crossval-softhsm.
SOFTHSMV3_DIR ?= $(abspath $(PWD)/../softhsmv3)

crossval: crossval-build
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             tests/crossval/build/test_pqc_crossval && \
	             tests/crossval/build/test_tpm_roundtrip && \
	             tests/crossval/build/test_pqc_phase3'

crossval-softhsm: crossval-build
	@echo "Running cross-val with softhsmv3 C++ engine at $(SOFTHSMV3_DIR)"
	@test -f $(SOFTHSMV3_DIR)/build-pqctoday/src/lib/libsofthsmv3.so \
	    || (echo "libsofthsmv3.so not found — run: cd $(SOFTHSMV3_DIR) && \
	                 cmake -S . -B build-pqctoday -DBUILD_TESTS=OFF && \
	                 cmake --build build-pqctoday -j"; exit 1)
	docker run --rm \
	    -v "$$PWD:/workspace" \
	    -v "$(SOFTHSMV3_DIR):/softhsmv3" \
	    -e SOFTHSM2_CONF=/tmp/softhsm2.conf \
	    -e PQCTODAY_TPM_PKCS11_MODULE=/softhsmv3/build-pqctoday/src/lib/libsofthsmv3.so \
	    -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             mkdir -p /tmp/tokens && \
	             printf "directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > /tmp/softhsm2.conf && \
	             tests/crossval/build/test_pqc_crossval && \
	             tests/crossval/build/test_tpm_roundtrip'

compliance: crossval-build
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             bash tests/compliance/v185_compliance.sh'

compliance-softhsm: crossval-build
	@echo "Running full compliance (includes softhsmv3) with $(SOFTHSMV3_DIR)"
	@test -f $(SOFTHSMV3_DIR)/build-pqctoday/src/lib/libsofthsmv3.so \
	    || (echo "libsofthsmv3.so not found — build softhsmv3 first"; exit 1)
	docker run --rm \
	    -v "$$PWD:/workspace" \
	    -v "$(SOFTHSMV3_DIR):/softhsmv3" \
	    -e SOFTHSM2_CONF=/tmp/softhsm2.conf \
	    -e PQCTODAY_TPM_PKCS11_MODULE=/softhsmv3/build-pqctoday/src/lib/libsofthsmv3.so \
	    -w /workspace pqctoday-tpm-dev \
	    bash -c 'mkdir -p /tmp/tokens && \
	             printf "directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > /tmp/softhsm2.conf && \
	             bash tests/compliance/v185_compliance.sh'

clean:
	rm -rf tests/crossval/build
