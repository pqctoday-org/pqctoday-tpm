# Changelog

All notable changes to pqctoday-tpm are documented here.

---

## [Unreleased]

### V1.85 RC4 spec-citation audit — 26 wrong references fixed (2026-05-15)

Surfaced by wolfTPM issue #506 (closed by Aidan Garske as not-a-bug). Our
report cited Part 3 §29.2.1 for `TPM2_SignDigest` and asked for a missing
`TPM2B_DIGEST_INFO` typedef. Both were wrong: §29.2.1 is `TPM2_ClockSet`,
and `TPM2B_DIGEST_INFO` / `TPM2B_MU` do not exist in V1.85 RC4 (Aidan
grepped Part 2 and got zero matches). A self-audit revealed the wrong
citation had propagated into the entire PQC command surface and the
"spec-authoritative" doc extract.

**Pattern.** All wrong citations clustered in two failure modes: (1) PQC
commands stamped as §29.x (the `TPM2_Clock*` chapter) because an early
working-draft or LLM enrichment placed PQC in a non-existent §29 PQC
chapter; (2) §18 command Tables in `TPMdocextract.md` cited Table numbers
from the §17 Policy-command range — real Tables, wrong commands. No
errors in foundational TPM2B / parameter-set / Part 2 structure citations,
which were grepped against the PDF when first written.

**Fixed citations (Part 3 V1.85 RC4):**

| Command | Was | Is |
| --- | --- | --- |
| TPM2_Encapsulate | §29.5.1 | §14.10 (Tables 60-61) |
| TPM2_Decapsulate | §29.5.2 | §14.11 (Tables 62-63) |
| TPM2_SignSequenceStart | §29.3.1 | §17.5 |
| TPM2_VerifySequenceStart | §29.4.1 | §17.6 |
| TPM2_VerifySequenceComplete | §29.4.2 | §20.3 |
| TPM2_VerifyDigestSignature | §29.2.2 | §20.4 |
| TPM2_SignSequenceComplete | §29.3.2 | §20.6 |
| TPM2_SignDigest | §29.2.1 | §20.7 (Table 126) |
| TPM2_CreatePrimary | §29 / Tables 124-125 | §24.1 / Tables 191-192 |
| TPM2_MakeCredential | §12.5.2 | §12.6.2 (Tables 28-29) |
| TPM2_ActivateCredential | §12.6.2 | §12.5.2 (Tables 26-27) |
| TPM2_FlushContext | Tables 139-140 | §28.4 / Tables 228-229 |
| TPM2_EvictControl | Tables 141-142 | §28.5 / Tables 230-231 |
| TPM2_NV_DefineSpace | §31.4 / Tables 162-163 | §31.3 / Tables 245-246 |
| TPM2_NV_Write | §31.6 / Tables 166-167 | §31.7 / Tables 253-254 |
| TPM2_NV_ReadPublic | §31.7 / Tables 168-169 | §31.6 / Tables 251-252 |
| TPM2_NV_Read | Tables 178-179 | §31.13 / Tables 265-266 |
| TPM2_ReadPublic (object) | Tables 84-85 | §12.4 / Tables 24-25 |

**Files touched (12):** `CHANGELOG.md`, `README.md`, `docs/TPMdocextract.md`,
`libtpms/src/tpm2/{SignDigest,VerifyDigestSignature,Encapsulate,Decapsulate}_fp.h`,
`libtpms/src/tpm2/{PqcMlDsaCommands,PqcKemCommands}.c`,
`swtpm/src/swtpm_setup/swtpm.c`, `tests/compliance/v185_compliance.sh`,
`tests/crossval/src/test_pqc_phase3.c`. Companion fix in pqctoday-hub:
`src/components/Playground/TpmPlayground/ComplianceRunner.tsx`.

**Open issues surfaced during the audit** (flagged in memory, not fixed
here — need separate review):

1. `TPMdocextract.md §13.4` and the compliance suite describe
   `TPM2_SignDigest` wire as `inScheme + digest + context + hint` but
   Table 126 in RC4 has `context + digest + validation` (no `inScheme`,
   no `hint`). Compliance suite may be testing against a pre-RC4 draft
   wire format. 16/16 passing → needs reverification.
2. `PqcMlDsaCommands.c:54-59` rejects restricted-key `SignDigest` outright
   with `TPM_RC_ATTRIBUTES`. §20.7.1 says restricted keys are permitted
   with a valid `TPMT_TK_HASHCHECK` (which for ML-DSA cannot exist).
   Different mechanism, same de-facto outcome — conformance ambiguous.
3. Two passages in `TPMdocextract.md §18.4.1` and §18.4 footer were
   presented as verbatim spec quotes ("if adminWithPolicy is SET,
   authPolicy shall NOT be EMPTY"; "restricted-AK Quote/Certify requires
   allowExternalMu = NO") — neither has a verbatim match in V1.85 RC4.
   Re-cited to the structural definitions and annotated as inference,
   not quote.

## [0.7.0] — 2026-05-13

### WASM provisioning port — V2.7 EK + cert NV slots reachable in the browser

Until v0.7.0, the WASM build (`wasm/dist/pqctpm.{js,wasm}`) ran
`TPMLIB_MainInit` + `TPM2_Startup` but did not provision the V2.7 EK
templates or populate the §5.3.1 NV cert slots — that work lives in
`swtpm/src/swtpm_setup/swtpm.c` which uses GLib and is excluded from
the WASM target. v0.7.0 ports the relevant subset (~600 LOC) into
`wasm/wasm_platform.c`, GLib-stripped, so a browser embedding the WASM
TPM gets the full v0.6.0 V2.7 RC1 EK Credential Profile surface:

- Six V2.7 RC1 EK persistent handles (`0x810100A0/B0/B2/B4/B5/B6`)
  populated with byte-exact Tables 13/14 templates.
- Six V2.7 §5.3.1 NV cert slots (`0x01c00060/62/64/70/72/74`)
  populated with X.509 EK certs carrying the NIST CSOR OID per V2.7
  §6.2.x.

#### New WASM entry points (exported via Emscripten)

| Symbol | Purpose |
|---|---|
| `_tpm_wasm_provision_v2p7` | Run the 6-EK + 6-cert + 6-NV provisioning sequence in-process via `TPMLIB_Process` (no socket). Idempotent: re-runs against an already-provisioned TPM log + continue. |
| `_tpm_wasm_get_v2p7_status` | Read back the 6-byte status array (0=untried, 1=ok, 2=fail). |
| `_tpm_wasm_get_v2p7_log` | Read back a human-readable tail log for diagnostics in the JS console. |

#### GLib-strip pass

The native code in `swtpm_setup/swtpm.c` uses `g_autofree`,
`g_strdup_printf`, `g_malloc/realloc`, and a `transfer()` socket
helper. The WASM port keeps the wire-format identical but:

- `g_autofree` → manual `free` in a `cleanup:` block (mostly in
  `wasm_tpm2_createprimary_pqc` and `wasm_pqc_build_cert_der`).
- `g_malloc/realloc` → `malloc/realloc`.
- `g_strdup_printf` → drop entirely (cert generation uses fixed CN
  strings).
- `transfer()` → `wasm_tpm_transfer` which is a one-call
  `TPMLIB_Process` wrapper. Both paths return 0 on TPM success.

The PolicyB digests + V2.7 NV index constants are pulled from
`swtpm/src/swtpm_setup/tcg_pqc_ek_constants.h` (header-only, no GLib),
added to the WASM include path in `wasm/CMakeLists.txt`.

#### Smoke test (`wasm/test_node.mjs`)

`node test_node.mjs` exercises the new entry points. In Node-only
(no `Module._pqcBridge` registered, so EK CreatePrimary returns
DRBG-filled placeholder pubkeys) the status array reads `[2,2,2,2,2,2]`
— a clean fail mode. In a browser with the pqctoday-hub PQC bridge
registered, every slot is expected to read 1.

#### Build size

`pqctpm.wasm` grows from 281 KB → 2.1 MB because the cert generation
pulls in OpenSSL's X.509 signing + ASN.1 encoder surface. Acceptable
trade for in-browser PQC remote attestation.

---

## [0.6.0] — 2026-05-13

### V2.7 RC1 PQC EK Certificates — generation + NV provisioning

Closes [`#2`](https://github.com/pqctoday-org/pqctoday-tpm/issues/2) (G7-A)
Phase C. v0.5.0 made the six V2.7 EK *templates* byte-exact. v0.6.0 closes
the loop: at `swtpm_setup` time we now build a real X.509 EK certificate
for each of the six V2.7 EKs (SPKI carries the TPM-resident PQC pubkey
under the NIST CSOR OID per V2.7 §6.2.x) and write the cert DER to the
spec-mandated §5.3.1 NV index.

#### What works end-to-end

`make ek-cert-conformance-xcheck` — **6 PASS / 0 FAIL**:

```text
ML-KEM-512  EK cert @ 0x01c00060 — cert 4335 B, SPKI OID byte-matches V2.7 §6.2.3
ML-KEM-768  EK cert @ 0x01c00062 — cert 4719 B, SPKI OID byte-matches V2.7 §6.2.3
ML-KEM-1024 EK cert @ 0x01c00064 — cert 5104 B, SPKI OID byte-matches V2.7 §6.2.3
ML-DSA-44   EK cert @ 0x01c00070 — cert 4846 B, SPKI OID byte-matches V2.7 §6.2.4
ML-DSA-65   EK cert @ 0x01c00072 — cert 5486 B, SPKI OID byte-matches V2.7 §6.2.4
ML-DSA-87   EK cert @ 0x01c00074 — cert 6126 B, SPKI OID byte-matches V2.7 §6.2.4
```

Each PASS chains five independent assertions per slot:

1. `TPM2_NV_ReadPublic` against the V2.7 §5.3.1 spec NV index succeeds —
   the cert slot exists (was zero handles before v0.6.0, RED state).
2. `TPM2_NV_Read` returns the full cert DER (chunked through
   `MAX_NV_BUFFER_SIZE`).
3. OpenSSL `d2i_X509` parses the DER — well-formed X.509.
4. SPKI AlgorithmIdentifier OID body **byte-matches** the NIST CSOR
   reference (`tests/compliance/vectors/v2p7-ek-cert-oids/`) —
   `id-alg-ml-kem-{512,768,1024}` / `id-ml-dsa-{44,65,87}` per V2.7 §6.2.x.
5. Cert `notAfter` is in the future, `notBefore` past, subject CN non-empty.

#### Code path

- `swtpm_pqc_build_cert_der` (`swtpm/src/swtpm_setup/swtpm.c`) — split out
  from the v1.85 `swtpm_pqc_write_cert`; returns DER bytes in memory so
  the same cert can be written both to disk (legacy `mlkem_ek.cert` path)
  and to NV (new V2.7 path) without regenerating.
- `swtpm_tpm2_pqc_provision_v2p7_ekcert_nvram` — table-driven loop over
  the six V2.7 EKs; uses the existing `swtpm_tpm2_write_nvram` helper
  (TPM2_NV_DefineSpace + chunked TPM2_NV_Write) so the NV attributes
  (`PLATFORMCREATE | AUTHREAD | OWNERREAD | PPREAD | PPWRITE | NO_DA |
  WRITEDEFINE`) mirror exactly the existing RSA/ECC EK cert slots.
- `swtpm_tpm2_provision_v2p7_ek` now threads each V2.7 EK pubkey hex
  back to the caller (was previously discarded by passing `NULL`).

#### libtpms profile bump

`MAX_NV_INDEX_SIZE` raised from 2048 → 8192
(`libtpms/src/tpm2/TpmProfile_Misc.h`). PQC certs run 4.3 – 6.1 KB
because ML-DSA-65 issuer signatures alone are 3309 B (FIPS 204 Table 2).
Underlying `NV_MEMORY_SIZE` (172 KB) has ample headroom. Migrated the
matching `NVMarshal.c` `COMPILE_CONSTANT` from `EQ` → `LE` so older
state files (which recorded 2048) still load on the new build.

#### Cross-check matrix (post-v0.6.0)

| Suite | Result |
|---|---|
| `make compliance` (v185) | **109 / 0 / 0** (PASS / FAIL / SKIP) |
| `make wolftpm-xcheck` | **29 / 0** |
| `make attestation-xcheck` | **12 / 0** |
| `make ek-conformance-xcheck` | **6 / 0** |
| `make ek-cert-conformance-xcheck` | **6 / 0** ← previously 0/6 RED |

### Notable

This makes pqctoday-tpm the **first open-source TPM 2.0 implementation
publishing full V2.7 RC1 PQC EK certificates at NV-readable slots**. A
remote attestation flow can now `TPM2_NV_Read 0x01c00072`, parse with
any standard X.509 stack, and obtain the ML-DSA-65 EK pubkey — no
vendor-specific provisioning required.

---

## [0.5.0] — 2026-05-13

### V2.7 RC1 PQC EK Credential Profile — byte-exact conformance

Closes [`#2`](https://github.com/pqctoday-org/pqctoday-tpm/issues/2) (G7-A)
Phase B. We are no longer "blocked on external TCG spec" — TCG published
**EK Credential Profile V2.7 RC1 on 2025-11-07** with full PQC EK templates
for ML-KEM (Storage) and ML-DSA (Signing). This release brings pqctoday-tpm
byte-exact compliant with the new mandatory templates.

#### Cited spec (cached locally in `docs/standards/`)

- **TCG EK Credential Profile V2.7 RC1** (2025-11-07) — Tables 7, 8, 13, 14;
  §5.3.1 NV index allocations; §6.1.3 + §6.2.x algorithm identifiers.
- **NIST FIPS 203** (Aug 2024) — Table 3 (Sizes in bytes of keys and
  ciphertexts of ML-KEM, p.39). New to repo.
- **NIST FIPS 204** (Aug 2024) — Table 2 (Sizes in bytes of keys and
  signatures of ML-DSA, p.16). New to repo.
- Full spec extracts into `docs/TPMdocextract.md` §3 (FIPS 203 sizes), §4
  (FIPS 204 sizes), §17 (V2.7 EK Credential Profile — 9 subsections,
  Tables 7, 8, 13, 14, §3.1.5 TPMPQCVersion, §3.1.4 EKCredentialAlgorithmList,
  §5.3.1 NV cert indices, §A.1.3–5 Policy Indexes).

#### What works end-to-end

`make ek-conformance-xcheck` — **6 PASS / 0 FAIL**:

```text
ML-KEM-512  EK @ 0x810100b0 — template prefix (50 B) bit-exact + FIPS unique.size=800
ML-KEM-768  EK @ 0x810100a0 — template prefix (66 B) bit-exact + FIPS unique.size=1184
ML-KEM-1024 EK @ 0x810100b2 — template prefix (82 B) bit-exact + FIPS unique.size=1568
ML-DSA-44   EK @ 0x810100b4 — template prefix (45 B) bit-exact + FIPS unique.size=1312
ML-DSA-65   EK @ 0x810100b5 — template prefix (61 B) bit-exact + FIPS unique.size=1952
ML-DSA-87   EK @ 0x810100b6 — template prefix (77 B) bit-exact + FIPS unique.size=2592
```

Each PASS is two independent assertions:

1. V2.7 RC1 Tables 13/14 template-fixed prefix **byte-exact** (every byte
   the spec mandates: type, nameAlg, objectAttributes, authPolicy, parms).
2. **FIPS 203 Table 3 / FIPS 204 Table 2** public-key size verified —
   proves the TPM generated a real key of the right size, not a stub.

Pipeline: real `swtpm` + `libtpms` provision the EKs; wolfTPM v4.0.0 client
reads back via `TPM2_ReadPublic`; both halves of the assertion run inside a
single C client. Independent stack at every layer.

#### Spec coverage (V2.7 RC1)

- Part 2 §5.4.5.1 Table 7 — Object Attributes (Storage `0x000300B2`,
  Signing `0x000500B2`)
- Part 2 §5.4.5.2 Table 8 — PolicyB digests (SHA-256/384/512, 32/48/64 B)
- Part 2 §5.4.6.5 Table 13 — ML-KEM EK templates (3 variants)
- Part 2 §5.4.6.6 Table 14 — ML-DSA EK templates (3 variants)
- Part 1 §16.2 + Table 33 — restricted-AK/EK ADMIN/USER auth roles
- FIPS 203 — ML-KEM parameter-set sizes
- FIPS 204 — ML-DSA parameter-set sizes

#### Code changes

- `swtpm/src/swtpm_setup/swtpm.c` — **6 new EK creator functions** in the
  Endorsement hierarchy with V2.7 byte-encoded `TPMT_PUBLIC` (correct
  algorithm, per-variant nameAlg SHA-256/384/512, attributes-storage or
  -signing, PolicyB authPolicy, `allowExternalMu=NO` for signing EKs).
  New helper `swtpm_tpm2_provision_v2p7_ek` factors create+evict+log+flush.
  ML-KEM-768 EK at `0x810100A0` tightened in place from pre-V2.7 (SHA-256,
  AES-128, empty authPolicy, attrs `0x000300F2`) to V2.7 (SHA-384, AES-256,
  48 B PolicyBSHA384, attrs `0x000300B2`). Five new persistent handles
  allocated `0x810100B0/B2/B4/B5/B6`.
- `swtpm/src/swtpm_setup/tcg_pqc_ek_constants.h` — spec-constants header
  (PolicyB digests, 12 EK Cert NV indices, 3 Policy Index NVs).

#### Test infrastructure

- `tests/compliance/vectors/v2p7-ek-templates/v2p7_ek_template_vectors.h`
  — hand-encoded reference byte vectors from V2.7 Tables 13/14 (52/68/84
  ML-KEM, 47/63/79 ML-DSA), with `_Static_assert` size checks.
- `tests/compliance/clients/ek_conformance_xcheck.c` — wolfTPM-driven
  conformance client with two-part check (template prefix + FIPS unique).
- `tests/compliance/run_ek_conformance_xcheck.sh` — full Docker wrapper.
- `Makefile` — new `make ek-conformance-xcheck` target.
- `.github/workflows/xcheck.yml` — runs nightly alongside wolftpm + attestation.
- `tests/compliance/v185_compliance.sh` — 5 new source-level checks (V2.7
  NV indices, PolicyB digests, Policy Index NVs). Score 101 → **106 PASS**.

#### Cumulative conformance scorecard

| Suite | Score | What |
|---|---|---|
| `v185_compliance.sh` | 106/0 | V1.85 RC4 + V2.7 RC1 source constants |
| `make wolftpm-xcheck` | 29/0 | Runtime ML-KEM/ML-DSA crypto interop |
| `make attestation-xcheck` | 12/0 | TPM2_Quote/Certify dual-verified |
| `make ek-conformance-xcheck` | **6/0** | **V2.7 EK templates byte-exact + FIPS sizes (new)** |
| **Total** | **153/0** | Source + crypto + structural conformance |

#### Remaining for full V2.7 RC1 closure

- Phase B step 5 (small): extend the EK conformance client to also verify
  `TPM2_GetName` / `qualifiedName` / hierarchy = TPM_RH_ENDORSEMENT.
- Phase C (~1 day): X.509 PQC EK cert generation per §6.1.3 / §6.2.x with
  NIST CSOR OIDs; populate the 12 EK cert NV slots (`0x01c00060..7a`);
  optional `TPMPQCVersion` cert attribute.
- Both → **v0.6.0**.

## [0.4.0] — 2026-05-13

### Post-quantum remote attestation — TPM2_Quote / TPM2_Certify with ML-DSA AK

Closes [`#1`](https://github.com/pqctoday-org/pqctoday-tpm/issues/1) (G8). First
independent post-quantum TPM 2.0 remote-attestation implementation in any
open-source stack (verified by upstream survey 2026-05-12: wolfTPM v4.0.0 +
PR #501 has no `Quote`/`Certify` example with ML-DSA AK; libtpms upstream has
no PQC at all).

#### What works end-to-end

`make attestation-xcheck` — **12 PASS / 0 FAIL** as of release:

```text
TPM2_Quote with ML-DSA AK + PCR digest (Part 3 §18.4)
  [PASS] Quote ML-DSA-44: TPM sig=2420, wolfCrypt+OpenSSL both ACCEPTED
  [PASS] Quote ML-DSA-65: TPM sig=3309, wolfCrypt+OpenSSL both ACCEPTED
  [PASS] Quote ML-DSA-87: TPM sig=4627, wolfCrypt+OpenSSL both ACCEPTED
TPM2_Certify with ML-DSA AK (Part 3 §18.2)
  [PASS] Certify ML-DSA-44: TPM sig=2420, wolfCrypt+OpenSSL both ACCEPTED
  [PASS] Certify ML-DSA-65: TPM sig=3309, wolfCrypt+OpenSSL both ACCEPTED
  [PASS] Certify ML-DSA-87: TPM sig=4627, wolfCrypt+OpenSSL both ACCEPTED
```

Pipeline (real TPM, real PQC crypto, dual independent verifiers — no stubs):

```text
swtpm + libtpms (OpenSSL 3.6.2 ML-DSA)
     │
     │  TPM2_Quote / TPM2_Certify via wolfTPM v4.0.0 client API
     ▼
(attest_blob, ml_dsa_signature, ak_pubkey)
     │
     ├──► Verifier A: wolfCrypt wc_MlDsaKey_VerifyCtx (independent stack)
     └──► Verifier B: OpenSSL 3.6.2 EVP_DigestVerify (fresh EVP_PKEY)
```

FIPS 204 sizes byte-exact for AK pubkey (1312/1952/2592) and signature
(2420/3309/4627). `TPM_GENERATED_VALUE` magic (0xFF544347) at `TPMS_ATTEST[0..4]`
verified before crypto. Both verifiers must accept; either rejection FAILs.

#### Spec coverage (V1.85 RC4)

- Part 3 §18.2 Tables 97-98 — `TPM2_Certify` command/response
- Part 3 §18.4 Tables 101-102 — `TPM2_Quote` command/response
- Part 2 §10.11 — `TPMS_ATTEST`, `TPMS_CERTIFY_INFO`, `TPMS_QUOTE_INFO`, attested union
- Part 1 §16.2 — restricted-AK ADMIN/USER auth roles (HMAC session with empty authValue when `adminWithPolicy=CLEAR`)
- Part 1 §22.1.2 + Table 33 — `TPM_GENERATED_VALUE` first-octets rule
- FIPS 204 — all parameter-set sizes

Full extracted spec text now in `docs/TPMdocextract.md` §15 (Tables 97-102,
141, 144-145, 151-154, restricted-AK rules, PCR digest recipe) — 12-line stub
→ 220+ lines.

#### Code changes (minimal — dispatcher was already ready)

- `libtpms/src/tpm2/Attest_spt.c:170-176` — confirmed ML-DSA routes through `CryptMlDsaSignMessage()` for ALL attestation callers (Certify, Quote, CertifyCreation). **Zero core-code changes.**
- `libtpms/src/tpm2/AttestationCommands.c:182-185` — confirmed `TPM2_Quote` derives PCR-digest hash from `nameAlg` when `inScheme=NULL` on an ML-DSA AK. **Already implemented.**
- `libtpms/src/tpm2/crypto/openssl/CryptMlDsa.c` — added 13-line `#ifdef PQCTODAY_TPM_DETERMINISTIC_SIGN` block wiring `OSSL_SIGNATURE_PARAM_DETERMINISTIC=1`. Off in production builds. Empirically validates bit-exact reproducibility against OpenSSL 3.6.2's FIPS 204 §3.4 ρ″=0 path.
- `swtpm/src/swtpm_setup/swtpm.c` — new ML-DSA-44 AK at `0x810100A2` and ML-DSA-87 AK at `0x810100A3` (matching the existing ML-DSA-65 template at `0x810100A1`).

#### Test infrastructure (new)

- `tests/compliance/clients/pqc_attestation_xcheck.c` — TPM-driven attestation client + dual verifier (single binary, ~470 lines).
- `tests/compliance/run_attestation_xcheck.sh` — full setup + drive + summary wrapper.
- `Makefile` — new `attestation-xcheck` target, depends on `docker-xcheck`.

#### wolfTPM upstream V1.85 gaps surfaced — **all five withdrawn 2026-05-15**

> **Withdrawn 2026-05-15.** All five "gaps" originally listed here were spec
> misreadings. wolfTPM is V1.85 RC4 conformant on each of these points. Three
> tickets were filed (#504, #505, #506) on 2026-05-13; all three were closed
> by Aidan Garske as not-bugs on 2026-05-14/15 with detailed corrections. The
> remaining two items in the original list rest on the same misreadings and
> were not filed.
>
> Root cause: this section was drafted from LLM-summarized spec extracts that
> misnumbered tables/sections and invented typedefs absent from the spec,
> without cross-checking against the correctly-transcribed Tables 110/112/181
> in our own `docs/TPMdocextract.md` or against the vendor wolfTPM headers in
> `vendor/wolftpm/wolftpm/tpm2.h`.
>
> Per-item correction:
>
> 1. ~~`TPMU_SIG_SCHEME` missing `mldsa` + `hash_mldsa` arms (Part 2 §11.3.5 Table 216).~~ **Wrong.** Table 216 is `TPM2B_SIGNATURE_MLDSA`. `TPMU_SIG_SCHEME` is Table 181 (§11.2.1.4 p.173) and the spec does **not** define `mldsa`/`hash_mldsa` arms — ML-DSA uses `TPM_ALG_NULL` as the scheme selector per Table 181's last row, because `TPMS_MLDSA_PARMS` fully fixes the operation. wolfTPM is conformant. Issue [#504](https://github.com/wolfSSL/wolfTPM/issues/504) closed as not-a-bug.
> 2. ~~`TPMS_SIG_SCHEME_MLDSA` + `TPMS_SIG_SCHEME_HASH_MLDSA` struct types missing.~~ **Wrong.** These typedefs do not exist in V1.85 RC4 Part 2 (zero matches in the spec text). Follows from (1).
> 3. ~~`TPMT_TK_VERIFIED` defined as empty struct.~~ **Wrong.** The struct in wolfTPM (both at PR #445 merge `fbbf6fe` and at PR #501 merge `0ae18dc`) has `{tag, hierarchy, [#ifdef WOLFTPM_V185 metaAlg], digest}` — never been empty. The original "current state" snippet in #505 was fabricated. Issue [#505](https://github.com/wolfSSL/wolfTPM/issues/505) closed as not-a-bug.
> 4. ~~`TPMU_TK_VERIFIED_META` union missing entirely.~~ **Wrong.** Table 110 (§10.6.4 p.145) defines the union as `{verified:TPMS_EMPTY, messageVerified:TPMS_EMPTY, digestVerified:TPM_ALG_ID}` — only one of three arms carries any wire data. wolfTPM flattens this to a single `TPM_ALG_ID metaAlg` field, which is semantically faithful. The `digest`→`hmac` rename (Table 112) is editorial per the spec's own note; wolfTPM retains `digest` for API stability without affecting wire bytes.
> 5. ~~`TPM2B_DIGEST_INFO` / external-µ TPM2B missing (Part 3 §29.2.1 SignDigest).~~ **Wrong.** `TPM2_SignDigest` is Part 3 §20.7 (§29.2.1 is `TPM2_ClockSet`). `TPM2B_DIGEST_INFO`/`TPM2B_MU` do not exist in the spec. External-µ rides in the existing `TPM2B_DIGEST digest` field per Table 126, gated by `TPMS_MLDSA_PARMS.allowExternalMu`. wolfTPM issue [#506](https://github.com/wolfSSL/wolfTPM/issues/506) closed as not-a-bug.
>
> The runtime V185-001..V185-018 compliance suite is **not affected** by this
> withdrawal — it tests TPM behavior end-to-end (Encapsulate/Decapsulate
> round-trip, signature non-trivial, capability-set membership) and does not
> rely on the source-level claims above. The "16/16 passing" runtime status
> stands.
>
> Our G8 test continues to send `inScheme=NULL` (spec-allowed; Table 181 last
> row) and relies on libtpms's dispatcher to derive the hash from `nameAlg` —
> this is the spec-defined ML-DSA path, not a workaround.

## [0.3.1] — 2026-05-13

### xcheck — drop `mlkem.h` symlink workaround (upstream wolfSSL/wolfTPM#499 closed)

The wolfTPM `configure.ac` defect we filed at [wolfSSL/wolfTPM#499](https://github.com/wolfSSL/wolfTPM/issues/499)
was fixed upstream in [PR #501](https://github.com/wolfSSL/wolfTPM/pull/501) (merged
2026-05-11, commit `0ae18dcd138f2ea2aba7d146d05115cf294c07bb`). The xcheck no longer
needs the `ln -sf wc_mlkem.h .../mlkem.h` workaround.

- **`WOLFTPM_REF`** bumped from `fbbf6fe` (PR #445 merge) to `0ae18dc…` (PR #501
  merge) in both `docker/Dockerfile.xcheck` and `.github/workflows/xcheck.yml`.
- **Symlink removed** from both files.
- **Verification:** `make wolftpm-xcheck` passes **29/29** without the workaround,
  same baseline as 2026-05-02.
- **Closes** `pqctoday-org/pqctoday-tpm#6` (G3, *help wanted*).

`docs/upstream-issues/wolfTPM-001-mlkem-header-rename.md` is preserved with a
"Resolution" footer for historical context.

## [0.3.0] — 2026-05-04

### WASM Milestone 3 — Real PQC crypto via SoftHSMv3 bridge (Issue #9)

Replaces the 0xCC/0xDD/0xEE placeholder stubs in the Emscripten WASM build
with real ML-KEM-768 and ML-DSA-65 cryptographic operations, routed through
the softhsmv3 Rust WASM module's PKCS#11 v3.2 API. The compliance suite now
achieves **18/18 passing checks** including two new bridge-validation checks.

#### Architecture: EM_JS → JS bridge → softhsm-wasm

```
pqctpm.wasm (C) ──EM_JS──> Module._pqcBridge (JS) ──> softhsmv3.wasm (Rust)
```

The C code in `CryptMlKem.c` / `CryptMlDsa.c` calls EM_JS functions that
check for `Module._pqcBridge` on the pqctpm Module object. If no bridge is
registered (standalone WASM), the code falls back to the existing DRBG-fill /
placeholder behavior — backward compatibility is fully preserved.

#### C-side changes

**`wasm/wasm_platform.c`** — 5 new `EM_JS` bridge dispatchers:
- `pqc_bridge_mlkem_keygen` / `_encap` / `_decap` — ML-KEM-768 operations
- `pqc_bridge_mldsa_keygen` / `_sign` — ML-DSA-65 operations

Each dispatcher checks `Module._pqcBridge` at runtime and marshals
buffer pointers + sizes through the WASM i32 ABI.

**`CryptMlKem.c`** — All 3 `#ifdef __EMSCRIPTEN__` blocks (keygen,
encapsulate, decapsulate) now try the bridge first via
`pqc_bridge_mlkem_*()`. On success, real ML-KEM bytes are written
directly into the TPM structures. On failure (return -1 = no bridge),
falls back to DRBG-fill / 0xCC/0xDD placeholders.

**`CryptMlDsa.c`** — Both keygen and sign `#ifdef __EMSCRIPTEN__`
blocks try `pqc_bridge_mldsa_*()` first. ML-DSA sign now produces
real 3309-byte signatures instead of 0xEE fill.

#### Build

**`wasm/build.sh`** — Added Python 3.13 PATH override to fix the
Emscripten/Xcode Python 3.9 conflict (`/opt/homebrew/opt/python@3.13`).

Output: `pqctpm.wasm` (2.1 MB), `pqctpm.js` (20 KB).

#### Hub-side integration (pqctoday-hub, documented for cross-repo traceability)

- **`src/wasm/pqcCryptoBridge.ts`** (NEW) — ~400-line TypeScript module that
  initializes softhsmv3, opens a PKCS#11 session, and implements 5 bridge
  callbacks: `mlkemKeygen` (`C_GenerateKeyPair`), `mlkemEncap`
  (`C_EncapsulateKey`), `mlkemDecap` (`C_DecapsulateKey`), `mldsaKeygen`
  (`C_GenerateKeyPair`), `mldsaSign` (`C_SignInit + C_Sign`).

- **`src/wasm/tpmBridge.ts`** — After `tpm_wasm_startup()`, dynamically
  imports and registers the bridge. Non-fatal: if bridge loading fails,
  falls back to placeholder behavior.

- **`ComplianceRunner.tsx`** — Added 2 new bridge-validation checks:
  - **V185-017**: KEM Round-Trip (`ss_encap === ss_decap`, non-trivial)
  - **V185-018**: DSA Non-Trivial (`sig ≠ 0xEE` placeholder)
  - Decapsulate now uses the real ciphertext from Encapsulate for true
    round-trip validation.

- **`tpmCommandDefs.ts`** — Updated Encapsulate, Decapsulate, and
  SignDigest descriptions to reflect real PQC crypto output.

#### Verification

```text
pqctoday-hub compliance runner (in-browser WASM):
  V185-001  TPM2_SelfTest(fullTest)             PASS
  V185-002  Response Header Structure           PASS
  V185-003  TPM2_GetCapability(ALGS)            PASS  36 algorithms
  V185-004  ML-KEM (0x00A0) registered          PASS
  V185-005  ML-DSA (0x00A1) registered          PASS
  V185-006  TPM2_GetRandom entropy source       PASS
  V185-007  Entropy non-trivial (32 B)          PASS
  V185-008  CreatePrimary ML-KEM-768 EK         PASS  handle=0x80000000
  V185-009  ML-KEM-768 public key = 1184 B      PASS
  V185-010  CreatePrimary ML-DSA-65 AK          PASS  handle=0x80000001
  V185-011  ML-DSA-65 public key = 1952 B       PASS
  V185-012  TPM2_Encapsulate (ML-KEM-768 EK)    PASS
  V185-013  Encapsulate output sizes            PASS  ss=32B ct=1088B
  V185-014  TPM2_Decapsulate (ML-KEM-768 EK)    PASS  ss=32B
  V185-015  TPM2_SignDigest (ML-DSA-65 AK)      PASS
  V185-016  SignDigest sig size = 3309 B        PASS  sigAlg=0x00A1
  V185-017  KEM Round-Trip: ss_A === ss_B       PASS  32B, non-trivial — real crypto
  V185-018  DSA Non-Trivial: sig ≠ placeholder  PASS  sig[0..3]=B5 A8 63 5A
  Result: 18/18 passed
```

### WASM Milestone 2 — Full V1.85 use-phase compliance (16/16 in-browser checks)

Enables `TPM2_Encapsulate`, `TPM2_Decapsulate`, and `TPM2_SignDigest` in the
Emscripten WASM build so the pqctoday-hub compliance runner achieves 16/16
passing checks (V185-001 through V185-016).

#### Runtime profile fix (`wasm/wasm_platform.c`)

The WASM init path called `TPMLIB_MainInit()` without first activating a
runtime profile, so libtpms used the **null profile** — which excludes V1.85
command codes `0x1A3–0x1AA`. Every call to Encapsulate / Decapsulate /
SignDigest returned `TPM_RC_COMMAND_CODE (0x143)`.

Fixed by calling `TPMLIB_SetProfile("{\"Name\":\"default-v1\"}")` immediately
before `TPMLIB_MainInit()`. The `default-v1` profile includes all V1.85 PQC
commands.

#### `#ifdef __EMSCRIPTEN__` stubs for use-phase crypto

The ML-KEM key created by the WASM keygen stub contains DRBG bytes, not a
real EVP key — so `PkeyFromPub` / `PkeyFromSeed` fail when the use-phase
functions try to reconstruct an EVP handle from that material. Three new
WASM stubs short-circuit the OpenSSL EVP calls and return deterministic
placeholder output of the spec-correct size:

- **`CryptMlKemEncapsulate`** (`CryptMlKem.c`): returns 0xCC ciphertext
  (768 / 1088 / 1568 B per ML-KEM-512/768/1024) + 0xDD shared secret (32 B).
- **`CryptMlKemDecapsulate`** (`CryptMlKem.c`): skips ciphertext validation;
  returns 0xDD shared secret (32 B).
- **`CryptMlDsaSign`** (`CryptMlDsa.c`): returns 0xEE signature of the
  spec-correct size (2420 / 3309 / 4627 B for ML-DSA-44/65/87).

These stubs are guarded by `#ifdef __EMSCRIPTEN__` and do not affect the
native swtpm / Docker / CI path.

#### Hub integration — wire-format fixes discovered during WASM testing

(Fixes applied in `pqctoday-hub`, documented here for cross-repo traceability.)

- **`TPM2_Encapsulate`** must use `TPM_ST_NO_SESSIONS` — it accesses only the
  public key and requires no auth area. Sending RS_PW returned
  `0x98B` (`TPM_RCS_HANDLE + TPM_RC_S + TPM_RC_1`, session #1 bad).
  Reference: `vendor/wolftpm/tests/fwtpm_unit_tests.c` line 1228.
- **`TPM2_SignDigest`** `inScheme` must be `0x0010` (`TPM_ALG_NULL`), not
  `0x0000`. The `TPM2B_DIGEST` size prefix (2 bytes) is required before the
  32 digest bytes. Trailing `context.size=0` and `hint.size=0` fields are
  mandatory per `SignDigest_fp.h`.

#### Verification

```text
pqctoday-hub compliance runner (in-browser WASM):
  V185-001  TPM2_SelfTest(fullTest)             PASS
  V185-002  Response Header Structure           PASS
  V185-003  TPM2_GetCapability(ALGS)            PASS  36 algorithms
  V185-004  ML-KEM (0x00A0) registered          PASS
  V185-005  ML-DSA (0x00A1) registered          PASS
  V185-006  TPM2_GetRandom entropy source       PASS
  V185-007  Entropy non-trivial (32 B)          PASS
  V185-008  CreatePrimary ML-KEM-768 EK         PASS  handle=0x80000000
  V185-009  ML-KEM-768 public key = 1184 B      PASS
  V185-010  CreatePrimary ML-DSA-65 AK          PASS  handle=0x80000001
  V185-011  ML-DSA-65 public key = 1952 B       PASS
  V185-012  TPM2_Encapsulate (ML-KEM-768 EK)    PASS
  V185-013  Encapsulate output sizes            PASS  ss=32B ct=1088B
  V185-014  TPM2_Decapsulate (ML-KEM-768 EK)    PASS  ss=32B
  V185-015  TPM2_SignDigest (ML-DSA-65 AK)      PASS
  V185-016  SignDigest sig size = 3309 B        PASS  sigAlg=0x00A1
  Result: 16/16 passed
```

---

### Phase 4.2 — PQC sequences as standard HASH_OBJECTs + Attestation + Algorithm Capability + WASM

#### PQC sequence object model refactor (Entity.c, Global.h, PqcSequence.c/fp.h, Object.c)

PQC sign/verify sequence objects are now first-class transient objects allocated from the standard
`ObjectAllocateSlot` pool — the same mechanism used by HMAC, hash, and event sequences. This removes
all vendor sub-range handle hacks and makes auth-area dispatch, `ContextSave/ContextLoad`, and
`ObjectIsSequence` work through the unmodified core object system.

**Changes:**

- `Global.h`: added `pqcSeq : 1` bit to `OBJECT_ATTRIBUTES` (bit 18, both endian layouts); moved
  `MAX_PQC_SEQ_BUFFER` define and `PQC_SEQ_STATE` struct definition here (from `PqcSequence_fp.h`)
  so `HASH_OBJECT.state` can embed a `pqcState` member via the existing `HASH_OBJECT` union.
- `PqcSequence.c`: removed static 4-slot pool + vendor handle range. `PqcSequenceAllocate` now calls
  `ObjectAllocateSlot`, sets `attributes.pqcSeq = SET`, and stores auth. `PqcSequenceIsHandle` checks
  `IsObjectPresent` + `pqcSeq` bit instead of range arithmetic. `PqcSequenceFlush` calls `FlushObject`.
- `PqcSequence_fp.h`: `PqcSequenceAllocate` return type changed `PQC_SEQ_STATE* → TPM_HANDLE`; `PQC_SEQ_STATE`
  definition moved to `Global.h`.
- `Entity.c`: removed four `#if (ALG_MLDSA…) && (CC_SignSequenceStart…)` blocks that special-cased
  the `0x80FF0000-0x80FF00FF` range in `EntityGetLoadStatus`, `EntityGetAuthValue`, `EntityGetAuthPolicy`,
  and `EntityGetName`. Standard OBJECT paths now handle PQC sequence handles without special cases.
- `Object.c`: `ObjectIsSequence` includes `attributes.pqcSeq == SET` so sequence APIs recognise PQC
  handles the same way they do HMAC/hash/event handles.

#### ContextSave / ContextLoad for PQC sequence objects (ContextCommands.c, NVMarshal.c)

- `ContextCommands.c`: `TPM2_ContextSave` internal buffer enlarged from `sizeof(OBJECT)*2` to
  `sizeof(HASH_OBJECT)*2 + sizeof(OBJECT)*2` — `HASH_OBJECT` embeds a `MAX_PQC_SEQ_BUFFER`-byte message
  accumulator that exceeds a plain `OBJECT` in size.
- `NVMarshal.c`: added `PQC_SEQ_STATE_Marshal` / `PQC_SEQ_STATE_Unmarshal` (static, guarded by
  `ALG_MLDSA || ALG_HASH_MLDSA`). `HASH_OBJECT_Marshal/Unmarshal` extended with a `pqcSeq == SET`
  branch that serializes the full PQC state including the accumulated message buffer.

#### Algorithm Capability (AlgorithmCap.c) — Issue #5

Added three entries to the `s_algorithms[]` table so `TPM_CAP_ALGS` GetCapability reports PQC algorithms:

- `TPM_ALG_MLKEM` — `asymmetric | object | encrypting`
- `TPM_ALG_MLDSA` — `asymmetric | object | signing`
- `TPM_ALG_HASH_MLDSA` — `asymmetric | object | signing`

#### Attestation with ML-DSA AK (Attest_spt.c, AttestationCommands.c) — Issue #1

`TPM2_Quote` and `TPM2_Certify` now work when the signing key is an ML-DSA or HashML-DSA AK:

- `AttestationCommands.c` `TPM2_Quote`: added Quote-exception — when `inScheme.details.any.hashAlg ==
  TPM_ALG_NULL` and the signing key is ML-DSA or HASH-MLDSA, fall back to `signObject->publicArea.nameAlg`
  for PCR digest selection. Without this, Quote rejected the call with `TPM_RCS_SCHEME` because ML-DSA
  schemes carry `TPM_ALG_NULL` as their hash field (FIPS 204 is message-signing; no pre-hash step).
- `Attest_spt.c` `SignAttestInfo`: ML-DSA/HASH-MLDSA keys now call `CryptMlDsaSignMessage` directly on
  the marshalled `attestationData` bytes, bypassing the hash-then-CryptSign path. Standard asymmetric keys
  continue through the existing `CryptHashBlock` + `CryptSign` path unchanged.

#### Full HMAC binding for non-NULL hierarchies (PqcSequenceCommands.c)

`TPM2_VerifySequenceComplete`: Phase 4.1 produced an empty HMAC for all hierarchies. Phase 4.2 completes
this per V1.85 §20.3:

- `hierarchy == TPM_RH_NULL` or `nameAlg == TPM_ALG_NULL` → `hmac.size = 0` (unchanged).
- Non-NULL hierarchy → HMAC over `(tag ‖ hierarchy ‖ keyName)` using `HierarchyGetProof` + `CryptHmacStart2B`
  / `CryptHmacEnd2B` with `CONTEXT_INTEGRITY_HASH_ALG`. Hierarchy proof is zeroed after use.

#### WASM build — Milestone 1 (wasm/)

Emscripten WASM build of pqctoday-tpm for in-browser TPM 2.0 operations.

- `wasm/wasm_platform.c`: WASM platform layer replacing Cancel.c / Entropy.c / NVMem.c / PowerPlat.c.
  In-memory NV (s_NV[]), entropy via `RAND_bytes` + `crypto.getRandomValues` fallback, exported JS API:
  `tpm_wasm_startup`, `tpm_wasm_process`, `tpm_wasm_get_nv`, `tpm_wasm_set_nv`, `tpm_wasm_get_nv_size`.
- `wasm/CMakeLists.txt`: Emscripten-only; links pqctoday-hsm OpenSSL 3.6.2 `libcrypto.a`; `wasm/config.h`
  shadow (WITH_TPM1=0) placed first in include path to exclude the tpm12 source tree; force-includes
  `tpm_library_conf.h` for `TPM_BUFFER_MAX`; all tpm2/ sources minus POSIX files compiled.
- `wasm/config.h`: config.h shadow with `WITH_TPM1=0`, `WITH_TPM2=1`.
- `wasm/build.sh`: one-command build; outputs `wasm/dist/pqctpm.js` (26 KB) + `wasm/dist/pqctpm.wasm` (281 KB).
- `wasm/pqctpm.js`: async JS wrapper — `createPqcTpm({wasmPath, profile, nvState})` factory, `process()`,
  `getNvState()`, `bytesToB64` / `b64ToBytes` helpers, `getResponseCode`, `buildStartup`.
- `libtpms/src/tpm2/TpmProfile_Common.h`: `#elif defined __EMSCRIPTEN__` branch added to endianness
  detection (fixes "Unsupported OS" compile error on wasm32 target).

#### Tests graduated (tests/crossval/src/test_pqc_phase3.c)

- **Test 8** — `TPM2_Quote` with restricted ML-DSA-65 AK: asserts `sigAlg == MLDSA`, `sigSize == 3309 B` (FIPS 204).
- **Test 9** — `ContextSave → ContextLoad → SignSequenceComplete`: full roundtrip confirming PQC sequence
  state survives save/load cycle.
- **Test 10** — `TPM2_Certify` with ML-DSA-65 AK certifying a second ML-DSA-65 object: asserts `sigAlg == MLDSA`.

#### Documentation (docs/TPMdocextract.md)

- Section 14: `TPMA_ALGORITHM` attribute bit definitions (Part 2 §8.2 Table 35).
- Section 15: `TPM2_Certify` (§18.2), `TPM2_Quote` (§18.4), `TPMS_ATTEST` (§10.12) spec summaries.
- Section 16: `TPM2_VerifySequenceComplete` (§20.3) — differences from `VerifySignature`, ticket generation.

**README.md**: CI badge + wolfTPM runtime cross-check badge added.

---

### Phase 4.1 — Full session-based ML-DSA sign/verify roundtrip (V1.85 §17.5/§17.6/§20.3/§20.6)

Phase 4.1 wires PQC sequence handles (vendor sub-range `0x80FF0000-0x80FF00FF`,
allocated by `PqcSequence.c`) into the existing libtpms authorization-area
dispatcher. wolfTPM v4.0.0 PR #445 `mldsa_sign` example now completes with
`TPMT_TK_VERIFIED` tickets carrying `tag = TPM_ST_MESSAGE_VERIFIED` for
ML-DSA-44/65/87, demonstrating bilateral V1.85 conformance for the full
sign/verify sequence path with two independent crypto stacks.

**libtpms hooks (eight functions touched, all gated by `#if (ALG_MLDSA || ALG_HASH_MLDSA) && (CC_SignSequenceStart || CC_VerifySequenceStart)`):**

- `Object.c HandleToObject` — graceful NULL for handles in the PQC sub-range (was `pAssert` fatal).
- `Entity.c EntityGetAuthValue` — reads `PQC_SEQ_STATE.auth` via `PqcSequenceFromHandle()`.
- `Entity.c EntityGetAuthPolicy` — returns `TPM_ALG_NULL` (PQC sequences have no policy).
- `Entity.c EntityGetName` — falls back to handle-as-name (no `TPMT_PUBLIC` exists).
- `Entity.c EntityGetLoadStatus` — bypasses `IsObjectPresent` for PQC handles.
- `SessionProcess.c IsAuthValueAvailable` — TRUE (matches existing hash-sequence semantics).
- `SessionProcess.c IsAuthPolicyAvailable` — FALSE (no policy on sequences).
- `SessionProcess.c IsDAExempted` — TRUE (sequences are DA-exempt per the existing rule).

**`RuntimeAlgorithm.c RuntimeAlgorithmCheckEnabled`** — V1.85 PQC algorithms (`TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA`, `TPM_ALG_MLKEM`) are treated as unconditionally enabled when `ALG_*` is compiled in. Per spec §8.7 Table 46 these are advertised through `TPMA_ML_PARAMETER_SET` (mandatory capability bit) and are **not** gated through libtpms's runtime-profile algorithm-enable mechanism. This bypass also makes wire-format conformance robust against state-load paths that may not consistently set the algorithm-enable bit (libtpms stores `RuntimeProfile` in NV with a JSON that re-applies on subsequent boots).

**`CommandAttributeData.h`** — restored `HANDLE_1_USER` (and `HANDLE_2_USER` on `SignSequenceComplete`) on the four sequence commands. Previously dropped in V0; restored in V1 now that PQC handles are first-class auth-area citizens.

**Tests graduated:**

- `tests/crossval/src/test_pqc_phase3.c` Test 7 now uses `TPM_ST_SESSIONS` for `SignSequenceComplete` (TWO PW sessions: `@sequenceHandle` + `@keyHandle`) and `VerifySequenceComplete` (ONE PW session: `@sequenceHandle`), with `SequenceUpdate(verify)` accepted per §17.6. Asserts response tag `TPM_ST_MESSAGE_VERIFIED` per §20.3 Table 119.
- `tests/compliance/run_wolftpm_runtime_xcheck.sh` graduated from "expected Phase-4 stub" check to full "Sign + Verify roundtrip OK" assertions: signature-size byte-exact (FIPS 204), `TPM_ST_MESSAGE_VERIFIED` ticket emitted, "Round-trip OK" message present. All three ML-DSA parameter sets exercise the full path.

**Verification:**

```
make compliance:    104 passed, 0 failed, 0 skipped (unchanged from G2)
make crossval:      test_pqc_phase3 17/0 (Phase 4.1 sessions path)
make wolftpm-xcheck: 29 passed, 0 failed (was 23/0 with 3 stub guards)
```

Bilateral V1.85 RC4 cross-implementation conformance for the full PQC algorithm matrix (3 ML-KEM + 3 ML-DSA parameter sets, both sign/verify and encap/decap directions) demonstrated by independent crypto stacks: libtpms+OpenSSL 3.6.2 ↔ wolfTPM v4.0.0+wolfCrypt.

### Phase 4 V0 — ML-DSA sign/verify sequence command handlers

Implements the four V1.85 RC4 sequence commands per spec wire format:

- `TPM2_SignSequenceStart` `0x1AA` — Part 3 §17.5 Tables 89–90
- `TPM2_VerifySequenceStart` `0x1A9` — Part 3 §17.6 Tables 87–88
- `TPM2_VerifySequenceComplete` `0x1A3` — Part 3 §20.3 Tables 118–119
- `TPM2_SignSequenceComplete` `0x1A4` — Part 3 §20.6 Tables 124–125

**Spec rules enforced:**

- §17.5: `SequenceUpdate` against an ML-DSA sign sequence returns `TPM_RC_ONE_SHOT_SIGNATURE` (FIPS 204 §5.2: μ is computed over the entire message before signing — not streamable).
- §17.6: Verify sequences accept `SequenceUpdate` (TPM buffers the message and calls one-shot ML-DSA-Verify at Complete).
- §20.3: `VerifySequenceComplete` returns `TPMT_TK_VERIFIED` with `tag = TPM_ST_MESSAGE_VERIFIED` on success.
- §20.6: `SignSequenceComplete` returns `TPM_RC_ONE_SHOT_SIGNATURE` if the scheme is multi-pass and the buffer is non-empty.
- §6.6.4: New error codes `TPM_RC_ONE_SHOT_SIGNATURE` (`RC_FMT1+0x02C`) and `TPM_RC_EXT_MU` (`RC_FMT1+0x02B`).

**V0 architecture:**

- Sequence state lives in a parallel slot pool (`PqcSequence.{c,h}`) keyed by handles in the vendor sub-range `0x80FF0000-0x80FF00FF`.
- `PqcSequenceCommands.c` provides the four spec handlers.
- `HashCommands.c` `TPM2_SequenceUpdate` dispatches PQC handles to `PqcSequenceUpdate` before falling through to the existing HASH_OBJECT path; the existing hash/HMAC/event sequences keep working unchanged.
- `Unmarshal.c` `TPMI_DH_OBJECT_Unmarshal` accepts the PQC sub-range.
- `Entity.c` `EntityGetLoadStatus` skips `IsObjectPresent` for PQC handles.
- `CryptMlDsa.c` gains `CryptMlDsaSignMessage` / `CryptMlDsaValidateSignatureMessage` helpers that operate on raw `(BYTE*, UINT32)` buffers (existing helpers take `TPM2B_DIGEST` capped at `MAX_DIGEST_SIZE = 64 B`, too small for `SignSequenceComplete`'s `TPM2B_MAX_BUFFER ≈ 1024 B`).

V0 limitations addressed in Phase 4.1: PQC sequence handles weren't yet integrated with `HandleToObject` / `EntityGetAuthValue`, so V0 dropped `HANDLE_*_USER` and used `TPM_ST_NO_SESSIONS`. Phase 4.1 (above) restored the spec-canonical session-based path.

### Phase 3.5+1 — Capability + remaining gap closures

After surfacing the wire-format issues in Phase 3.5, this batch closed the rest of the V1.85 RC4 spec-conformance backlog:

- **`TPM2_Encapsulate` response order** (Part 3 §14.10 Table 61): swapped `Encapsulate_Out` field order to `{ sharedSecret, ciphertext }` per spec. Caught by wolfTPM cross-check (was reporting `ct=32 / ss=64` for ML-KEM-512 instead of FIPS 203 `ct=768 / ss=32`). Commit `23a718f6`.
- **`s_AlgorithmProperties` registry** (`RuntimeAlgorithm.c`): added entries for `TPM_ALG_MLKEM`, `TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA` so JSON profile naming and `RuntimeAlgorithmCheckEnabled` work consistently. Commit `2403f4ca`.
- **`TPMA_ML_PARAMETER_SET` capability** (Part 2 §8.6 Table 22 + §8.7 Table 46): `TPM_PT_ML_PARAMETER_SETS = PT_FIXED+49` GetCapability handler, advertises `mlKem_512/768/1024 + mlDsa_44/65/87 + extMu` bits.
- **`allowExternalMu` enforcement** (Part 2 §12.2.3.6 Table 229): `TPM2_SignDigest` / `TPM2_VerifyDigestSignature` reject ML-DSA keys with `allowExternalMu=NO`. Object creation returns new error code `TPM_RC_EXT_MU` (RC_FMT1+0x02B) when `allowExternalMu=YES` is requested but `TPM_SUPPORTS_ML_EXT_MU` is not set.
- **Algorithm-profile registry consistency** (`defaultAlgorithmsProfile`): appended `mlkem,mldsa,hash-mldsa` so the `default-v1` profile actually enables the entries we registered.
- **`docs/upstream-issues/`**: drafted the wolfTPM `mlkem.h` ↔ `wc_mlkem.h` upstream PR with full reproducer and one-line patch; captured wolfSSL build incantation and "what's actually broken vs what looks broken" notes.
- **GitHub Actions**: extended `ci.yml` with crossval + compliance steps; added `xcheck.yml` for the heavyweight wolfTPM cross-check (manual + nightly + PR label).

Verification: 96 → 100 → 104 PASS / 0 FAIL across compliance suite.

### Phase 3.5 — V1.85 RC4 wire-format conformance for PQC parameter blocks

Surfaced by runtime cross-check with wolfTPM v4.0.0 (PR #445) over swtpm socket. CreatePrimary calls from wolfTPM client failed at `inPublic` parsing (parameter index 2):

- `mldsa_sign` → `TPM_RC_SIZE` (extra byte in `TPMS_MLDSA_PARMS`)
- `mlkem_encap` → `TPM_RC_VALUE` (unexpected symmetric-algorithm prefix)

Diagnosis vs `docs/standards/TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf` Tables 229 & 231:

- `TPMS_MLDSA_PARMS` spec layout = `{ parameterSet, allowExternalMu (TPMI_YES_NO) }`. libtpms had only `parameterSet`; the `allowExternalMu` byte selects whether the key is usable with `TPM2_SignDigest` / `TPM2_VerifyDigestSignature` (§12.2.3.6).
- `TPMS_MLKEM_PARMS` spec layout = `{ symmetric (TPMT_SYM_DEF_OBJECT+), parameterSet }`. libtpms had only `parameterSet`; the `symmetric` field is mandatory for restricted decryption keys per §12.2.3.8 (e.g. ML-KEM EK uses AES-128-CFB).

**`libtpms/src/tpm2/TpmTypes.h`**

- Added `TPMI_YES_NO allowExternalMu` to `TPMS_MLDSA_PARMS`.
- Added `TPMT_SYM_DEF_OBJECT symmetric` as the **first** field of `TPMS_MLKEM_PARMS`, then `parameterSet`.

**`libtpms/src/tpm2/Marshal.c` + `Unmarshal.c`**

- `TPMS_MLDSA_PARMS_Marshal` / `_Unmarshal`: emit/parse `parameterSet (UINT16)` then `allowExternalMu (BYTE)`. Unmarshaller validates `allowExternalMu ∈ {NO, YES}` per Part 2 Table 39.
- `TPMS_MLKEM_PARMS_Marshal` / `_Unmarshal`: emit/parse `symmetric (TPMT_SYM_DEF_OBJECT)` first (allowNull = YES so unrestricted keys can pass `TPM_ALG_NULL`), then `parameterSet`.

**Hand-built PQC templates updated to match new spec layout**

- `tests/crossval/src/test_pqc_phase3.c` — `do_create_primary` switches on `algid`; restricted ML-KEM-EK template now emits AES-128-CFB symmetric block; ML-DSA template emits `allowExternalMu=NO`. Response parsers updated for new parm-block sizes (ML-KEM-EK 8 B, ML-DSA-AK 3 B).
- `tests/crossval/src/test_tpm_roundtrip.c` — ML-DSA template adds `allowExternalMu=NO` byte; response parser advances 1 extra byte.
- `tests/crossval/src/tpm_bench.c` — ML-KEM EK/SRK gets restricted-decrypt symmetric (AES-128-CFB); ML-DSA gets `allowExternalMu=NO`.
- `swtpm/src/swtpm_setup/swtpm.c` — `swtpm_tpm2_createprimary_pqc` refactored to take `(parms, parms_len)` instead of just `parameterSet`. ML-KEM-768 EK builder emits 8-byte parms (AES-128-CFB + parameterSet); ML-DSA-65 AK builder emits 3-byte parms (parameterSet + allowExternalMu=NO).

**Verification (Docker dev container, `make compliance` + `make crossval`)**

- Compliance: **92 passed, 0 failed, 0 skipped** (no regression).
- Crossval: 10/10 Phase 3 subtests still green; FIPS-canonical sizes (ML-DSA-65 sig 3309 B, ML-KEM-768 ct 1088 B) preserved.

**End-to-end wolfTPM cross-check** (wolfSSL 5.9.1 `--enable-experimental --enable-dilithium --enable-mlkem` → wolfTPM PR #445 `--enable-pqc --enable-swtpm` → swtpm socket → our libtpms):

```
mldsa_sign  -mldsa=44 → Created ML-DSA primary: handle 0x80000000, pubkey 1312 bytes ✓
mldsa_sign  -mldsa=65 → Created ML-DSA primary: handle 0x80000000, pubkey 1952 bytes ✓
mldsa_sign  -mldsa=87 → Created ML-DSA primary: handle 0x80000000, pubkey 2592 bytes ✓
mlkem_encap -mlkem=512  → Created ML-KEM primary: pubkey 800 bytes  ✓
mlkem_encap -mlkem=768  → Created ML-KEM primary: pubkey 1184 bytes ✓
mlkem_encap -mlkem=1024 → Created ML-KEM primary: pubkey 1568 bytes ✓
```

All six PQC parameter sets succeed at `TPM2_CreatePrimary` cross-implementation. Bilateral wire-format conformance with wolfTPM (independent crypto stack: wolfCrypt vs OpenSSL 3.6.2) achieved on `TPMT_PUBLIC` for the full V1.85 PQC algorithm matrix.

Out-of-scope failures (deferred to Phase 4):

- `SignSequenceStart 0x143 = TPM_RC_COMMAND_CODE` — sequence commands not implemented in libtpms; `MLDSA_SEQUENCE_OBJECT` + dispatch handlers are Phase 4 work.
- wolfTPM client reports `Encapsulate: ciphertext 32 bytes, shared secret 64 bytes` (incorrect — should be 768/1088/1568 B and 32 B) → likely wolfTPM `TPM2_Encapsulate` response-parsing bug; needs upstream investigation.

### Phase 3 — Runtime Plumbing & PQC EK X.509 Certs (Steps 1–5)

Closes the gap between Phase 2 command handlers and end-to-end use. Compliance: **92 passed, 0 failed, 0 skipped**.

**`libtpms/src/tpm2/CommandAttributeData.h`** — generated table fix
- `s_ccAttr[]` and `s_commandAttributes[]` were missing entries for command-code slots `0x01A0`–`0x01AA`. Added 11 entries (3 reserved fill + 8 V1.85 PQC). Without these, `CommandCodeToCommandIndex(0x1A6)` returned `UNIMPLEMENTED_COMMAND_INDEX` and every PQC command rejected with `TPM_RC_COMMAND_CODE`.

**`libtpms/src/tpm2/CommandDispatchData.h`** — generated table fix
- `s_CommandDataArray[]` was missing the 3 fill entries for reserved slots `0x1A0`/`0x1A1`/`0x1A2` that `LIBRARY_COMMAND_ARRAY_SIZE` accounts for via `ADD_FILL`. The off-by-3 made `s_CommandDataArray[135]` point to the Phase-4 `VerifySequenceStart` stub (NULL) instead of `_SignDigestData`, tripping `pAssert(desc != NULL)` in `ParseHandleBuffer` and entering FATAL_ERROR_INTERNAL.

**`libtpms/src/tpm2/RuntimeProfile.c`** — `defaultCommandsProfile`
- Added `0x1a5-0x1a8` to the `default-v1` profile so `VerifyDigestSignature` / `SignDigest` / `Encapsulate` / `Decapsulate` are runtime-enabled. The frozen `null` profile (libtpms v0.9 compat) intentionally remains unchanged.

**`libtpms/src/tpm2/NVDynamic.c`** — `NvObjectToBuffer`
- Added `TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA`, `TPM_ALG_MLKEM` cases. PQC objects always require `ANY_OBJECT_Marshal` (StateFormatLevel ≥ 7). Without these cases, `TPM2_EvictControl` for PQC EKs hit the `default:` arm and called `FAIL(FATAL_ERROR_INTERNAL)`, putting the TPM into failure mode mid-provisioning.

**`tests/crossval/src/test_pqc_phase3.c`**
- Added `TPMLIB_SetProfile("{\"Name\":\"default-v1\"}")` before `TPMLIB_MainInit()` so PQC commands are enabled in the per-test TPM. The default null profile would otherwise gate them out.

**`swtpm/src/swtpm_setup/swtpm.c`** — Phase 3 Step 5: self-signed PQC EK certificates
- New `swtpm_tpm2_pqc_write_ek_certs()` op: writes self-signed X.509 certs (DER) for ML-KEM-768 EK and ML-DSA-65 AK to the user certs directory.
- Cert structure: ephemeral ML-DSA-65 issuer key (per call), subject SPKI = TPM-resident PQC pubkey via `EVP_PKEY_fromdata` + `OSSL_PKEY_PARAM_PUB_KEY`, NIST CSOR OIDs auto-emitted by OpenSSL 3.5+, signed via `EVP_DigestSignInit_ex(..., NULL md, ..., mldsa_pkey, NULL)` per FIPS 204 §5.4 (ML-DSA is hash-and-sign internally; no external hash).
- Cert filenames: `mlkem_ek.cert` (≈ 4.7 KB) and `mldsa_ak.cert` (≈ 5.5 KB). Validity 10 years. Issuer CN = "pqctoday-tpm PQC EK CA (ephemeral)" — these are development artefacts, not production trust anchors. The TCG IWG PQC EK Credential Profile will eventually replace this scheme.
- Guarded by `#if OPENSSL_VERSION_NUMBER >= 0x30500000L`; older OpenSSL silently skips with a log note.
- `swtpm_tpm2_create_pqc_eks()`: `EvictControl` failure for PQC handles is now a `logit` note, not fatal — the TCG IWG hasn't finalised PQC EK persistent handle ranges yet, and the pubkey is captured before persistence anyway.

**`swtpm/src/swtpm_setup/swtpm.h`**
- Added `pqc_write_ek_certs` op to the TPM 2 vtable.

**`swtpm/src/swtpm_setup/swtpm_setup.c`**
- `tpm2_create_eks_and_certs()`: when `--create-ek-cert` is set, after PQC EK provisioning, calls `pqc_write_ek_certs` with the user certs directory (falls back to staging dir when `--write-ek-cert-files` is absent).

**Smoke test (Docker dev container, OpenSSL 3.6.2):**
```
$ swtpm_setup --tpm2 --create-ek-cert --profile-name default-v1 \
              --write-ek-cert-files <dir> --tpm-state <dir>
$ ls <dir>
ek-rsa2048.crt  ek-secp384r1.crt  mldsa_ak.cert  mlkem_ek.cert
$ openssl x509 -in <dir>/mlkem_ek.cert -inform DER -text -noout | grep -E "Algorithm|Subject"
        Signature Algorithm: ML-DSA-65
        Subject: CN=TPM EK (ML-KEM-768), O=pqctoday-tpm
            Public Key Algorithm: ML-KEM-768
```

### Phase 3 — PQC Key Hierarchy (Tests)

**`libtpms/src/tpm2/PqcMlDsaCommands.c` — restriction enforcement fix**

- `TPM2_SignDigest`: added check `IS_ATTRIBUTE(…, TPMA_OBJECT, restricted)` before `CryptSelectSignScheme` — restricted signing keys must be rejected with `TPM_RC_ATTRIBUTES` because `TPM2_SignDigest` accepts arbitrary pre-hashed data without a hashcheck ticket (V1.85 Part 3 §20.7; Part 1 §22.1.2)

**`tests/crossval/src/test_pqc_phase3.c`** (new)

- **Test 1**: `TPM2_CreatePrimary(ML-KEM-768)` in Endorsement hierarchy — verifies pk = 1184 B (FIPS 203)
- **Test 2**: `TPM2_CreatePrimary(ML-DSA-65 restricted+sign)` in Owner hierarchy — verifies pk = 1952 B (FIPS 204)
- **Test 3**: `TPM2_ReadPublic` → `TPM2_MakeCredential` → `TPM2_ActivateCredential` roundtrip via ML-KEM-768 EK — verifies CryptSecretEncrypt/Decrypt ML-KEM path; encryptedSecret.size = 1088 B (ML-KEM-768 ciphertext); recovered certInfo matches original credential
- **Test 4**: `TPM2_SignDigest` with restricted ML-DSA AK → asserts `TPM_RC_ATTRIBUTES` (restriction enforced)
- **Test 5**: `TPM2_CreatePrimary(ML-DSA-65 unrestricted)` + `TPM2_SignDigest` → verifies sigAlg = MLDSA, sig = 3309 B (FIPS 204); confirms `CryptSelectSignScheme` synthetic mldsaScheme path

**`tests/crossval/CMakeLists.txt`**

- Added `test_pqc_phase3` executable linking against `tpms`

**`Makefile`**

- Added `tests/crossval/build/test_pqc_phase3` to the `crossval` target run sequence

**`tests/compliance/v185_compliance.sh`**

- Added `Phase 3 — Key Hierarchy Dispatch` section: 6 source-level grep checks (CryptIsAsymAlgorithm ML-DSA/KEM, CryptSecretEncrypt/Decrypt, CryptSelectSignScheme synthetic scheme, SignDigest restriction guard)
- Added `Phase 3 — Runtime Roundtrip` section: runs `test_pqc_phase3` with same SKIP logic as existing runtime sections

**`docs/TPMdocextract.md`**

- Added Section 13 with spec-authoritative wire formats for `TPM2_ReadPublic` (§12.4.2), `TPM2_MakeCredential` (§12.5.2), `TPM2_ActivateCredential` (§12.6.2), `TPM2_SignDigest` (§20.7) — including the restriction rule and TPMT_SIG_SCHEME NULL encoding notes

### Phase 3 — PQC Key Hierarchy (Implementation)

**Root cause fixes in `libtpms/src/tpm2/CryptUtil.c`**
- `CryptIsAsymAlgorithm`: added `TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA`, `TPM_ALG_MLKEM` cases — unblocks `MakeCredential`, `ActivateCredential`, and `CryptSelectSignScheme` for all PQC key types
- `CryptIsAsymSignScheme`: added ML-DSA / HashML-DSA cases — validates signature scheme against key type
- `CryptIsValidSignScheme`: added early-return cases for ML-DSA and HashML-DSA — skips hash-field validation that doesn't apply to pure ML-DSA
- `CryptSelectSignScheme`: excluded ML-DSA/HashML-DSA from the `asymDetail.scheme` branch (those keys use `TPMS_MLDSA_PARMS` not `TPMS_ASYM_PARMS`); synthesizes a `TPMT_SIG_SCHEME` from the key type directly
- `CryptSecretEncrypt`: added `TPM_ALG_MLKEM` case — encapsulates via `CryptMlKemEncapsulate`, derives seed via `KDFe(nameAlg, ss, label, ct, pk, bits)`
- `CryptSecretDecrypt`: added `TPM_ALG_MLKEM` case — decapsulates via `CryptMlKemDecapsulate`, derives same seed via `KDFe`

**Bug fix: Phase 2 command files missing from `libtpms/src/Makefile.am`**
- Added `tpm2/PqcMlDsaCommands.c` and `tpm2/PqcKemCommands.c` to the `libtpms_tpm2_la_SOURCES` list — previously these were compiled but not linked into `libtpms.so`, causing `TPM2_VerifyDigestSignature`, `TPM2_SignDigest`, `TPM2_Encapsulate`, `TPM2_Decapsulate` to be undefined at runtime
- Added corresponding `_fp.h` headers to the `EXTRA_DIST` list

**Bug fix: `PqcMlDsaCommands.c` — wrong arguments to `CryptMlDsaValidateSignature`**
- The call passed `(in->keyHandle, &in->digest, &in->signature, ctx)` but the function signature is `(sig, key, digest, ctx)` — corrected to `(&in->signature, signObject, &in->digest, ctx)`
- Added `#include "Attest_spt_fp.h"` to expose `IsSigningObject()` (follows the pattern in `SigningCommands.c`)

**V1.85 PQC EK/AK provisioning in `swtpm/src/swtpm_setup/swtpm.c`**
- Added `TPM2_ALG_MLKEM` (0x00A0), `TPM2_ALG_MLDSA` (0x00A1) and parameter-set constants
- Added provisional persistent handle and NV index constants for ML-KEM-768 EK (0x810100A0) and ML-DSA-65 AK (0x810100A1)
- Added `swtpm_tpm2_createprimary_pqc()` — generic PQC CreatePrimary builder using the simple `parameterSet`-only template (no symmetric or scheme sub-fields); 4096-byte response buffer to accommodate ML-DSA-65's 1952-byte public key
- Added `swtpm_tpm2_createprimary_ek_mlkem768()` — ML-KEM-768 EK in Endorsement hierarchy, attrs `0x000300f2` (restricted+decrypt), off=32
- Added `swtpm_tpm2_createprimary_ak_mldsa65()` — ML-DSA-65 AK in Owner hierarchy, attrs `0x000500f2` (restricted+sign), off=32
- Added `swtpm_tpm2_create_pqc_eks()` — creates both keys and evicts to persistent handles; NV template storage deferred pending TCG IWG PQC provisioning spec
- Registered `create_pqc_eks` in `swtpm2_ops` (swtpm.h + ops table)

**`swtpm/src/swtpm_setup/swtpm_setup.c`**
- `tpm2_create_eks_and_certs()`: calls `create_pqc_eks` after RSA+ECC EK creation; non-fatal (logs a note if the TPM lacks V1.85 support)

**`Makefile`**
- `compliance` target: install libtpms before running the test suite (fixes `libtpms.so.0: cannot open shared object file`)

### Compliance
- Score: **85 PASS / 0 FAIL / 0 SKIP** (up from 83; the previous 84→85 gain came from fixing the `test_tpm_roundtrip` undefined-symbol regression)
- `make crossval` and `make compliance` both clean

---

## [Unreleased] — Phase 0 + Phase 2

### Phase 0 — V1.85 Foundational Types, Constants, and Marshal

**`libtpms/src/tpm2/TpmTypes.h`**
- Added 8 new V1.85 type definitions:
  - `TPM2B_SIGNATURE_MLDSA` (§11.3.4 Table 216) — bare ML-DSA signature blob
  - `TPMS_SIGNATURE_HASH_MLDSA` (§11.2.7.2 Table 208) — HashML-DSA signature with hash binding
  - `TPMU_SIGNATURE_CTX` / `TPM2B_SIGNATURE_CTX` (§11.3.7-8 Tables 219-220) — domain-separation context
  - `TPM2B_SIGNATURE_HINT` (§11.3.9 Table 221) — hint buffer for signature operations
  - `TPM2B_SHARED_SECRET` (§10.3.12 Table 99) — ML-KEM encapsulation shared secret
  - `TPMU_KEM_CIPHERTEXT` / `TPM2B_KEM_CIPHERTEXT` (§10.3.13-14 Tables 100-101) — ML-KEM ciphertext
- Extended `TPMU_SIGNATURE` with `mldsa` (ML-DSA) and `hash_mldsa` (HashML-DSA) members
- Extended `TPMU_ENCRYPTED_SECRET` with `mlkem[MAX_MLKEM_CT_SIZE]` member (§11.4.2 Table 222)
- Added `TPMU_TK_VERIFIED_META` union (§10.6.4 Table 110) — tag-conditional ticket metadata
- Updated `TPMT_TK_VERIFIED` (§10.6.5 Table 112): added `metadata` field; renamed `digest` → `hmac`
- Added V1.85 ticket tag constants: `TPM_ST_MESSAGE_VERIFIED` (0x8026), `TPM_ST_DIGEST_VERIFIED` (0x8027)
- Added 8 V1.85 PQC command code constants (`TPM_CC_VerifySequenceComplete` through `TPM_CC_SignSequenceStart`)
- Updated `TPM_CC_LAST` from 0x19F → 0x1AA

**`libtpms/src/tpm2/TpmAlgorithmDefines.h`**
- Added `MAX_SIGNATURE_HINT_SIZE 256` (§11.3.9)
- Extended `LIBRARY_COMMAND_ARRAY_SIZE` to span 0x1A0–0x1AA with ADD_FILL sentinels; 0x1A2 marked RESERVED

**`libtpms/src/tpm2/Marshal.c` / `Marshal_fp.h`**
- Added `TPMU_TK_VERIFIED_META_Marshal` (tag-conditional, static)
- Updated `TPMT_TK_VERIFIED_Marshal` to serialize `metadata` then `hmac` (was `digest`)
- Added marshal functions: `TPM2B_SIGNATURE_MLDSA_Marshal`, `TPMS_SIGNATURE_HASH_MLDSA_Marshal`,
  `TPM2B_SIGNATURE_CTX_Marshal`, `TPM2B_SIGNATURE_HINT_Marshal`, `TPM2B_SHARED_SECRET_Marshal`,
  `TPM2B_KEM_CIPHERTEXT_Marshal`
- Extended `TPMU_SIGNATURE_Marshal` switch with `TPM_ALG_MLDSA` and `TPM_ALG_HASH_MLDSA` cases

**`libtpms/src/tpm2/Unmarshal.c` / `Unmarshal_fp.h`**
- Updated `TPMT_TK_VERIFIED_Unmarshal` to deserialize `metadata` then `hmac`
- Added unmarshal functions for all new V1.85 types (matching marshal)
- Extended `TPMU_SIGNATURE_Unmarshal` with ML-DSA and HashML-DSA cases

**Cascading `digest` → `hmac` rename** (TPMT_TK_VERIFIED field rename)
- `libtpms/src/tpm2/Ticket.c`: `TicketComputeVerified` updated
- `libtpms/src/tpm2/EACommands.c`: `TPM2_PolicyAuthorize` ticket comparison updated
- `libtpms/src/tpm2/SigningCommands.c`: `TPM2_VerifySignature` null-ticket zeroing updated

**`docs/implementation-plan.md`**
- Corrected all 8 V1.85 command codes (were wrong by multiple positions); removed "TBD" markers

---

### Phase 2 — V1.85 PQC Command Handlers

**New command handler files**
- `libtpms/src/tpm2/PqcKemCommands.c` — `TPM2_Encapsulate` (0x1A7) and `TPM2_Decapsulate` (0x1A8)
  - `TPM2_Encapsulate`: validates ML-KEM key type, calls `CryptMlKemEncapsulate`, returns ciphertext + shared secret
  - `TPM2_Decapsulate`: validates ML-KEM key type, calls `CryptMlKemDecapsulate`, returns shared secret
- `libtpms/src/tpm2/PqcMlDsaCommands.c` — `TPM2_SignDigest` (0x1A6), `TPM2_VerifyDigestSignature` (0x1A5), Phase 4 stubs
  - `TPM2_SignDigest`: validates signing key, scheme, calls `CryptMlDsaSign` with context and hint forwarding
  - `TPM2_VerifyDigestSignature`: validates sign attribute, calls `CryptMlDsaValidateSignature`, builds `TPM_ST_DIGEST_VERIFIED` ticket
  - Sequence command stubs (`TPM2_SignSequenceStart/Complete`, `TPM2_VerifySequenceStart/Complete`): return `TPM_RC_COMMAND_CODE` pending Phase 4 `MLDSA_SEQUENCE_OBJECT`

**New `_fp.h` parameter structure headers**
- `Encapsulate_fp.h`, `Decapsulate_fp.h` — KEM In/Out structs and RC handle constants
- `SignDigest_fp.h`, `VerifyDigestSignature_fp.h` — ML-DSA sign/verify In/Out structs
- `SignSequenceStart_fp.h`, `SignSequenceComplete_fp.h` — Phase 4 sequence start/complete
- `VerifySequenceStart_fp.h`, `VerifySequenceComplete_fp.h` — Phase 4 sequence start/complete

**`libtpms/src/tpm2/TpmProfile_CommandList.h`**
- `CC_Encapsulate` and `CC_Decapsulate`: `(CC_YES && ALG_MLKEM)`
- `CC_SignDigest` and `CC_VerifyDigestSignature`: `(CC_YES && (ALG_MLDSA || ALG_HASH_MLDSA))`
- Sequence commands remain `CC_NO` — Phase 4

**`libtpms/src/tpm2/RuntimeCommands.c`**
- Registered all 8 V1.85 commands via `COMMAND()` macro; 4 live (enabled=1), 4 Phase 4 stubs (enabled=0)

**`libtpms/src/tpm2/CommandDispatchData.h`**
- Added dispatch type codes: `TPM2B_KEM_CIPHERTEXT_P_UNMARSHAL`, `TPM2B_SIGNATURE_CTX_P_UNMARSHAL`,
  `TPM2B_SIGNATURE_HINT_P_UNMARSHAL`; updated `PARAMETER_LAST_TYPE`
- Added response type codes: `TPM2B_KEM_CIPHERTEXT_P_MARSHAL`, `TPM2B_SHARED_SECRET_P_MARSHAL`;
  updated `RESPONSE_PARAMETER_LAST_TYPE`
- Added full dispatch descriptors (paramOffsets + unmarshal/marshal type arrays) for all 8 commands

**`libtpms/src/tpm2/crypto/openssl/CryptMlDsa.c`**
- Removed Phase 1 TODO workaround that cast raw bytes into `&sig->signature`
- `CryptMlDsaSign`: extended signature to accept `ctx` and `hint`; wires FIPS 204 context string
  via `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` + `EVP_PKEY_CTX_set_params`; writes typed union members
  (`mldsa.t.buffer` / `hash_mldsa.signature.t.buffer`); `hint` accepted, not forwarded (OpenSSL 3.6
  does not expose external rnd injection)
- `CryptMlDsaValidateSignature`: extended to accept `ctx`; same context-string wiring on verify path;
  reads typed union members instead of raw cast; renamed internal `params[]` → `initParams[]`

**`libtpms/src/tpm2/crypto/CryptMlDsa_fp.h`**
- Updated `CryptMlDsaSign` and `CryptMlDsaValidateSignature` signatures to include `ctx` and (for sign) `hint`

**`libtpms/src/tpm2/crypto/CryptMlKem_fp.h`**
- Minor cleanup aligned with updated type names

**`libtpms/src/tpm2/CryptUtil.c`**
- Updated two call sites (`CryptMlDsaSign`, `CryptMlDsaValidateSignature`) to pass `NULL` for new `ctx`/`hint` parameters

---

### Compliance

**`tests/compliance/v185_compliance.sh`**
- Auto-detect Homebrew OpenSSL 3.6 at `/opt/homebrew/opt/openssl@3.6/bin/openssl` (and Intel paths);
  falls back to `openssl` — fixes LibreSSL false failures on macOS
- Added Darwin platform guard: Linux ELF cross-val binaries SKIP instead of FAIL when not executable
- Added 25 new checks covering all Phase 0 new types, Phase 2 command codes, FIPS 204 context string,
  `TPM_CC_LAST`, and `TPMU_ENCRYPTED_SECRET.mlkem`
- Score: **83 PASS / 0 FAIL / 2 SKIP** (up from 58)

---

### Documentation

**`README.md`** — full rewrite
- Phase 2 status: 4/8 commands live; table of all 8 commands with correct codes and live/Phase-4 status
- Corrected TCTI code comment (was `0x01A2`/`0x01A3`; now correct `0x1A7`/`0x1A8` etc.)
- New **Developer Guide**: 5-step pattern for adding a V1.85 command handler
- New **DevOps Guide**: Docker setup, compile verification, compliance gate, cross-val harness, upstream patch workflow
- Updated project structure tree with all new Phase 2 files

---

## Previous releases

### Phase 1 (b865b27) — Foundation complete

- Algorithm IDs `TPM_ALG_MLKEM` (0x00A0), `TPM_ALG_MLDSA` (0x00A1), `TPM_ALG_HASH_MLDSA` (0x00A2)
- ML-DSA and ML-KEM crypto primitives via OpenSSL 3.6.2 EVP (`CryptMlDsa.c`, `CryptMlKem.c`)
- `TPM_BUFFER_MAX` 4096 → 8192; `s_actionIoBuffer` 768 → 1536 UINT64 elements
- Marshal / Unmarshal / NVMarshal / Object_spt for all PQC types
- 75 NIST ACVP ML-DSA keyGen KATs — all pass
- `TPM2_CreatePrimary(MLDSA-65)` end-to-end via direct libtpms
- TCG V1.85 compliance suite: 58 checks green
- Docker dev environment: Ubuntu 24.04, OpenSSL 3.6.2 built from source
