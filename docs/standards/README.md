# TCG TPM 2.0 Library Specification — V1.85 (Published, March 12, 2026)

This directory archives the normative references for this project's PQC work.
Every algorithm ID, command code, structure tag, and error value committed
to `libtpms/src/tpm2/` traces back to a table in one of these documents.

**As of 2026-07-23 the normative reference is the PUBLISHED V1.85
(March 12, 2026) plus its Errata Version 1** — superseding the V1.85 RC4
(12 Dec 2025) drafts this fork was originally developed against. The RC4
PDFs are retained below for provenance (they document what the C code was
written from); any NEW work must cite the published documents, and existing
RC4-derived citations should be re-verified against the published tables
when touched (section/table numbers may have shifted between RC4 and
publication).

Starting with V1.85, TCG merged the "Supporting Routines" material (legacy
Part 4) into the inline reference code in Part 3. V1.85 therefore ships as
four parts rather than the five parts of earlier revisions.

## Normative documents (PUBLISHED — use these)

| File | Document | Source |
|------|----------|--------|
| [Trusted-Platform-Module-2.0-Library-Part-0-Introduction_Version-185_pub.pdf](Trusted-Platform-Module-2.0-Library-Part-0-Introduction_Version-185_pub.pdf) | Part 0: Introduction (Published 2026-03-12) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-0-Introduction_Version-185_pub.pdf) |
| [Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf](Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf) | Part 1: Architecture (Published 2026-03-12) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf) |
| [Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf](Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf) | Part 2: Structures (Published 2026-03-12) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf) |
| [Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf](Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf) | Part 3: Commands + Supporting Routines (Published 2026-03-12) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf) |
| [Eratta-Trusted-Platform-Module-2.0-Library_Version-185_pub.pdf](Eratta-Trusted-Platform-Module-2.0-Library_Version-185_pub.pdf) | **Errata for TPM Library v185, Version 1** (2026-03-12; filename typo "Eratta" is TCG's own) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Eratta-Trusted-Platform-Module-2.0-Library_Version-185_pub.pdf) |
| [TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.7_Pub.pdf](TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.7_Pub.pdf) | EK Credential Profile v2.7 (Published — supersedes the RC1 below) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/) |
| [PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-v1p07_Pub.pdf](PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-v1p07_Pub.pdf) | PC Client Platform TPM Profile (PTP) v1.07 (Published 2026) — **makes ML-KEM + ML-DSA support mandatory for PC-class TPMs** (the Library spec itself keeps them optional) | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/) |

## Errata v1 summary (what changed vs the published text)

Eight errata + two clarifications; none change command wire formats. The
ones that matter to this fork and its consumers:

- **§2.1** `TPM_SPEC` constants: `TPM_SPEC_VERSION=185`, `TPM_SPEC_YEAR=0`
  (now always zero), new `TPM_SPEC_ERRATA=1` (renamed from
  `TPM_SPEC_DAY_OF_YEAR`).
- **§2.2** `TPM2_SignSequenceStart()` may fail-fast the `x509sign`
  attribute check instead of deferring it to `SignSequenceComplete()`.
- **§2.3** `TPMU_SIG_SCHEME` for `TPM_ALG_MLDSA`/`TPM_ALG_HASH_MLDSA` is
  to be read as `TPMS_EMPTY`.
- **§2.4** `TPM_RC_NO_RESULT` is the expected error when ML-DSA
  rejection sampling exceeds the implementation's iteration limit
  (FIPS 204 fn. 10 / Appendix C); sessions left as if never executed.
- **§2.5** `TPM2_VerifyDigestSignature()` over an external Mu: the
  resulting `TPMT_TK_VERIFIED` is not viable for `TPM2_PolicyAuthorize()`
  (it cannot recompute the `tr` hash), so a conforming TPM SHOULD return a
  NULL ticket instead. *This fork (built from RC4) still returns
  `TPM_ST_DIGEST_VERIFIED` — divergence to resolve or document.*
- **§2.6** `TPM2_Quote()` with schemeless signatures (pure ML-DSA, EdDSA):
  `pcrDigest` uses the signing key's **Name algorithm**; `TPM_ALG_NULL`
  nameAlg → `TPM_RC_SCHEME`.
- **§2.7/2.8** Same Name-algorithm rule for `TPM2_NV_Certify()`; a TPM may
  return `TPM_RC_SIZE` for large-buffer NV certification with ML-DSA keys.

## Superseded drafts (provenance only — do NOT cite for new work)

| File | Document |
|------|----------|
| [TPM-2.0-Library-Part-0_Introduction-V185-RC4.pdf](TPM-2.0-Library-Part-0_Introduction-V185-RC4.pdf) | Part 0, V1.85 RC4 (12 Dec 2025) |
| [TPM-2.0-Library-Part-1_Architecture-V185-RC4.pdf](TPM-2.0-Library-Part-1_Architecture-V185-RC4.pdf) | Part 1, V1.85 RC4 (12 Dec 2025) |
| [TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf](TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf) | Part 2, V1.85 RC4 (12 Dec 2025) |
| [TPM-2.0-Library-Part-3_Commands-V185-RC4.pdf](TPM-2.0-Library-Part-3_Commands-V185-RC4.pdf) | Part 3, V1.85 RC4 (12 Dec 2025) |
| [TCG-EK-Credential-Profile-for-TPM-Family-2p0-Level-0-V2p7-RC1_7November2025.pdf](TCG-EK-Credential-Profile-for-TPM-Family-2p0-Level-0-V2p7-RC1_7November2025.pdf) | EK Credential Profile v2.7 RC1 (7 Nov 2025) |

## Compliance anchors — where each pqctoday-tpm change is derived

Values below were originally derived from RC4 and re-checked against the
published Part 2 §6.3/§6.5/§6.9 tables (unchanged at publication):

| pqctoday-tpm artifact | V1.85 citation |
|---|---|
| `ALG_MLKEM_VALUE = 0x00A0` (TpmTypes.h)       | Part 2 §6.3 "TPM_ALG_ID" table, row TPM_ALG_MLKEM           |
| `ALG_MLDSA_VALUE = 0x00A1` (TpmTypes.h)       | Part 2 §6.3 "TPM_ALG_ID" table, row TPM_ALG_MLDSA           |
| `ALG_HASH_MLDSA_VALUE = 0x00A2` (TpmTypes.h)  | Part 2 §6.3 "TPM_ALG_ID" table, row TPM_ALG_HASH_MLDSA      |
| `MLDSA_{44,65,87}_*_SIZE` (TpmAlgorithmDefines.h)    | Part 2 §15 "ML-DSA" + FIPS 204 §7.6 Table 3          |
| `MLKEM_{512,768,1024}_*_SIZE` (TpmAlgorithmDefines.h) | Part 2 §14 "ML-KEM" + FIPS 203 §8 Table 3           |
| `MLDSA_PRIVATE_SEED_SIZE = 32`                | Part 2 "TPM2B_PRIVATE_KEY_MLDSA" — size shall be 32 (seed ξ)|
| `MLKEM_PRIVATE_SEED_SIZE = 64`                | Part 2 "TPM2B_PRIVATE_KEY_MLKEM" — size shall be 64 (d‖z)  |
| `MAX_SIGNATURE_CTX_SIZE = 255`                | Part 2 "TPM2B_SIGNATURE_CTX" definition (domain separation) |
| `TPM_BUFFER_MAX = 8192`                       | Required so ML-DSA-87 signatures (4627 B) + TPM header + auth sessions fit a single command/response. |
| `TPM_CC_Encapsulate = 0x1A7`                  | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_Decapsulate = 0x1A8`                  | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_SignDigest = 0x1A6`                   | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_SignSequenceStart = 0x1AA`            | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_SignSequenceComplete = 0x1A4`         | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_VerifySequenceStart = 0x1A9`          | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_VerifySequenceComplete = 0x1A3`       | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_VerifyDigestSignature = 0x1A5`        | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_ST_MESSAGE_VERIFIED = 0x8026`            | Part 2 §6.9 "TPM_ST" table                                  |
| `TPM_ST_DIGEST_VERIFIED = 0x8027`             | Part 2 §6.9 "TPM_ST" table                                  |
| `TPM_RC_EXT_MU = RC_FMT1 + 0x02B`             | Part 2 §6.6 "TPM_RC" table                                  |

## Cross-reference sources (non-normative)

- [wolfTPM PR #445](https://github.com/wolfSSL/wolfTPM/pull/445) —
  reference implementation by wolfSSL tracking V1.85. Used to
  sanity-check our numeric values.
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice
  KEM (ML-KEM). Normative for ML-KEM behavior.
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice
  Digital Signature (ML-DSA). Normative for ML-DSA behavior.

## License

TCG specifications are published under a royalty-free reproduction
license (see Part 0 §1 "Copyright Licenses"). We keep local copies here
so every contributor can verify the implementation against the spec
without an external download.

## Refreshing

```bash
cd docs/standards
BASE="https://trustedcomputinggroup.org/wp-content/uploads"
for F in \
  "Trusted-Platform-Module-2.0-Library-Part-0-Introduction_Version-185_pub.pdf" \
  "Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf" \
  "Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf" \
  "Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf" \
  "Eratta-Trusted-Platform-Module-2.0-Library_Version-185_pub.pdf"; do
  curl -sfL -O "$BASE/$F"
done
```

Check [trustedcomputinggroup.org/resource/tpm-library-specification/](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
for newer revisions or errata versions before starting spec-derived work.
