# V2.7 RC1 PQC EK Template — Reference Byte Vectors

Hand-encoded byte vectors for the 6 mandatory PQC EK `TPMT_PUBLIC` structures
in TCG EK Credential Profile **V2.7 RC1** (2025-11-07), Tables 13 and 14.

These are the **spec-anchored ground truth** used by:

- `tests/compliance/clients/ek_conformance_xcheck.c` — the wolfTPM-driven
  runtime conformance test that calls `TPM2_ReadPublic` on each provisioned
  EK and byte-diffs the marshalled response against these references.
- `tests/compliance/v185_compliance.sh` — source-level check that the
  reference header constants match the spec exactly.

## Source

Encoded by hand from:

- `docs/standards/TCG-EK-Credential-Profile-for-TPM-Family-2p0-Level-0-V2p7-RC1_7November2025.pdf`
  Tables 13 (ML-KEM Storage), 14 (ML-DSA Signing), 7 (Object Attributes),
  8 (PolicyB digests).
- Spec text extracted into `docs/TPMdocextract.md` §17 — review there for
  the spec language without opening the PDF.
- Algorithm IDs from TCG TPM 2.0 Library V1.85 Part 2 Table 9 (verified
  against `libtpms/src/tpm2/TpmTypes.h:163-170`).

## Format

Each variant is a single contiguous `TPMT_PUBLIC` byte stream as defined in
V1.85 Part 2 §12.2.4 Table 200. The wire-format order is:

```text
type            (2 B BE)       // TPM_ALG_MLKEM = 0x00A0  /  TPM_ALG_MLDSA = 0x00A1
nameAlg         (2 B BE)       // SHA-256 / SHA-384 / SHA-512 by variant
objectAttributes(4 B BE)       // V2.7 §5.4.5.1 Table 7 (0x000300B2 storage / 0x000500B2 signing)
authPolicy.size (2 B BE)       // 32 / 48 / 64 by hash
authPolicy.buf  (size B)       // PolicyB SHA-256/384/512 (V2.7 §5.4.5.2 Table 8)
parameters      (variant)      // TPMS_MLKEM_PARMS (8 B) or TPMS_MLDSA_PARMS (3 B)
unique.size     (2 B BE)       // 0 — empty buffer per Tables 13/14
```

## Byte totals (no surprises — every byte accounted for)

| Variant | type | nameAlg | attrs | authPolicy {sz,buf} | parms | unique{sz} | Total |
|---|---|---|---|---|---|---|---|
| ML-KEM-512  | 2 | 2 | 4 | 2 + 32 | 8 | 2 | **52** |
| ML-KEM-768  | 2 | 2 | 4 | 2 + 48 | 8 | 2 | **68** |
| ML-KEM-1024 | 2 | 2 | 4 | 2 + 64 | 8 | 2 | **84** |
| ML-DSA-44   | 2 | 2 | 4 | 2 + 32 | 3 | 2 | **47** |
| ML-DSA-65   | 2 | 2 | 4 | 2 + 48 | 3 | 2 | **63** |
| ML-DSA-87   | 2 | 2 | 4 | 2 + 64 | 3 | 2 | **79** |

## Updating these vectors

When V2.7 RC1 → V2.7 Final ships (or any later TCG revision lands), the
diff process is:

1. Drop the new spec PDF into `docs/standards/`.
2. Re-extract relevant tables into `docs/TPMdocextract.md` §17.
3. Re-encode any changed byte vector by hand, leaving an inline comment with
   the spec line that motivated the change.
4. `make ek-conformance-xcheck` against the unchanged TPM-side templates
   will go RED for any non-trivial drift — fix the templates until green.

Do **not** generate these vectors from the very code they validate — that's
circular. Hand-encoding from the spec, with one set of human eyes per byte,
is the whole point.
