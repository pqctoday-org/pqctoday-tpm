# TCG TPM 2.0 Library Specification V1.85 RC4 — PQC Reference Extract

**Source:** TCG TPM 2.0 Library Specification V1.85 RC4 (2025-12-11)  
**Files:** `docs/standards/TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf` and `docs/standards/TPM-2.0-Library-Part-3_Commands-V185-RC4.pdf`  
**Purpose:** Fast-lookup reference for PQC compliance cross-checks. All values are spec-authoritative.

---

## 1. Algorithm Identifiers (Part 2 §6.3 — TCG Algorithm Registry)

Numeric values assigned by TCG Algorithm Registry. Correspond to `TCG_ALG_x` in the registry.

| Constant | Value | Algorithm |
|---|---|---|
| TPM_ALG_MLKEM | **0x00A0** | ML-KEM (FIPS 203) |
| TPM_ALG_MLDSA | **0x00A1** | ML-DSA (FIPS 204) |
| TPM_ALG_HASH_MLDSA | **0x00A2** | HashML-DSA (FIPS 204 §5.4.1) |

> These three IDs are the complete PQC addition to the algorithm registry in V1.85.

---

## 2. PQC Command Codes (Part 2 Table 11, p.52)

All 8 new V1.85 PQC command codes, in code order. **0x1A2 is RESERVED.**

| Value | Command | Description |
|---|---|---|
| 0x000001A2 | *(RESERVED)* | Not a command; reserved slot |
| 0x000001A3 | TPM_CC_VerifySequenceComplete | Complete a HashML-DSA verify sequence |
| 0x000001A4 | TPM_CC_SignSequenceComplete | Complete a HashML-DSA sign sequence |
| 0x000001A5 | TPM_CC_VerifyDigestSignature | Verify ML-DSA signature over pre-hashed digest |
| 0x000001A6 | TPM_CC_SignDigest | Sign pre-hashed digest with ML-DSA |
| 0x000001A7 | TPM_CC_Encapsulate | ML-KEM encapsulation (key generation + wrap) |
| 0x000001A8 | TPM_CC_Decapsulate | ML-KEM decapsulation (unwrap) |
| 0x000001A9 | TPM_CC_VerifySequenceStart | Start a HashML-DSA verify sequence |
| 0x000001AA | TPM_CC_SignSequenceStart | Start a HashML-DSA sign sequence |

> `TPM_CC_LAST = 0x000001AA` — SignSequenceStart is the last defined command.

**Commands by functional group:**

| Group | Commands |
|---|---|
| ML-KEM KEM | Encapsulate (0x1A7), Decapsulate (0x1A8) |
| ML-DSA bare sign/verify | SignDigest (0x1A6), VerifyDigestSignature (0x1A5) |
| HashML-DSA streaming sign | SignSequenceStart (0x1AA), SignSequenceComplete (0x1A4) |
| HashML-DSA streaming verify | VerifySequenceStart (0x1A9), VerifySequenceComplete (0x1A3) |

---

## 3. ML-KEM Parameter Sets (Part 2 §11.2.6, Table 204, p.182)

| Parameter set | Numeric value | Public key (bytes) | Ciphertext (bytes) | Shared secret (bytes) |
|---|---|---|---|---|
| TPM_MLKEM_NONE | 0x0000 | — | — | — |
| TPM_MLKEM_512 | 0x0001 | 800 | 768 | 32 |
| TPM_MLKEM_768 | 0x0002 | 1184 | 1088 | 32 |
| TPM_MLKEM_1024 | 0x0003 | 1568 | 1568 | 32 |

> Values correspond to FIPS 203 [4]. Shared secret = 32 bytes for all parameter sets.

**Buffer size constants derived from Table 204:**

| Constant | Value | Basis |
|---|---|---|
| MAX_MLKEM_PUB_SIZE | 1568 | largest public key (ML-KEM-1024) |
| MAX_MLKEM_PRIV_SEED_SIZE | 64 | Table 206: `buffer[64]` = d‖z seed |
| MAX_MLKEM_CT_SIZE | impl-dependent | max ciphertext for supported param sets; ML-KEM-1024 max = 1568 |
| MAX_SHARED_SECRET_SIZE | impl-dependent | depends on KEMs supported (note: Table 99) |

---

## 4. ML-DSA Parameter Sets (Part 2 §11.2.7, Table 207, p.183-184)

| Parameter set | Numeric value | Public key (bytes) | Signature (bytes) |
|---|---|---|---|
| TPM_MLDSA_NONE | 0x0000 | — | — |
| TPM_MLDSA_44 | 0x0001 | 1312 | 2420 |
| TPM_MLDSA_65 | 0x0002 | 1952 | 3309 |
| TPM_MLDSA_87 | 0x0003 | 2592 | 4627 |

> Values correspond to FIPS 204 [5].

**Buffer size constants derived from Table 207:**

| Constant | Value | Basis |
|---|---|---|
| MAX_MLDSA_PUB_SIZE | 2592 | largest public key (ML-DSA-87) |
| MAX_MLDSA_SIG_SIZE | 4627 | largest signature (ML-DSA-87) |
| MAX_MLDSA_PRIV_SEED_SIZE | 32 | Table 210: `buffer[32]` = ξ seed |

---

## 5. PQC Structure Definitions (Part 2)

### 5.1 ML-KEM Structures

#### TPM2B_PUBLIC_KEY_MLKEM (§11.2.6.2, Table 205, p.183)
```
{
  UINT16 size;
  BYTE   buffer[size] {:MAX_MLKEM_PUB_SIZE};
}
```
Holds encoded ML-KEM public key per FIPS 203 Algorithm 19 (ML-KEM.KeyGen).

#### TPM2B_PRIVATE_KEY_MLKEM (§11.2.6.3, Table 206, p.183)
```
{
  UINT16 size;   // shall be 64
  BYTE   buffer[64];   // 64-byte private seed (d‖z)
}
```

#### TPM2B_SHARED_SECRET (§10.3.12, Table 99, p.139)
```
{
  UINT16 size;
  BYTE   buffer[size] {:MAX_SHARED_SECRET_SIZE};
}
```
> **`MAX_SHARED_SECRET_SIZE` is TPM-dependent** (depends on KEM algorithms supported). For ML-KEM-only TPMs the minimum is 32; wolfTPM reserves 64 for future salted session extensions.

#### TPMU_KEM_CIPHERTEXT (§10.3.13, Table 100, p.140)
```
union {
  BYTE  ecdh[sizeof(TPMS_ECC_POINT)];   // selector: TPM_ALG_ECC
  BYTE  mlkem[MAX_MLKEM_CT_SIZE];        // selector: TPM_ALG_MLKEM
}
```
> Used internally for `TPM2B_KEM_CIPHERTEXT`. **`MAX_MLKEM_CT_SIZE` is not fixed by spec**; it equals the largest ciphertext for ML-KEM parameter sets supported by the TPM. For ML-KEM-1024 only: 1568 bytes.

#### TPM2B_KEM_CIPHERTEXT (§10.3.14, Table 101, p.140)
```
{
  UINT16 size;
  BYTE   buffer[size] {:sizeof(TPMU_KEM_CIPHERTEXT)};
}
```

---

### 5.2 ML-DSA Structures

#### TPM2B_PUBLIC_KEY_MLDSA (§11.2.7.3, Table 209, p.184)
```
{
  UINT16 size;
  BYTE   buffer[size] {:MAX_MLDSA_PUB_SIZE};
}
```
Holds encoded ML-DSA public key per FIPS 204 Algorithm 22 (pkEncode).

#### TPM2B_PRIVATE_KEY_MLDSA (§11.2.7.4, Table 210, p.185)
```
{
  UINT16 size;   // shall be 32
  BYTE   buffer[32];   // 32-byte private seed ξ
}
```

#### TPM2B_SIGNATURE_MLDSA (§11.3.4, Table 216, p.186) — SPEC-CANONICAL NAME
```
{
  UINT16 size;
  BYTE   buffer[size] {:MAX_MLDSA_SIG_SIZE};
}
```
> **Naming warning:** The spec-canonical name is `TPM2B_SIGNATURE_MLDSA`. wolfTPM v4.0.0 uses `TPM2B_MLDSA_SIGNATURE` — this diverges from the spec. Use spec name in new code.

#### TPMS_SIGNATURE_HASH_MLDSA (§11.2.7.2, Table 208, p.184)
```
struct {
  TPMI_ALG_HASH       hash;       // hash algorithm (TPM_ALG_NULL not allowed)
  TPM2B_SIGNATURE_MLDSA signature;
}
```

---

### 5.3 Signature Union Extensions (Part 2 §11.3.5, Table 217, p.187)

New members added to `TPMU_SIGNATURE` in V1.85:

| Member | Type | Selector |
|---|---|---|
| mldsa | TPM2B_SIGNATURE_MLDSA | TPM_ALG_MLDSA |
| hash_mldsa | TPMS_SIGNATURE_HASH_MLDSA | TPM_ALG_HASH_MLDSA |

> Note from spec (Table 217): `mldsa`, `eddsa`, and `hash_eddsa` members are **TPM2B types** (not TPMS types), because unlike other signature types there is no hash algorithm choice to include in the signature metadata.

---

### 5.4 Signature Context Structures (Part 2 §11.3.7-§11.3.9, p.187-189)

**New in V1.85 — required for SignSequenceStart / VerifySequenceStart.**

#### TPMU_SIGNATURE_CTX (§11.3.7, Table 219, p.188)
```
union {
  BYTE  commitCount[sizeof(UINT16)];   // selector: TPM_ALG_ECDAA
  BYTE  buffer[MAX_SIG_CTX_BYTES];     // selector: TPM_ALG_MLDSA or TPM_ALG_HASH_MLDSA
  BYTE  empty[0];                       // all other values
}
```
> `MAX_SIG_CTX_BYTES` is **implementation-dependent**. For TPMs supporting ML-DSA or HashML-DSA, it must be **≥ 255**. Illustrative structure only — implementations may vary.

#### TPM2B_SIGNATURE_CTX (§11.3.8, Table 220, p.188)
```
{
  UINT16 size;
  BYTE   context[size] {:sizeof(TPMU_SIGNATURE_CTX)};
}
```
Used by `TPM2_SignSequenceComplete()` and `TPM2_VerifySequenceComplete()`.

#### TPM2B_SIGNATURE_HINT (§11.3.9, Table 221, p.189)
```
{
  UINT16 size;
  BYTE   hint[size] {:MAX_SIGNATURE_HINT_SIZE};
}
```
> `MAX_SIGNATURE_HINT_SIZE` is **implementation-dependent** (not a fixed spec value). For EdDSA, hint contains encoded R value. For all other algorithms the buffer must be zero-length. wolfTPM sets this to 256. Used by `TPM2_VerifySequenceStart()`.

---

### 5.5 Public Area Union Extensions (Part 2 §12.2.3.2, Table 225, p.192)

New members added to `TPMU_PUBLIC_ID` in V1.85:

| Member | Type | Selector |
|---|---|---|
| mldsa | TPM2B_PUBLIC_KEY_MLDSA | TPM_ALG_MLDSA or TPM_ALG_HASH_MLDSA |
| mlkem | TPM2B_PUBLIC_KEY_MLKEM | TPM_ALG_MLKEM |

New entries in `TPMI_ALG_PUBLIC` (Table 224, p.191):
- TPM_ALG_MLDSA
- TPM_ALG_HASH_MLDSA
- TPM_ALG_MLKEM

---

### 5.6 PQC Public-Parameter Structures (Part 2 §12.2.3, Tables 229-231)

> **Critical for wire-format compliance.** These structures appear in `TPMT_PUBLIC.parameters` for `TPM_ALG_MLDSA` / `TPM_ALG_HASH_MLDSA` / `TPM_ALG_MLKEM` keys. Field order on the wire MUST match the spec exactly — wolfTPM cross-check (May 2026) caught two omissions in libtpms here, fixed in Phase 3.5.

#### TPMS_MLDSA_PARMS (§12.2.3.6, Table 229) — V1.85 NEW

```
struct TPMS_MLDSA_PARMS {
    TPMI_MLDSA_PARMS  parameterSet;     // ML-DSA parameter set ID (44/65/87)
    TPMI_YES_NO       allowExternalMu;  // YES → key usable with TPM2_SignDigest +
                                        //       TPM2_VerifyDigestSignature; the
                                        //       digest field is interpreted as the
                                        //       512-byte external Mu (μ) value
                                        //       computed per FIPS 204
};
```

**Wire size:** 3 bytes (UINT16 + BYTE).

When `allowExternalMu = YES`, the spec mandates that:
- `TPM2_SignDigest` and `TPM2_VerifyDigestSignature` accept the key.
- ML-DSA keys can ALWAYS be used with `TPM2_SignSequenceComplete` and `TPM2_VerifySequenceComplete` regardless of this flag.
- Object creation and `TPM2_TestParms()` return `TPM_RC_EXT_MU` if `allowExternalMu` is YES but the parameter set or implementation doesn't support external-Mu.

#### TPMS_HASH_MLDSA_PARMS (§12.2.3.7, Table 230) — V1.85 NEW (Pre-Hash ML-DSA)

```
struct TPMS_HASH_MLDSA_PARMS {
    TPMI_MLDSA_PARMS  parameterSet;  // ML-DSA parameter set ID
    TPMI_ALG_HASH     hashAlg;       // pre-hash function PH (e.g. SHA-256)
};
```

**Wire size:** 4 bytes (UINT16 + UINT16).

#### TPMS_MLKEM_PARMS (§12.2.3.8, Table 231) — V1.85 NEW

```
struct TPMS_MLKEM_PARMS {
    TPMT_SYM_DEF_OBJECT+  symmetric;     // FIRST. For restricted decryption
                                         // keys → AES/CAMELLIA + keyBits + mode.
                                         // Otherwise → TPM_ALG_NULL (no keyBits/mode).
    TPMI_MLKEM_PARMS      parameterSet;  // ML-KEM parameter set ID (512/768/1024)
};
```

**Wire size:** depends on `symmetric.algorithm`:
- AES-128-CFB restricted EK: `2 + 2 + 2 + 2` = **8 bytes** (alg + keyBits + mode + parameterSet).
- TPM_ALG_NULL: `2 + 2` = **4 bytes** (alg + parameterSet, no keyBits/mode).

> ⚠ **Field order matters.** `symmetric` is FIRST per the spec. libtpms versions before commit `ea52cf9d` (Phase 3.5) had only `parameterSet`; that violated wire-format conformance and broke runtime cross-implementation interop with wolfTPM.

---

### 5.7 ML-DSA Parameter-Set Capability (Part 2 §6 Table 46) — V1.85 NEW

```
TPMA_ML_PARAMETER_SET (UINT32 attributes)
  bit 0       supports ML-KEM-512
  bit 1       supports ML-KEM-768
  bit 2       supports ML-KEM-1024
  bit 3       supports ML-DSA-44
  bit 4       supports ML-DSA-65
  bit 5       supports ML-DSA-87
  bit 6       Indicates support for allowExternalMu for ML-DSA
  bit 31:7    Reserved
```

Read via `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_ML_PARAMETER_SETS)`. A TPM that exposes `TPMS_MLDSA_PARMS.allowExternalMu = YES` MUST advertise bit 6 here.

> **Implementation gap (open):** libtpms supports the field syntactically (Phase 3.5) but does not yet expose this capability bit nor enforce `allowExternalMu` in `TPM2_SignDigest` / `TPM2_VerifyDigestSignature`. Tracked under Phase 3.5+ work.

---

### 5.8 Key/Secret Exchange (Part 2 §11.4, Table 222, p.189)

#### TPMU_ENCRYPTED_SECRET additions
```
union {
  BYTE  ecc[sizeof(TPMS_ECC_POINT)];   // TPM_ALG_ECC
  BYTE  rsa[MAX_RSA_KEY_BYTES];          // TPM_ALG_RSA
  BYTE  mlkem[MAX_MLKEM_CT_SIZE];        // TPM_ALG_MLKEM  ← new in V1.85
  BYTE  symmetric[sizeof(TPM2B_DIGEST)]; // TPM_ALG_SYMCIPHER
}
```
> Note: This is separate from `TPMU_KEM_CIPHERTEXT`. Both contain `mlkem[MAX_MLKEM_CT_SIZE]` but serve different purposes (`TPMU_ENCRYPTED_SECRET` is for session secrets; `TPMU_KEM_CIPHERTEXT` is the raw KEM output).

---

## 6. Implementation-Dependent Size Constants Summary

| Constant | Spec says | Minimum | wolfTPM choice | Our choice |
|---|---|---|---|---|
| MAX_MLKEM_CT_SIZE | impl-dependent | max ciphertext of supported param sets | 2048 | 1568 (ML-KEM-1024 max) |
| MAX_SHARED_SECRET_SIZE | impl-dependent | 32 (for ML-KEM only) | 64 | 32 |
| MAX_SIG_CTX_BYTES | impl-dependent | ≥ 255 for ML-DSA/HashML-DSA | not reported | TBD (Phase 2) |
| MAX_SIGNATURE_HINT_SIZE | impl-dependent | sufficient for all supported hints | 256 | TBD (Phase 2) |
| MAX_2B_BUFFER_SIZE | impl-dependent | ≥ 1024 (Table 95) | — | — |

---

## 7. Fixed Size Constants (from spec derivation, not "implementation-dependent")

| Constant | Value (bytes) | Source |
|---|---|---|
| MAX_MLKEM_PUB_SIZE | 1568 | Table 204 — ML-KEM-1024 public key |
| MAX_MLKEM_PRIV_SEED_SIZE | 64 | Table 206 — d‖z private seed |
| MAX_MLDSA_PUB_SIZE | 2592 | Table 207 — ML-DSA-87 public key |
| MAX_MLDSA_SIG_SIZE | 4627 | Table 207 — ML-DSA-87 signature |
| MAX_MLDSA_PRIV_SEED_SIZE | 32 | Table 210 — ξ private seed |
| MAX_SIGNATURE_CTX_SIZE | 255 | Table 219 — minimum for ML-DSA (≥ 255) |
| MLKEM_SHARED_SECRET_SIZE | 32 | Table 204 — all ML-KEM param sets |

---

## 8. Naming Pitfalls — Three-Way Divergence

The ML-DSA signature buffer type has three different names in different contexts:

| Context | Name used |
|---|---|
| **TCG V1.85 RC4 spec (authoritative)** | `TPM2B_SIGNATURE_MLDSA` |
| wolfTPM v4.0.0 | `TPM2B_MLDSA_SIGNATURE` |
| pqctoday-tpm Phase 1 plan | `TPMS_SIGNATURE_MLDSA` (wrong — TPMS implies struct, not byte buffer) |

**Use `TPM2B_SIGNATURE_MLDSA` in all new code.**

The HashML-DSA signature struct `TPMS_SIGNATURE_HASH_MLDSA` is consistent across spec and wolfTPM (different field names but same layout: `{hash, signature}`).

---

## 9. Ticket Tags and Updated TPMT_TK_VERIFIED (Part 2 §10.6.5, Tables 111-112, p.145-146)

### Ticket tag values (Table 20, p.67-68; Table 111, p.146)

| TPM_ST constant | Value | Producing command |
|---|---|---|
| TPM_ST_VERIFIED | 0x8022 | TPM2_VerifySignature() |
| TPM_ST_MESSAGE_VERIFIED | **0x8026** | TPM2_VerifySequenceComplete() |
| TPM_ST_DIGEST_VERIFIED | **0x8027** | TPM2_VerifyDigestSignature() |

### TPMU_TK_VERIFIED_META (§10.6.4, Table 110, p.145) — **NEW in V1.85**

Union of additional metadata carried inside `TPMT_TK_VERIFIED`. Zero-length for most variants:

```
union TPMU_TK_VERIFIED_META {
  verified:        TPMS_EMPTY    selector: TPM_ST_VERIFIED         (empty — no metadata)
  messageVerified: TPMS_EMPTY    selector: TPM_ST_MESSAGE_VERIFIED  (empty — no metadata)
  digestVerified:  TPM_ALG_ID    selector: TPM_ST_DIGEST_VERIFIED   (hash algo used for digest)
}
```

> `digestVerified` carries the `TPM_ALG_ID` of the hash that was used to produce the pre-hashed digest in `TPM2_VerifyDigestSignature()`. This allows the verifier to know what hash was applied.

### TPMT_TK_VERIFIED (§10.6.5, Table 112, p.146) — **Updated in V1.85**

```
struct TPMT_TK_VERIFIED {
  tag:             TPM_ST                  must be TPM_ST_VERIFIED, TPM_ST_MESSAGE_VERIFIED,
                                           or TPM_ST_DIGEST_VERIFIED
  hierarchy:       TPMI_RH_HIERARCHY+
  [tag]metadata:   TPMU_TK_VERIFIED_META   ← NEW in V1.85; zero-length for VERIFIED/MESSAGE_VERIFIED
  hmac:            TPM2B_DIGEST            ← RENAMED from "digest" in V1.85 (spec note: earlier
                                             versions called this "digest"; renamed to reduce ambiguity)
}
```

> **Impact on existing code:** The field formerly named `digest` is now `hmac`. The `[tag]metadata` field is new and must be serialized before `hmac` in the wire format. Both `TPMT_TK_VERIFIED` in `TpmTypes.h` and all marshal/unmarshal code referencing `.digest` must be updated.

These ticket types are used by the three ML-DSA verify commands and with `TPM2_PolicySigned()`.

---

## 10. New Response Codes (Part 2 Table 17, p.57-61)

V1.85 adds new format-one response codes — PQC-specific (0x02A–0x02D) and secure-channel (0x030–0x031):

| Name | Value | Description |
|---|---|---|
| TPM_RC_PARMS | RC_FMT1 + 0x02A | parameter set not supported |
| TPM_RC_EXT_MU | RC_FMT1 + 0x02B | external-Mu not supported |
| TPM_RC_ONE_SHOT_SIGNATURE | RC_FMT1 + 0x02C | TPM does not support signing arbitrarily long messages; entire message must be in the buffer parameter of TPM2_SignSequenceComplete() |
| TPM_RC_SIGN_CONTEXT_KEY | RC_FMT1 + 0x02D | key used to finish the signature context is not the same as the one used to start it |
| TPM_RC_CHANNEL | RC_FMT1 + 0x030 | command requires secure channel protection (not PQC-specific) |
| TPM_RC_CHANNEL_KEY | RC_FMT1 + 0x031 | secure channel was not established with required requester or TPM key (not PQC-specific) |

---

## 11. TPMU_ENCRYPTED_SECRET — Complete V1.85 Layout (§11.4.2, Table 222, p.189)

The complete union including the new `mlkem` member added in V1.85:

```
union TPMU_ENCRYPTED_SECRET {
  ecc[sizeof(TPMS_ECC_POINT)]:  BYTE    selector: TPM_ALG_ECC
  rsa[MAX_RSA_KEY_BYTES]:        BYTE    selector: TPM_ALG_RSA
  mlkem[MAX_MLKEM_CT_SIZE]:      BYTE    selector: TPM_ALG_MLKEM   ← NEW in V1.85
  symmetric[sizeof(TPM2B_DIGEST)]: BYTE  selector: TPM_ALG_SYMCIPHER
  keyedHash[sizeof(TPM2B_DIGEST)]: BYTE  selector: TPM_ALG_KEYEDHASH
}
```

> Table 222 is **illustrative** — the actual union is implementation-dependent based on algorithms supported. The spec note says: "It would be modified depending on the algorithms supported in the TPM."
> `MAX_MLKEM_CT_SIZE` is the implementation's largest supported ML-KEM ciphertext (1568 for ML-KEM-1024).

---

## 12. Pages Read Per Section

| Section | Pages read |
|---|---|
| §6.3 Algorithm IDs | ToC + wolfTPM cross-check (values confirmed via compliance script) |
| §6.6 TPM_RC (response codes) | Part 2 pp.55-63 |
| §6.9 TPM_ST constants (Table 20) | Part 2 pp.65-68 |
| Table 11 — command codes | Part 2 pp.47-56 (previous session) |
| §10.3 Sized buffers | Part 2 pp.134-148 |
| §10.3.12-14 KEM types | Part 2 pp.139-140 |
| §10.6.4-5 Tickets — TPMU_TK_VERIFIED_META, TPMT_TK_VERIFIED | Part 2 pp.143-148 |
| §11.2.6 ML-KEM | Part 2 pp.182-183 |
| §11.2.7 ML-DSA | Part 2 pp.183-185 |
| §11.3 Signatures (Tables 216-221) | Part 2 pp.185-189 |
| §11.4 Key/Secret Exchange (Tables 222-223) | Part 2 pp.189-190 |
| §12.2.2 TPMI_ALG_PUBLIC (Table 224) | Part 2 p.191 |
| §12.2.3.2 TPMU_PUBLIC_ID (Table 225) | Part 2 p.192 |
| §12.5-12.6 MakeCredential / ActivateCredential wire formats | Part 3 pp.192-200 (Phase 3) |
| §22.1.2 Restricted signing key policy | Part 1 §22.1.2 (Phase 3) |
| §29.2.1 TPM2_SignDigest restriction rule | Part 3 §29.2.1 (Phase 3) |

---

## 13. Phase 3 Command Wire Formats (Part 3)

These formats are used by `test_pqc_phase3.c` and cross-checked with the spec.

### 13.1 TPM2_ReadPublic (Part 3 §12.4.2, CC = 0x00000173)

Tag: `TPM_ST_NO_SESSIONS`

**Request:**

```text
tag (2) = 0x8001
size (4)
commandCode (4) = 0x00000173
objectHandle (4)   // handle of loaded object
```

**Response:**

```text
tag (2) = 0x8001
size (4)
responseCode (4) = 0 on success
outPublic (TPM2B_PUBLIC)     // size(2) + TPMT_PUBLIC
name (TPM2B_NAME)            // size(2) + name bytes
qualifiedName (TPM2B_NAME)   // size(2) + qualified name bytes
```

Name format for SHA-256 nameAlg: `0x000B` (2 B) || SHA-256(TPMT_PUBLIC) (32 B) = 34 bytes.

---

### 13.2 TPM2_MakeCredential (Part 3 §12.5.2, CC = 0x00000172)

Tag: `TPM_ST_NO_SESSIONS` (no authorization required — uses public key only).

**Request:**

```text
tag (2) = 0x8001
size (4)
commandCode (4) = 0x00000172
H1: objectHandle (4)          // loaded EK or other decryption key
P1: credential (TPM2B_DIGEST) // secret to protect; size ≤ nameAlg hash size
P2: objectName (TPM2B_NAME)   // name of object that will call ActivateCredential
```

**Response:**

```text
tag (2) = 0x8001
size (4)
responseCode (4) = 0 on success
credentialBlob (TPM2B_ID_OBJECT)       // encrypted credential + HMAC binding
encryptedSecret (TPM2B_ENCRYPTED_SECRET)  // encrypted seed
```

For ML-KEM-768 EK: `encryptedSecret.size = 1088` (ML-KEM-768 ciphertext per FIPS 203 Table 2).
The seed derivation uses `CryptSecretEncrypt(MLKEM)` → `CryptMlKemEncapsulate` + `KDFe`.

---

### 13.3 TPM2_ActivateCredential (Part 3 §12.6.2, CC = 0x00000147)

Tag: `TPM_ST_SESSIONS` (two authorizations required: H1 activateHandle + H2 keyHandle).

**Request:**

```text
tag (2) = 0x8002
size (4)
commandCode (4) = 0x00000147
H1: activateHandle (4)    // loaded object whose name was bound in MakeCredential
H2: keyHandle (4)         // loaded EK — must match objectHandle from MakeCredential
authArea (4 + sessions):  // size field + two TPMS_AUTH_COMMAND entries
  session1 {handle(4), nonce(TPM2B), sessionAttributes(1), hmac(TPM2B)}  // for activateHandle
  session2 {handle(4), nonce(TPM2B), sessionAttributes(1), hmac(TPM2B)}  // for keyHandle
P1: credentialBlob (TPM2B_ID_OBJECT)       // from MakeCredential
P2: encryptedSecret (TPM2B_ENCRYPTED_SECRET)  // from MakeCredential
```

**Response:**

```text
tag (2) = 0x8002
size (4)
responseCode (4) = 0 on success
paramSize (4)
certInfo (TPM2B_DIGEST)   // recovered credential — equals MakeCredential.credential
authArea (session responses)
```

Password session (TPM_RS_PW = 0x40000009) with empty auth satisfies authorization when
both handles have `userWithAuth = 1` and empty `authValue`. Each session = 9 bytes:
`{handle(4)=0x40000009, nonce.size(2)=0, sessionAttribs(1)=0, hmac.size(2)=0}`.

---

### 13.4 TPM2_SignDigest (Part 3 §29.2.1, CC = 0x000001A6) — V1.85

Tag: `TPM_ST_SESSIONS`.

**Request:**

```text
tag (2) = 0x8002
size (4)
commandCode (4) = 0x000001A6
H1: keyHandle (4)           // loaded ML-DSA or HashML-DSA signing key; must NOT be restricted
authArea (4 + session):
  session {handle(4), nonce(TPM2B), sessionAttribs(1), hmac(TPM2B)}
P1: inScheme (TPMT_SIG_SCHEME)  // {scheme(2), details}; TPM_ALG_NULL (2B only) → key default
P2: digest (TPM2B_DIGEST)       // {size(2), buffer[32]}  (SHA-256 hash)
P3: context (TPM2B_SIGNATURE_CTX)  // {size(2)=0} for no context
P4: hint (TPM2B_SIGNATURE_HINT)    // {size(2)=0} for no hint
```

**Response (success):**

```text
tag (2) = 0x8002
size (4)
responseCode (4) = 0
paramSize (4)
TPMT_SIGNATURE:
  sigAlg (2) = TPM_ALG_MLDSA (0x00A1)
  TPMU_SIGNATURE.mldsa = TPM2B_SIGNATURE_MLDSA:
    size (2) = 3309   // ML-DSA-65 per FIPS 204 Table 3
    buffer[3309]
authArea (session response)
```

**Restriction rule (V1.85 §29.2.1; Part 1 §22.1.2):** Restricted signing keys (`TPMA_OBJECT.restricted = 1`) MUST be rejected with `TPM_RC_ATTRIBUTES + TPM_RC_H + TPM_RC_1 = 0x182`. TPM2_SignDigest accepts arbitrary pre-hashed data with no hashcheck ticket; allowing restricted keys would bypass the restriction security property. Use `TPM2_Sign` (with a `TPMT_TK_HASHCHECK` ticket) for restricted keys.

**Note on TPMT_SIG_SCHEME wire encoding for NULL scheme:** When `inScheme.scheme = TPM_ALG_NULL` (0x0010), the `TPMU_SIG_SCHEME` is the `nullScheme` arm = `TPMS_EMPTY` = 0 bytes. The wire encoding is just 2 bytes (the scheme selector). The TPM then uses the key's implicit scheme (ML-DSA → TPM_ALG_MLDSA).

---

### 13.5 TPM2_Encapsulate (Part 3 §14.10, CC = 0x000001A7) — V1.85

Performs the public-key operation in a Key Encapsulation Mechanism. The key referenced by `keyHandle` shall be a KEM key (`TPM_RC_KEY` if not), with `restricted` CLEAR and `decrypt` SET (`TPM_RC_ATTRIBUTES`). Returns a random `sharedSecret` and an accompanying `ciphertext` that can be decapsulated by the holder of the private key.

If the KEM scheme includes a Key Derivation Method (KDM) step, `sharedSecret` is suitable for direct use as a cryptographic key. Otherwise it is just a shared secret value.

`TPM2_Encapsulate()` was added in V1.85.

Tag: `TPM_ST_SESSIONS` if an audit or encrypt session is present; otherwise `TPM_ST_NO_SESSIONS`.

**Table 60: Request**

```text
tag (2)
size (4)
commandCode (4) = 0x000001A7
H1: keyHandle (4)           // public KEM key; Auth Index: None
```

No parameters in the input — only the handle.

**Table 61: Response — sharedSecret FIRST, ciphertext SECOND**

```text
tag (2)
size (4)
responseCode (4) = 0
[paramSize (4) — only when tag = TPM_ST_SESSIONS]
P1: sharedSecret  (TPM2B_SHARED_SECRET)   // {size(2), buffer[size]}
P2: ciphertext    (TPM2B_KEM_CIPHERTEXT)  // {size(2), TPMU_KEM_CIPHERTEXT}
[authArea — only when tag = TPM_ST_SESSIONS]
```

> ⚠ **Field order is part of the spec.** libtpms versions before commit `<phase-3.5+1>` had `Encapsulate_Out = { ciphertext, sharedSecret }` — that violated Table 61 and was caught by the wolfTPM v4.0.0 cross-check. Fixed by swapping struct field order, the `paramOffsets[]` reference, and the `types[]` marshal type list in `CommandDispatchData.h`.

---

### 13.6 TPM2_Decapsulate (Part 3 §14.11, CC = 0x000001A8) — V1.85

Performs the private-key operation in a Key Encapsulation Mechanism. The key referenced by `keyHandle` shall be a KEM key (`TPM_RC_KEY`) with `restricted` CLEAR and `decrypt` SET (`TPM_RC_ATTRIBUTES`). Returns the same `sharedSecret` produced during the matching encapsulation.

Uses the private key of `keyHandle`; **authorization is required** (Auth Role: USER).

`TPM2_Decapsulate()` was added in V1.85.

Tag: `TPM_ST_SESSIONS` (always — auth session is required).

**Table 62: Request**

```text
tag (2) = 0x8002
size (4)
commandCode (4) = 0x000001A8
H1: @keyHandle (4)              // loaded KEM key; Auth Index: 1, Auth Role: USER
authArea (4 + session)
P1: ciphertext (TPM2B_KEM_CIPHERTEXT)  // {size(2), TPMU_KEM_CIPHERTEXT}
```

**Table 63: Response**

```text
tag (2) = 0x8002
size (4)
responseCode (4) = 0
paramSize (4)
P1: sharedSecret (TPM2B_SHARED_SECRET)  // {size(2), buffer[size]}
authArea (session response)
```

---

## 14. TPMA_ALGORITHM (Part 2 §8.2 Table 35)

Definition of `TPMA_ALGORITHM` bits:
- **Bit 0 (asymmetric):** SET (1) if an asymmetric algorithm.
- **Bit 1 (symmetric):** SET (1) if a symmetric block cipher.
- **Bit 2 (hash):** SET (1) if a hash algorithm.
- **Bit 3 (object):** SET (1) if an algorithm that may be used as an object type.
- **Bit 8 (signing):** SET (1) if a signing algorithm.
- **Bit 9 (encrypting):** SET (1) if an encryption/decryption algorithm.
- **Bit 10 (method):** SET (1) if a method such as a key derivative function (KDF).

---

## 15. Attestation Commands and Structures (Part 3 & Part 2)

Full wire formats extracted from `docs/standards/TPM-2.0-Library-Part-{1,2,3}-V185-RC4.pdf`. Pulled here so any future
PQC attestation work (G8, G9, G10 and beyond) doesn't have to re-read the PDFs.

### 15.1 TPM2_Certify (Part 3 §18.2, p.153-154)

**Purpose.** Prove that an object with a specific Name is loaded in the TPM. By certifying that the object is loaded,
the TPM warrants that a public area with a given Name is self-consistent and associated with a valid sensitive area.
"If a relying party has a public area that has the same Name as a Name certified with this command, then the values
in that public area are correct." (§18.2.1)

**Authorization.** `objectHandle` requires **ADMIN role**. With a policy session, the session shall have
`policySession→commandCode == TPM_CC_Certify` — policy that grants *use* does not grant *certification*.

**Object eligibility.** "The object may be any object that is loaded with TPM2_Load() or TPM2_CreatePrimary(). An
object that only has its public area loaded cannot be certified." (§18.2.1)

**NULL signing.** "If signHandle is TPM_RH_NULL, the TPMS_ATTEST structure is returned and signature is a NULL
Signature." (§18.2.1) — useful for testing the marshal path without a sign step.

#### Table 97: TPM2_Certify Command (p.154)

| Type | Name | Description |
|---|---|---|
| `TPMI_ST_COMMAND_TAG` | tag | `TPM_ST_SESSIONS` |
| `UINT32` | commandSize | |
| `TPM_CC` | commandCode | `TPM_CC_Certify` |
| `TPMI_DH_OBJECT` | `@objectHandle` | handle of the object to be certified. Auth Index 1, Auth Role **ADMIN** |
| `TPMI_DH_OBJECT+` | `@signHandle` | handle of the key used to sign the attestation structure. Auth Index 2, Auth Role USER |
| `TPM2B_DATA` | qualifyingData | user-provided qualifying data |
| `TPMT_SIG_SCHEME+` | inScheme | signing scheme to use if the scheme for `signHandle` is `TPM_ALG_NULL` |

#### Table 98: TPM2_Certify Response (p.154)

| Type | Name | Description |
|---|---|---|
| `TPM_ST` | tag | see Clause 6 |
| `UINT32` | responseSize | |
| `TPM_RC` | responseCode | |
| `TPM2B_ATTEST` | certifyInfo | the structure that was signed |
| `TPMT_SIGNATURE` | signature | the signature over `certifyInfo` using the key referenced by `signHandle` |

### 15.2 TPM2_Quote (Part 3 §18.4, p.157-158)

**Purpose.** Quote PCR values. "The TPM will hash the list of PCR selected by PCRselect using the hash algorithm in
the selected signing scheme. If the selected signing scheme or the scheme hash algorithm is `TPM_ALG_NULL`, then
the TPM shall return `TPM_RC_SCHEME`." (§18.4.1)

**PCR digest computation.** "The digest is computed as the hash of the concatenation of all of the digest values of
the selected PCR. The concatenation of PCR is described in TPM 2.0 Part 1, Selecting Multiple PCR." (§18.4.1) — see
§15.5 below for the canonical recipe.

**NULL signing.** Same as Certify: "If signHandle is TPM_RH_NULL, the TPMS_ATTEST structure is returned and signature
is a NULL Signature." (§18.4.1) — note V1.83-and-earlier returned `TPM_RC_SCHEME` in this case; V1.85 relaxed that.

#### Table 101: TPM2_Quote Command (p.158)

| Type | Name | Description |
|---|---|---|
| `TPMI_ST_COMMAND_TAG` | tag | `TPM_ST_SESSIONS` |
| `UINT32` | commandSize | |
| `TPM_CC` | commandCode | `TPM_CC_Quote` |
| `TPMI_DH_OBJECT+` | `@signHandle` | handle of key that will perform signature. Auth Index 1, Auth Role USER |
| `TPM2B_DATA` | qualifyingData | data supplied by the caller |
| `TPMT_SIG_SCHEME+` | inScheme | signing scheme to use if the scheme for `signHandle` is `TPM_ALG_NULL` |
| `TPML_PCR_SELECTION` | PCRselect | PCR set to quote |

#### Table 102: TPM2_Quote Response (p.158)

| Type | Name | Description |
|---|---|---|
| `TPM_ST` | tag | see Clause 6 |
| `UINT32` | responseSize | |
| `TPM_RC` | responseCode | |
| `TPM2B_ATTEST` | quoted | the quoted information |
| `TPMT_SIGNATURE` | signature | the signature over `quoted` |

### 15.3 TPMS_ATTEST and the attested union (Part 2 §10.11, p.159-163)

The TPM-generated structure that every attestation command signs. The signature is over the marshalled `TPMS_ATTEST`
bytes — therefore the marshalled blob is fully deterministic given fixed inputs (key Name, qualifyingData, clockInfo,
firmwareVersion, attested-union payload).

#### Table 153: TPMS_ATTEST Structure (Part 2 §10.11.12, p.162-163)

| Parameter | Type | Description |
|---|---|---|
| magic | `TPM_CONSTANTS32` | "the indication that this structure was created by a TPM (always `TPM_GENERATED_VALUE` = `0xFF544347`)" |
| type | `TPMI_ST_ATTEST` | type of the attestation structure — selector for the attested union |
| qualifiedSigner | `TPM2B_NAME` | Qualified Name of the signing key |
| extraData | `TPM2B_DATA` | external information supplied by caller (typically `qualifyingData` echoed back) |
| clockInfo | `TPMS_CLOCK_INFO` | Clock, resetCount, restartCount, Safe |
| firmwareVersion | `UINT64` | TPM-vendor-specific firmware version |
| `[type]attested` | `TPMU_ATTEST` | the type-specific attestation information (union, selected by `type`) |

> **Note** (§10.11.12 narrative): "When the structure is signed by a key in the Storage hierarchy, the values of
> `clockInfo.resetCount`, `clockInfo.restartCount`, and `firmwareVersion` are obfuscated with a per-key obfuscation
> value." Implications for KAT reproducibility: pin the AK to a hierarchy whose values are NOT obfuscated (e.g.
> Endorsement) **or** model the obfuscation deterministically in the test fixture.

#### Table 151: TPMI_ST_ATTEST (selector values, Part 2 §10.11.10, p.162)

| Value | Generated by |
|---|---|
| `TPM_ST_ATTEST_CERTIFY` | `TPM2_Certify()` |
| `TPM_ST_ATTEST_QUOTE` | `TPM2_Quote()` |
| `TPM_ST_ATTEST_SESSION_AUDIT` | `TPM2_GetSessionAuditDigest()` |
| `TPM_ST_ATTEST_COMMAND_AUDIT` | `TPM2_GetCommandAuditDigest()` |
| `TPM_ST_ATTEST_TIME` | `TPM2_GetTime()` |
| `TPM_ST_ATTEST_CREATION` | `TPM2_CertifyCreation()` |
| `TPM_ST_ATTEST_NV` | `TPM2_NV_Certify()` |
| `TPM_ST_ATTEST_NV_DIGEST` | `TPM2_NV_Certify()` |

#### Table 152: TPMU_ATTEST union (Part 2 §10.11.11, p.162)

| Parameter | Type | Selector |
|---|---|---|
| certify | `TPMS_CERTIFY_INFO` | `TPM_ST_ATTEST_CERTIFY` |
| creation | `TPMS_CREATION_INFO` | `TPM_ST_ATTEST_CREATION` |
| quote | `TPMS_QUOTE_INFO` | `TPM_ST_ATTEST_QUOTE` |
| commandAudit | `TPMS_COMMAND_AUDIT_INFO` | `TPM_ST_ATTEST_COMMAND_AUDIT` |
| sessionAudit | `TPMS_SESSION_AUDIT_INFO` | `TPM_ST_ATTEST_SESSION_AUDIT` |
| time | `TPMS_TIME_ATTEST_INFO` | `TPM_ST_ATTEST_TIME` |
| nv | `TPMS_NV_CERTIFY_INFO` | `TPM_ST_ATTEST_NV` |
| nvDigest | `TPMS_NV_DIGEST_CERTIFY_INFO` | `TPM_ST_ATTEST_NV_DIGEST` |

#### Table 144: TPMS_CERTIFY_INFO (attested data for Certify, Part 2 §10.11.3, p.160)

| Parameter | Type | Description |
|---|---|---|
| name | `TPM2B_NAME` | Name of the certified object |
| qualifiedName | `TPM2B_NAME` | Qualified Name of the certified object |

#### Table 145: TPMS_QUOTE_INFO (attested data for Quote, Part 2 §10.11.4, p.160)

| Parameter | Type | Description |
|---|---|---|
| pcrSelect | `TPML_PCR_SELECTION` | information on algID, PCRs selected and digest |
| pcrDigest | `TPM2B_DIGEST` | digest of the selected PCRs using the hash of the signing key |

#### Table 154: TPM2B_ATTEST (Part 2 §10.11.13, p.163)

| Parameter | Type | Description |
|---|---|---|
| size | `UINT16` | size of attestationData |
| attestationData[size]{:sizeof(TPMS_ATTEST)} | `BYTE` | the signed structure |

#### Table 141: TPMS_CLOCK_INFO (Part 2 §10.10.1, p.158)

| Parameter | Type | Description |
|---|---|---|
| clock | `UINT64` | milliseconds since TPM powered (or last `TPM2_Clear()`); UTC convention common |
| resetCount | `UINT32` | TPM Resets since last `TPM2_Clear()` |
| restartCount | `UINT32` | `TPM2_Shutdown()` or `_TPM_Hash_Start` occurrences since last Reset/Clear |
| safe | `TPMI_YES_NO` | YES iff no Clock value > current was previously reported; set to YES on `TPM2_Clear()` |

### 15.4 Restricted signing keys + TPM_GENERATED_VALUE — why ML-DSA AKs work for Quote/Certify (Part 1 §22.1.2, p.189-191)

**The rule** (§22.1.2 verbatim):

> "A restricted signing key can only sign a digest that has been produced by the TPM. The digest can be over
> externally supplied data or an internally generated structure. An internally generated structure that is to be
> signed will have the characteristic `TPM_GENERATED_VALUE` as the first octets in the structure to be hashed and
> signed. When the TPM generates a digest over externally provided data, the TPM validates that the first octets of
> the data are not equal to the `TPM_GENERATED_VALUE`. When a digest is signed by a restricted signing key, there is
> no ambiguity about whether or not the signed data was generated by the TPM."
>
> "A restricted signing key is occasionally referred to in this specification as an Attesting or Attestation Key."

**Table 33 (p.190) row `sign=1, decrypt=0, restricted=1`:** "This combination indicates a key that can sign any digest
that the TPM has created. The TPM only signs a digest over externally provided data that did not have as its first
octets `TPM_GENERATED_VALUE`. This key can be used reliably for quoting, certifying, and signing. No signing command
is prohibited for this type of key. Only the default schemes and modes of the object can be used."

**Implication for ML-DSA AKs.** `TPMS_ATTEST.magic = TPM_GENERATED_VALUE` (0xFF544347) is the **first 4 octets** of
every attestation blob. Therefore:

- A **restricted** ML-DSA key (e.g. the AKs at `0x810100A0/A1/A2` provisioned by `swtpm_setup`) is *valid* for
  `TPM2_Quote` / `TPM2_Certify` — and indeed is the *intended* type for these operations.
- The restricted-AK gate in `PqcMlDsaCommands.c:54-59` correctly rejects `TPM2_SignDigest` (which can sign arbitrary
  externally-supplied data) but **must not** block `Attest_spt.c:SignAttestInfo()`. The latter signs a TPM-generated
  `TPMS_ATTEST` blob whose first octets are `TPM_GENERATED_VALUE` — exactly the spec-mandated condition.

### 15.5 PCR digest computation for TPM2_Quote (Part 1 §14.5 + §14.6.2, p.93-94)

> "When a command allows multiple PCR to be selected, a list of selectors is used. Each entry in the list consists of
> an algorithm ID followed by a bit array. Each bit in the bit array corresponds to one PCR. If a bit is SET, then the
> indicated PCR in the bank corresponding to the algorithm ID is selected."
>
> "The bit correspondence to PCR is that the bit corresponding to PCR[n] is the (n mod 8) bit in the ⌊n/8⌋ octet of the
> array."
>
> "The list of selectors is processed in order. The selected PCR are concatenated, with the lowest numbered PCR in the
> first selector being the first in the list and the highest numbered PCR in the last selector being the last."
>
> "TPM2_Quote() and TPM2_PolicyPCR() digest the concatenation of PCR."

**Canonical recipe for `TPMS_QUOTE_INFO.pcrDigest`:**

1. Filter `pcrSelect` to remove unimplemented PCR indexes (§14.5: *"No value is included in the concatenation of PCR
   for an unimplemented PCR. It is an error if the algorithm ID selects a hash algorithm that is not implemented."*)
2. Concatenate, in selector-order then ascending-PCR-order, the **current PCR values** (per bank, using each bank's
   native hash output).
3. Hash the concatenation using the **hash algorithm of the signing scheme** (NOT the bank's hash — for ML-DSA the
   scheme hash is governed by the AK's parameter set).

This is the value placed in `TPMS_QUOTE_INFO.pcrDigest`. The whole `TPMS_ATTEST` is then signed by the AK.

### 15.6 PQC attestation specifics (V1.85)

V1.85 does not add any PQC-specific fields to `TPMS_ATTEST`, `TPMS_QUOTE_INFO`, or `TPMS_CERTIFY_INFO`. The
attestation structures are **signature-algorithm-agnostic**. PQC support enters through:

- `TPMT_SIGNATURE.sigAlg` = `TPM_ALG_MLDSA` (0xA1) or `TPM_ALG_HASH_MLDSA` (0xA2) — see §5.3.
- `TPMU_SIGNATURE.mldsa` = `TPM2B_SIGNATURE_MLDSA` carrier — see §5.3 Table 217.
- The signing scheme hash on the AK template (`TPMS_MLDSA_PARMS`, §5.6) — drives the PCR digest hash used in
  `TPMS_QUOTE_INFO.pcrDigest`.

The dispatcher in `libtpms/src/tpm2/Attest_spt.c:172 SignAttestInfo()` already routes `TPM_ALG_MLDSA` through
`CryptMlDsaSignMessage()` — no new attestation-side code is required to support an ML-DSA AK; the work is testing
infrastructure (KATs, dual-verifier xcheck) and additional AK templates for ML-DSA-44 / ML-DSA-87.

---

---

## 16. TPM2_VerifySequenceComplete (Part 3 §20.3)

Validates a signature on a message incorporated into a sequence.
- **Differences from `TPM2_VerifySignature`:**
  - Verifies with context (requires supporting scheme like `TPM_ALG_MLDSA`).
  - Verifies a message instead of a digest.
  - The ticket's tag is `TPM_ST_MESSAGE_VERIFIED`.
- **Ticket generation:** If successful, returns a `TPMT_TK_VERIFIED`. If the key is in the NULL hierarchy, then `hmac` in the ticket will be the Empty Buffer. For other hierarchies, the `hmac` must be computed over the hierarchy proof.
