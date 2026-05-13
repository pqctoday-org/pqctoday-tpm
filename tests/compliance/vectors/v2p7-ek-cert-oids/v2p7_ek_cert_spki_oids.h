/*
 * v2p7_ek_cert_spki_oids.h
 *
 * NIST CSOR OIDs for the PQC EK certificate Subject Public Key Info,
 * encoded as DER OBJECT IDENTIFIERs ready to byte-match against an X.509
 * cert's parsed SPKI.algorithm.algorithm field.
 *
 * Source (cached locally in docs/standards/):
 *   docs/standards/TCG-EK-Credential-Profile-...-V2p7-RC1.pdf §6.2.3 (ML-KEM SPKI)
 *   docs/standards/TCG-EK-Credential-Profile-...-V2p7-RC1.pdf §6.2.4 (ML-DSA SPKI)
 *   Mirrored into docs/TPMdocextract.md §17.6.
 *
 * OID assignment (all under joint-iso-itu-t(2) country(16) us(840)
 * organization(1) gov(101) csor(3) nistAlgorithm(4)):
 *
 *   id-alg-ml-kem-512    = 2.16.840.1.101.3.4.4.1
 *   id-alg-ml-kem-768    = 2.16.840.1.101.3.4.4.2
 *   id-alg-ml-kem-1024   = 2.16.840.1.101.3.4.4.3
 *   id-ml-dsa-44         = 2.16.840.1.101.3.4.3.17
 *   id-ml-dsa-65         = 2.16.840.1.101.3.4.3.18
 *   id-ml-dsa-87         = 2.16.840.1.101.3.4.3.19
 *
 * DER OID body encoding (X.690 §8.19 — base-128, MSB chained):
 *   2.16 → first octet = 40*2 + 16 = 96 = 0x60
 *   840  → 0x86 0x48
 *   1    → 0x01
 *   101  → 0x65
 *   3    → 0x03
 *   4    → 0x04
 *   3 (ml-dsa class) or 4 (ml-kem class)
 *   variant — 1..3 for ML-KEM, 17..19 for ML-DSA
 *
 * Wrapped with the OBJECT IDENTIFIER tag/length:
 *   0x06 (tag) 0x09 (length = 9 body bytes) followed by the 9-byte body.
 *
 * Total per OID = 11 bytes including tag/length, or 9 bytes body-only.
 * The conformance client matches the 9-byte body against the parsed
 * X.509 SPKI algorithm OID (after OpenSSL strips the tag/length).
 */

#ifndef PQCTODAY_TPM_V2P7_EK_CERT_SPKI_OIDS_H
#define PQCTODAY_TPM_V2P7_EK_CERT_SPKI_OIDS_H

#include <stddef.h>

#define V2P7_OID_BODY_LEN 9u

/* 2.16.840.1.101.3.4.4.1 — id-alg-ml-kem-512 */
static const unsigned char v2p7_oid_mlkem512[V2P7_OID_BODY_LEN] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01,
};

/* 2.16.840.1.101.3.4.4.2 — id-alg-ml-kem-768 */
static const unsigned char v2p7_oid_mlkem768[V2P7_OID_BODY_LEN] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
};

/* 2.16.840.1.101.3.4.4.3 — id-alg-ml-kem-1024 */
static const unsigned char v2p7_oid_mlkem1024[V2P7_OID_BODY_LEN] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03,
};

/* 2.16.840.1.101.3.4.3.17 — id-ml-dsa-44 (variant = 17 = 0x11) */
static const unsigned char v2p7_oid_mldsa44[V2P7_OID_BODY_LEN] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
};

/* 2.16.840.1.101.3.4.3.18 — id-ml-dsa-65 (variant = 18 = 0x12) */
static const unsigned char v2p7_oid_mldsa65[V2P7_OID_BODY_LEN] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
};

/* 2.16.840.1.101.3.4.3.19 — id-ml-dsa-87 (variant = 19 = 0x13) */
static const unsigned char v2p7_oid_mldsa87[V2P7_OID_BODY_LEN] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
};

#endif /* PQCTODAY_TPM_V2P7_EK_CERT_SPKI_OIDS_H */
