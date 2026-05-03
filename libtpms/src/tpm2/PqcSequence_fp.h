/********************************************************************************/
/*                                                                              */
/*  PqcSequence_fp.h — V1.85 RC4 Phase 4 sign/verify sequence support           */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                         */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Provides the parallel slot pool and lifecycle for ML-DSA sign and verify    */
/*  sequence objects (V1.85 §17.5, §17.6, §20.3, §20.6). Sequence handles are   */
/*  minted in a vendor sub-range so they don't collide with existing transient  */
/*  object handles or hash sequences; TPM2_SequenceUpdate dispatches by handle. */
/*                                                                              */
/*  Sequence-object state lives entirely in this module and is NOT context-     */
/*  saveable in V0 (transient-only). Phase-4-follow-up will add ContextSave     */
/*  support once the upstream HASH_OBJECT contract can be extended without      */
/*  breaking NV-state compatibility.                                            */
/*                                                                              */
/********************************************************************************/

#ifndef _PQC_SEQUENCE_FP_H_
#define _PQC_SEQUENCE_FP_H_

#if (ALG_MLDSA || ALG_HASH_MLDSA) && (CC_SignSequenceStart || CC_SignSequenceComplete \
                                       || CC_VerifySequenceStart || CC_VerifySequenceComplete)

#include "Tpm.h"

/* Vendor-defined transient handle range used for ML-DSA sequence handles.
 * The TCG spec reserves 0x80000000–0x80FFFFFF for transient objects; we use
 * 0x80FF00xx so dispatch is unambiguous (existing transient objects mint
 * handles starting from 0x80000000 and grow upward, which won't collide). */
#define PQC_SEQ_HANDLE_BASE   ((TPM_HANDLE)0x80FF0000)
#define PQC_SEQ_HANDLE_MAX    ((TPM_HANDLE)0x80FF00FF)

/* PQC_SEQ_STATE is defined in Global.h so it can be embedded in HASH_OBJECT */

/* Module lifecycle */
LIB_EXPORT void   PqcSequenceStartup(void);

/* Slot allocation / lookup */
LIB_EXPORT TPM_HANDLE PqcSequenceAllocate(BOOL isSign, TPM2B_AUTH *auth);
LIB_EXPORT PQC_SEQ_STATE *PqcSequenceFromHandle(TPM_HANDLE handle);
LIB_EXPORT BOOL           PqcSequenceIsHandle(TPM_HANDLE handle);
LIB_EXPORT void           PqcSequenceFlush(TPM_HANDLE handle);

/* Append data to a sequence buffer (TPM2_SequenceUpdate path).
 * For sign sequences, returns TPM_RC_ONE_SHOT_SIGNATURE per V1.85 §17.5
 * narrative (FIPS 204 ML-DSA-Sign is one-shot — entire message must arrive
 * in SignSequenceComplete.buffer, not via prior SequenceUpdate calls). */
LIB_EXPORT TPM_RC PqcSequenceUpdate(PQC_SEQ_STATE *seq,
                                    const BYTE *data, UINT16 dataLen);

#endif  /* sequence commands enabled */
#endif  /* _PQC_SEQUENCE_FP_H_ */
