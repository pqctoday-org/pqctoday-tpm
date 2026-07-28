/********************************************************************************/
/*										*/
/*			     	Vendor Info					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2023-2024				*/
/*										*/
/********************************************************************************/

#ifndef _VENDORINFO_H
#define _VENDORINFO_H

// Define the TPM specification-specific capability values.
// Per TCG TPM 2.0 Library v185 Errata v1 (2026-03-12) section 2.1, the
// TPM_SPEC_DAY_OF_YEAR slot is retired in favor of TPM_SPEC_ERRATA (the
// TPM_PT_DAY_OF_YEAR capability property is unchanged; only the backing
// constant's name and meaning change), and TPM_SPEC_YEAR shall be zero.
#define TPM_SPEC_FAMILY      (0x322E3000)
#define TPM_SPEC_LEVEL_NUM   0		// libtpms added: TPM_SPEC_LEVEL without leading zeros and '()'
#define TPM_SPEC_LEVEL       (00)
#define TPM_SPEC_VERSION     185	// libtpms changed: removed '()'; V185 published 2026-03-12
#define TPM_SPEC_YEAR        (0)	// shall be zero per Errata v1 section 2.1
#define TPM_SPEC_ERRATA      (1)	// errata level implemented; was TPM_SPEC_DAY_OF_YEAR
#define MAX_VENDOR_PROPERTY  (1)

// Define the platform specification-specific capability values.
#define PLATFORM_FAMILY      (1)		/* kgold changed for PC Client */
#define PLATFORM_LEVEL       TPM_SPEC_LEVEL_NUM		// libtpms: changed
#define PLATFORM_VERSION     (0x00000107)	// TCG PC Client Platform TPM Profile v1.07 (2026-03-23)
#define PLATFORM_YEAR        TPM_SPEC_YEAR		// libtpms: changed
#define PLATFORM_DAY_OF_YEAR TPM_SPEC_ERRATA	// libtpms: changed

#endif

