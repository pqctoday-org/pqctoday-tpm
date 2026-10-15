#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 PQC Today, LLC
#
# Downloads the published TCG specifications this project is checked against
# into docs/standards/ and verifies each against the SHA-256 recorded when it
# was last used. TCG licenses the specification text for the purpose of
# developing products, so the PDFs are kept out of git; this script restores
# the local copies. The NIST FIPS 203/204 PDFs are US government works and
# stay in git.
#
# Usage: docs/standards/fetch-tcg-specs.sh
set -u
cd "$(dirname "$0")"

BASE="https://trustedcomputinggroup.org/wp-content/uploads"
# sha256  file  resource page (for a manual download if the direct link fails)
SPECS="
d8b43afb50e5c17e307c7fd1b69cb16d2e2cfa6adb4df574bbb652db3c30e9f1 Trusted-Platform-Module-2.0-Library-Part-0-Introduction_Version-185_pub.pdf https://trustedcomputinggroup.org/resource/tpm-library-specification/
c2604f79a833b7bfa557c0ab2f880458e6af0993826ed48f22c41c34a6c0daad Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf https://trustedcomputinggroup.org/resource/tpm-library-specification/
67a6786816d6ef36952e910750652c0fb4668926369be81954dcf0f63c012b77 Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf https://trustedcomputinggroup.org/resource/tpm-library-specification/
e7f6e1ec3d801f42e2da9d1a416922cab5695a21940bd80b5f7090a6cddf7551 Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf https://trustedcomputinggroup.org/resource/tpm-library-specification/
3ca362bc3a99c31f8e13a3773f643d78e9f4aec811582dfef4b2a0a8fc7529f4 Eratta-Trusted-Platform-Module-2.0-Library_Version-185_pub.pdf https://trustedcomputinggroup.org/resource/tpm-library-specification/
b021106be50d5f391064ef702ca5f98249b614a90f2672931f45b79b2f441c2f TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.7_Pub.pdf https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/
e6a031c5811b28bf7993d4b93de845f12da5f3e61c86131187b09ae186836cb5 PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-v1p07_Pub.pdf https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/
"

fail=0
while read -r sum file page; do
  [ -z "${sum:-}" ] && continue
  if [ ! -f "$file" ]; then
    curl -sfL -A "Mozilla/5.0 (pqctoday-tpm spec fetch)" -o "$file.part" "$BASE/$file" \
      && mv "$file.part" "$file" || rm -f "$file.part"
  fi
  if [ ! -f "$file" ]; then
    echo "MISSING  $file  (download it from $page)"; fail=1; continue
  fi
  got=$(shasum -a 256 "$file" | cut -d' ' -f1)
  if [ "$got" = "$sum" ]; then
    echo "ok       $file"
  else
    echo "CHANGED  $file  (sha256 $got; TCG may have reissued it, re-check before citing)"; fail=1
  fi
done <<< "$SPECS"
exit $fail
