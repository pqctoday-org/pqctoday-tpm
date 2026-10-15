#!/usr/bin/env bash

# For the license, see the LICENSE file in the root directory.
# Modified by PQC Today, LLC, 2026: ML-KEM / ML-DSA (TPM 2.0 Library V1.85) support. See NOTICE.

ROOT=${abs_top_builddir:-$(pwd)/..}
TESTDIR=${abs_top_testdir:-$(dirname "$0")}
DIR=${PWD}

WORKDIR=$(mktemp -d)

. "${TESTDIR}/common"

function cleanup()
{
	rm -rf "${WORKDIR}"
}

trap "cleanup" QUIT EXIT

pushd "$WORKDIR" &>/dev/null || exit 1

"${DIR}/${1}"
rc=$?

if ! fs=$(get_filesize NVChip); then
	exit 1
fi
# Size of the NVChip file a clean build writes (Linux, amd64 and arm64,
# OpenSSL 3.6.2). The PQC commands 0x1A3-0x1AA grow the in-memory command
# bitmaps, but not this serialised file: a clean build still writes 176832.
exp=176832
if [ "$fs" -ne "$exp" ]; then
	echo "Error: Unexpected size of NVChip file."
	echo "Expected: $exp"
	echo "Got     : $fs"
	rc=1
fi

popd &>/dev/null || exit 1

exit $rc
