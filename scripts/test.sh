#!/bin/sh
# Copyright 2026 Crux. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# test.sh runs the test suite in the configurations that matter for this
# package: as is; with AVX, AVX2 and SHA-NI hidden through GODEBUG, so that
# the CPU looks like the target class (SSSE3 without AVX2 or SHA-NI); with
# SSSE3 hidden as well (scalar fallback); with the race detector; with the
# purego tag; and for other architectures.
#
# Every run also forces each code path the CPU supports, so the SSSE3 and
# scalar paths are tested even on CPUs where crypto/sha1 is used by default.
#
# GODEBUG is only passed to the test binaries, not to the go command, which
# would complain about cpu options it does not know.
#
# Usage: scripts/test.sh
#
# Set FUZZTIME (for example FUZZTIME=5m) to also run each fuzz target for
# that long with AVX2 and SHA-NI hidden.

set -eu
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

run() {
	echo
	echo "+ $*"
	"$@"
}

# runbin GODEBUG BINARY [FLAGS]: runs a compiled test binary.
runbin() {
	godebug=$1
	bin=$2
	shift 2
	echo
	echo "+ GODEBUG=$godebug $(basename "$bin") $*"
	GODEBUG=$godebug "$bin" -test.count=1 "$@"
	GODEBUG=$godebug "$bin" -test.run='^TestImplString$' -test.v |
		sed -n 's/.*default implementation: \([a-z0-9]*\).*/  default code path: \1/p'
}

run go vet ./...
run go vet -tags purego ./...
for arch in 386 arm64 riscv64; do
	run env GOARCH=$arch go vet ./...
done

run go test -c -o "$tmp/sha1.test" .
run go test -c -race -o "$tmp/sha1.race.test" .
run go test -c -tags purego -o "$tmp/sha1.purego.test" .

runbin "" "$tmp/sha1.test"
if [ "$(go env GOARCH)" = amd64 ]; then
	for godebug in \
		cpu.avx2=off,cpu.sha=off \
		cpu.avx=off,cpu.avx2=off,cpu.sha=off \
		cpu.avx=off,cpu.avx2=off,cpu.sha=off,cpu.ssse3=off; do
		runbin "$godebug" "$tmp/sha1.test"
	done
fi
runbin "" "$tmp/sha1.race.test" -test.short
runbin cpu.avx2=off,cpu.sha=off "$tmp/sha1.race.test" -test.short
runbin "" "$tmp/sha1.purego.test"

# 386 binaries usually run on amd64 Linux; skip them if they cannot.
if [ "$(go env GOARCH)" = amd64 ] && GOARCH=386 go test -c -o "$tmp/sha1.386.test" . &&
	"$tmp/sha1.386.test" -test.run='^TestNISTVectors$' >/dev/null 2>&1; then
	runbin "" "$tmp/sha1.386.test" -test.short
fi

if [ -n "${FUZZTIME:-}" ]; then
	for target in FuzzSum FuzzWrite; do
		echo
		echo "+ GODEBUG=cpu.avx2=off,cpu.sha=off fuzz $target for $FUZZTIME"
		# Failing inputs are written to testdata/fuzz.
		GODEBUG=cpu.avx2=off,cpu.sha=off "$tmp/sha1.test" \
			-test.run='^$' -test.fuzz="^$target\$" -test.fuzztime="$FUZZTIME" \
			-test.fuzzcachedir="$tmp/fuzzcache"
	done
fi

echo
echo "all tests passed"
