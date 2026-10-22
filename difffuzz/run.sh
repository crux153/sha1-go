#!/usr/bin/env bash
# Launch the differential fuzzing containers.
# Usage: ./run.sh <end-epoch> [name ...]
# With names, only those containers are started. Each fuzz worker
# process runs with GOMAXPROCS=$WORKER_PROCS (default 1) and every
# process with GOGC=$GOGC (default 400).
set -euo pipefail
cd "$(dirname "$0")"
END=${1:?end epoch}
shift

# name, target (or "hunt"), code path, worker processes or goroutines.
JOBS="
sum-ssse3    FuzzSum   ssse3  22
ops-ssse3    FuzzOps   ssse3  26
state-ssse3  FuzzState ssse3  18
hunt-ssse3   hunt      ssse3  16
sum-scalar   FuzzSum   scalar 8
ops-scalar   FuzzOps   scalar 12
state-scalar FuzzState scalar 10
hunt-scalar  hunt      scalar 8
"
NAMES=${*:-$(echo "$JOBS" | awk 'NF { print $1 }')}
want() { case " $(echo $NAMES) " in *" $1 "*) return 0 ;; esac; return 1; }
DUR=$(( END - $(date +%s) ))
[ "$DUR" -gt 60 ] || { echo "end time too close"; exit 1; }
mkdir -p logs failures .cache

IMG=golang:1.26
TAGS=difffuzz_boringssl
BIN=.cache/difffuzz.test
# GODEBUG settings that make the package under test pick each path. They
# also make crypto/sha1, used for triage, run its pure Go code.
SSSE3=cpu.avx2=off,cpu.sha=off
SCALAR=$SSSE3,cpu.ssse3=off
godebug() { [ "$1" = ssse3 ] && echo "$SSSE3" || echo "$SCALAR"; }
common=(--user "$(id -u):$(id -g)" --cpu-shares 256
  -v "$(cd .. && pwd)":/src -w /src/difffuzz
  -e HOME=/tmp -e GOCACHE=/src/difffuzz/.cache/go-build
  -e GOMODCACHE=/src/difffuzz/.cache/mod -e GOFLAGS=-modcacherw
  -e GOTOOLCHAIN=local -e GOGC="${GOGC:-400}"
  -e DIFFFUZZ_FAILDIR=/src/difffuzz/failures -e DIFFFUZZ_REQUIRE_OWN=1)

# Build BoringSSL and the test binaries. -fuzz makes the go command
# build with coverage instrumentation, which the fuzzing engine needs to
# keep interesting inputs. The GODEBUG settings go only to the test
# binaries, not to the go command. Check that each setting selects the
# intended path and that the references agree.
docker run --rm "${common[@]}" "$IMG" sh -c "
  set -e
  ./boringssl.sh
  go vet -tags $TAGS .
  go test -c -fuzz=. -tags $TAGS -o $BIN .
  (cd .. && go test -c -o difffuzz/.cache/sha1.test .)
  for p in ssse3:$SSSE3 scalar:$SCALAR; do
    path=\${p%%:*} g=\${p#*:}
    got=\$(GODEBUG=\$g .cache/sha1.test -test.run '^TestImplString\$' -test.v |
      sed -n 's/.*default implementation: \([a-z0-9]*\).*/\1/p')
    [ \"\$got\" = \"\$path\" ] || { echo \"GODEBUG=\$g selects \$got, want \$path\"; exit 1; }
    echo \"GODEBUG=\$g selects \$got\"
    GODEBUG=\$g $BIN -test.count=1 -test.run '^(TestPath|TestReferencesAgree)\$' -test.v |
      grep -E 'reference:|^(--- |ok|PASS|FAIL)'
  done"

echo "$JOBS" | while read -r name target path n; do
  [ -n "$name" ] && want "$name" || continue
  docker rm -f "sha1fuzz-$name" >/dev/null 2>&1 || true
  if [ "$target" = hunt ]; then
    docker run -d --name "sha1fuzz-$name" "${common[@]}" -e GODEBUG="$(godebug "$path")" \
      -e GOMAXPROCS="$n" -e HUNT="${DUR}s" -e HUNT_WORKERS="$n" -e HUNT_LOG="logs/$name.progress" "$IMG" \
      sh -c "exec $BIN -test.count=1 -test.run '^TestHunt\$' -test.timeout 0 -test.v > logs/$name.log 2>&1" >/dev/null
  else
    docker run -d --name "sha1fuzz-$name" "${common[@]}" -e GODEBUG="$(godebug "$path")" \
      -e GOMAXPROCS="${WORKER_PROCS:-1}" "$IMG" \
      sh -c "exec $BIN -test.run '^\$' -test.fuzz '^$target\$' -test.fuzztime ${DUR}s -test.parallel $n \
        -test.timeout 0 -test.fuzzcachedir .cache/fuzz > logs/$name.log 2>&1" >/dev/null
  fi
  echo "started sha1fuzz-$name ($target, $path, $n)"
done
echo "running for ${DUR}s (until $(date -d @"$END"))"
