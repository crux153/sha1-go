# difffuzz

Differential fuzzing of `github.com/crux153/sha1-go` against
BoringSSL's SHA-1, an independent C and assembly implementation.
`crypto/sha1` only breaks ties: when a check fails, it is run again
against `crypto/sha1`, and the failure message says whether
`crypto/sha1` agrees with BoringSSL. `TestReferencesAgree` checks that
the two references match. It is a separate module, so the root module
does not change, and it uses only the public API.

BoringSSL is linked with cgo under `-tags difffuzz_boringssl` from a
static `libcrypto.a` that `boringssl.sh` builds into `.cache/` inside
the `golang:1.26` image (no cmake needed). Without the tag,
`crypto/sha1` is the reference.

The package under test chooses its code path at init time, so each run
selects one with `GODEBUG`: `cpu.avx2=off,cpu.sha=off` for the SSSE3
assembly, plus `cpu.ssse3=off` for the scalar assembly.
`DIFFFUZZ_REQUIRE_OWN=1` makes every target fail if the package
delegates to `crypto/sha1` instead.

- `FuzzSum`: `Sum` and a single `Write` on inputs up to 4 MiB at every
  alignment, optionally placed directly before or after an
  inaccessible page.
- `FuzzOps`: random sequences of `Write`, `Sum`, `Clone`, `Reset`,
  state round trips through `crypto/sha1`, and corrupt states, with
  the marshalled state compared after every operation.
- `FuzzState`: continues from arbitrary marshalled states (chaining
  values, buffer, and lengths near 2^29, 2^61 and 2^64 bytes), which
  compares the block functions directly on arbitrary chaining values.
- `TestHunt` (`HUNT=<duration>`): runs without the fuzzing engine.
  It sweeps every length up to 256 KiB at alignments 0–15 and every
  two-write split up to 2 KiB, then checks random inputs up to 8 MiB.

`run.sh <end-epoch>` runs all eight jobs (each target on both paths)
in Docker until the given time. `status.sh` prints a summary. Failures
are written to `failures/`, and Go fuzz crashers to `testdata/fuzz/`.

The fuzz binary is built with `go test -c -fuzz=.`. Without `-fuzz`,
it has no coverage instrumentation, and the engine keeps no inputs.
Each fuzz worker process runs with `GOMAXPROCS=1`. With the default
`GOMAXPROCS`, every worker starts GC workers on every CPU, which cut
throughput by about 20%. When the corpora are replayed, nearly all
time goes to the two block functions, and GC takes under 1%.

## Results

### 2026-10-22, 3.5 hours

Run against commit b1323f4, with no failures. The corpus is shared
by both code paths.

| Target      | SSSE3 executions | Scalar executions | Corpus |
|-------------|-----------------:|------------------:|-------:|
| `FuzzSum`   |           3.55e9 |            1.43e9 |      4 |
| `FuzzOps`   |           1.98e9 |            0.81e9 |    170 |
| `FuzzState` |           2.77e9 |            1.48e9 |     99 |

`TestHunt` completed both sweeps on both paths. It then checked random
inputs, for a total of 93.8M inputs (77 TB) on the SSSE3 path and
40.8M inputs (31 TB) on the scalar path, with no failures.
