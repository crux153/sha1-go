// Package difffuzz differentially fuzzes github.com/crux153/sha1-go
// against BoringSSL's SHA-1 (C and assembly; built by boringssl.sh and
// linked with -tags difffuzz_boringssl) through the public API only.
//
// crypto/sha1 is not compared on every execution: it is the reference
// only when BoringSSL is not linked in, and otherwise tells, on a
// failure, whether BoringSSL or the package under test is wrong.
// TestReferencesAgree checks that the two agree.
//
// The package under test picks its code path once at init time from the
// CPU features, so the path is chosen with GODEBUG: with
// cpu.avx2=off,cpu.sha=off the SSSE3 assembly runs, and with cpu.ssse3=off
// as well the scalar assembly. Set DIFFFUZZ_REQUIRE_OWN=1 to fail instead
// of silently testing crypto/sha1 when the package under test delegates
// to it.
//
// It lives in its own module so the package itself is not modified.
package difffuzz
