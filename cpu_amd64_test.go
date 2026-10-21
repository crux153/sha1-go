// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package sha1

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestApplyGODEBUG(t *testing.T) {
	var x86 cpuFeatures
	type flags = struct{ ssse3, sse41, avx, avx2, bmi1, bmi2, sha bool }
	get := func() flags {
		return flags{x86.hasSSSE3, x86.hasSSE41, x86.hasAVX, x86.hasAVX2, x86.hasBMI1, x86.hasBMI2, x86.hasSHA}
	}
	all := flags{true, true, true, true, true, true, true}
	set := func(f flags) {
		x86.hasSSSE3, x86.hasSSE41, x86.hasAVX, x86.hasAVX2, x86.hasBMI1, x86.hasBMI2, x86.hasSHA =
			f.ssse3, f.sse41, f.avx, f.avx2, f.bmi1, f.bmi2, f.sha
	}

	tests := []struct {
		env   string
		level int32
		start flags
		want  flags
	}{
		{"", 1, all, all},
		{"cpu.avx2=off,cpu.sha=off", 1, all, flags{true, true, true, false, true, true, false}},
		{"gctrace=1,cpu.avx=off", 1, all, flags{true, true, false, true, true, true, true}},
		{"cpu.all=off", 1, all, flags{}},
		{"cpu.all=off,cpu.ssse3=on", 1, all, flags{ssse3: true}},
		{"cpu.ssse3=on", 1, flags{}, flags{}},
		{"cpu.avx2=off,cpu.avx2=on", 1, all, all},
		{"cpu.sha=bogus,cpu.unknown=off,cpu.avx", 1, all, all},
		{"cpu.all=off", 2, all, flags{true, true, false, false, false, false, false}},
		{"cpu.all=off", 3, all, flags{true, true, true, true, true, true, false}},
		{"cpu.avx2=off,cpu.sha=off", 3, all, flags{true, true, true, true, true, true, false}},
	}
	for _, tt := range tests {
		set(tt.start)
		applyGODEBUG(&x86, tt.env, tt.level)
		if got := get(); got != tt.want {
			t.Errorf("applyGODEBUG(%q, v%d) = %+v, want %+v", tt.env, tt.level, got, tt.want)
		}
	}
}

// TestPrintDefaultImpl is a helper for TestGODEBUGSelection.
func TestPrintDefaultImpl(t *testing.T) {
	if os.Getenv("SHA1GO_PRINT_IMPL") != "1" {
		t.Skip("helper for TestGODEBUGSelection")
	}
	fmt.Printf("impl=%v\n", impl)
}

// TestGODEBUGSelection checks the code path chosen in a fresh process when
// GODEBUG hides CPU features.
func TestGODEBUGSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("starts subprocesses")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	run := func(godebug string) implementation {
		t.Helper()
		cmd := exec.Command(exe, "-test.run=^TestPrintDefaultImpl$", "-test.v")
		cmd.Env = append(os.Environ(), "SHA1GO_PRINT_IMPL=1", "GODEBUG="+godebug)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("GODEBUG=%s: %v\n%s", godebug, err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if name, ok := strings.CutPrefix(line, "impl="); ok {
				for i := implStdlib; i <= implSSSE3; i++ {
					if i.String() == name {
						return i
					}
				}
			}
		}
		t.Fatalf("GODEBUG=%s: no impl in output\n%s", godebug, out)
		return 0
	}

	level := goamd64Level()
	for _, godebug := range []string{
		"",
		"cpu.avx2=off,cpu.sha=off",
		"cpu.avx=off",
		"cpu.avx2=off,cpu.sha=off,cpu.ssse3=off",
		"cpu.all=off",
	} {
		want := chooseImpl(detectCPU(godebug, level))
		if got := run(godebug); got != want {
			t.Errorf("GODEBUG=%s: got %v, want %v", godebug, got, want)
		}
	}

	// Hiding AVX2 and SHA-NI must stop the delegation to crypto/sha1
	// unless the GOAMD64 level makes AVX2 mandatory.
	if level < 3 {
		if got := run("cpu.avx2=off,cpu.sha=off"); got == implStdlib {
			t.Errorf("cpu.avx2=off,cpu.sha=off: got %v", got)
		}
	}
	if level < 2 {
		if got := run("cpu.avx2=off,cpu.sha=off,cpu.ssse3=off"); got != implScalar {
			t.Errorf("cpu.avx2=off,cpu.sha=off,cpu.ssse3=off: got %v, want scalar", got)
		}
	}
}

func TestChooseImpl(t *testing.T) {
	all := cpuFeatures{true, true, true, true, true, true, true}
	tests := []struct {
		name string
		edit func(*cpuFeatures)
		want implementation
	}{
		{"all", func(*cpuFeatures) {}, implStdlib},
		{"no SHA", func(f *cpuFeatures) { f.hasSHA = false }, implStdlib},
		{"no AVX2", func(f *cpuFeatures) { f.hasAVX2 = false }, implStdlib},
		{"no AVX2, no SHA", func(f *cpuFeatures) { f.hasAVX2, f.hasSHA = false, false }, implSSSE3},
		{"no AVX2, no SSE4.1", func(f *cpuFeatures) { f.hasAVX2, f.hasSSE41 = false, false }, implSSSE3},
		{"no BMI2, no SHA", func(f *cpuFeatures) { f.hasBMI2, f.hasSHA = false, false }, implSSSE3},
		// crypto/sha1 needs AVX for its SHA-NI path too.
		{"SHA without AVX", func(f *cpuFeatures) { f.hasAVX, f.hasAVX2 = false, false }, implSSSE3},
		{"no AVX2, no SHA, no SSSE3", func(f *cpuFeatures) { f.hasAVX2, f.hasSHA, f.hasSSSE3 = false, false, false }, implScalar},
		{"nothing", func(f *cpuFeatures) { *f = cpuFeatures{} }, implScalar},
	}
	for _, tt := range tests {
		f := all
		tt.edit(&f)
		if got := chooseImpl(f); got != tt.want {
			t.Errorf("%s: chooseImpl(%+v) = %v, want %v", tt.name, f, got, tt.want)
		}
	}
}
