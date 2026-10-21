// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package sha1

import "os"

// x86 holds the CPU features relevant to choosing a code path.
//
// The detection and the GODEBUG handling mirror Go's internal/cpu, which
// decides what crypto/sha1 uses. That keeps the delegation decision in
// sync with crypto/sha1, including runs with GODEBUG=cpu.avx2=off and the
// like. Mirroring it only matters for speed: every code path computes the
// same digests.
//
// x86 is initialized before impl because defaultImpl refers to it.
var x86 = detectCPU(os.Getenv("GODEBUG"), goamd64Level())

type cpuFeatures struct {
	hasSSSE3 bool
	hasSSE41 bool
	hasAVX   bool
	hasAVX2  bool
	hasBMI1  bool
	hasBMI2  bool
	hasSHA   bool
}

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

func xgetbv() (eax, edx uint32)

// goamd64Level returns the GOAMD64 level the package was built for, 1 to 4.
func goamd64Level() int32

const (
	// CPUID leaf 1, ECX.
	cpuidSSSE3   = 1 << 9
	cpuidSSE41   = 1 << 19
	cpuidOSXSAVE = 1 << 27
	cpuidAVX     = 1 << 28

	// CPUID leaf 7, sub-leaf 0, EBX.
	cpuidBMI1 = 1 << 3
	cpuidAVX2 = 1 << 5
	cpuidBMI2 = 1 << 8
	cpuidSHA  = 1 << 29
)

// detectCPU queries CPUID and then applies the GODEBUG settings in env.
func detectCPU(env string, level int32) cpuFeatures {
	f := queryCPU()
	applyGODEBUG(&f, env, level)
	return f
}

func queryCPU() cpuFeatures {
	var f cpuFeatures
	maxID, _, _, _ := cpuid(0, 0)
	if maxID < 1 {
		return f
	}
	_, _, ecx1, _ := cpuid(1, 0)
	f.hasSSSE3 = ecx1&cpuidSSSE3 != 0
	f.hasSSE41 = ecx1&cpuidSSE41 != 0

	osSupportsAVX := false
	if ecx1&cpuidOSXSAVE != 0 {
		// The OS must save and restore the XMM and YMM registers.
		eax, _ := xgetbv()
		osSupportsAVX = eax&(1<<1) != 0 && eax&(1<<2) != 0
	}
	f.hasAVX = ecx1&cpuidAVX != 0 && osSupportsAVX

	if maxID < 7 {
		return f
	}
	_, ebx7, _, _ := cpuid(7, 0)
	f.hasBMI1 = ebx7&cpuidBMI1 != 0
	f.hasAVX2 = ebx7&cpuidAVX2 != 0 && osSupportsAVX
	f.hasBMI2 = ebx7&cpuidBMI2 != 0
	f.hasSHA = ebx7&cpuidSHA != 0
	return f
}

// applyGODEBUG applies the cpu.<feature>=on|off settings in env the way
// internal/cpu does: later settings override earlier ones, cpu.all applies
// to every option, and features that the GOAMD64 level requires cannot be
// turned off. Enabling a feature the CPU lacks has no effect. Unknown
// options are ignored silently, because the runtime already reports them.
func applyGODEBUG(f *cpuFeatures, env string, level int32) {
	type option struct {
		name      string
		feature   *bool
		specified bool
		enable    bool
	}
	options := []option{{name: "sha", feature: &f.hasSHA}}
	if level < 2 {
		options = append(options,
			option{name: "sse41", feature: &f.hasSSE41},
			option{name: "ssse3", feature: &f.hasSSSE3})
	}
	if level < 3 {
		options = append(options,
			option{name: "avx", feature: &f.hasAVX},
			option{name: "avx2", feature: &f.hasAVX2},
			option{name: "bmi1", feature: &f.hasBMI1},
			option{name: "bmi2", feature: &f.hasBMI2})
	}

	for env != "" {
		var field string
		if i := indexByte(env, ','); i < 0 {
			field, env = env, ""
		} else {
			field, env = env[:i], env[i+1:]
		}
		if len(field) < 4 || field[:4] != "cpu." {
			continue
		}
		i := indexByte(field, '=')
		if i < 0 {
			continue
		}
		key, value := field[4:i], field[i+1:]
		var enable bool
		switch value {
		case "on":
			enable = true
		case "off":
			enable = false
		default:
			continue
		}
		for j := range options {
			if key == "all" || options[j].name == key {
				options[j].specified = true
				options[j].enable = enable
			}
		}
	}

	for _, o := range options {
		if o.specified && (!o.enable || *o.feature) {
			*o.feature = o.enable
		}
	}
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
