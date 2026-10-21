// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package sha1

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const ssse3File = "sha1block_ssse3_amd64.s"

// TestSSSE3SourceRules checks the generated SSSE3 assembly for the rules
// it must follow:
//
//   - no VEX-encoded (AVX) instructions;
//   - SSE instructions only access memory through MOVOU (unaligned loads),
//     the explicitly aligned W+K buffer in R11, or this file's own data,
//     because a legacy SSE memory operand faults on an unaligned address.
func TestSSSE3SourceRules(t *testing.T) {
	src, err := os.ReadFile(ssse3File)
	if err != nil {
		t.Fatal(err)
	}
	memOperand := regexp.MustCompile(`\(`)
	ymm := regexp.MustCompile(`\b[YZ]\d+\b`)
	sse := regexp.MustCompile(`^(P[A-Z]+|MOVO|MOVOU|MOVDQ[AU]|MOVAP[SD]|MOVUP[SD]|SHUFP[SD])$`)
	checked := 0
	for n, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasSuffix(line, ":") ||
			strings.HasPrefix(line, "#") || strings.HasPrefix(line, "TEXT") ||
			strings.HasPrefix(line, "DATA") || strings.HasPrefix(line, "GLOBL") {
			continue
		}
		op, args, _ := strings.Cut(line, " ")
		if strings.HasPrefix(op, "V") {
			t.Errorf("line %d: VEX instruction %q", n+1, line)
		}
		if ymm.MatchString(args) {
			t.Errorf("line %d: YMM or ZMM register in %q", n+1, line)
		}
		if !sse.MatchString(op) || !memOperand.MatchString(args) {
			continue
		}
		checked++
		switch {
		case op == "MOVOU":
		case op == "MOVO" && strings.Contains(args, "(R11)"):
		default:
			t.Errorf("line %d: SSE memory operand that may be unaligned: %q", n+1, line)
		}
	}
	if checked == 0 {
		t.Fatal("found no SSE memory operands; is the parser broken?")
	}
}

// TestSSSE3Generated checks that the SSSE3 assembly matches its generator.
func TestSSSE3Generated(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the generator")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not found")
	}
	out := filepath.Join(t.TempDir(), ssse3File)
	cmd := exec.Command(goTool, "run", ".", "-out", out)
	cmd.Dir = "_asm"
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator failed: %v\n%s", err, b)
	}
	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(ssse3File)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale; run go generate", ssse3File)
	}
}
