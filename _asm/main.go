// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command asm generates ../sha1block_ssse3_amd64.s, the SSSE3 SHA-1 block
// function.
//
// Run it from this directory with
//
//	go run . -out ../sha1block_ssse3_amd64.s
//
// # Algorithm
//
// This is an independent implementation of the technique that Intel
// published in 2010 ("Improving the Performance of the Secure Hash
// Algorithm (SHA-1)", Max Locktyukhin): the 80 rounds run on general
// purpose registers while SSE computes the message schedule four words at
// a time, interleaved with the rounds. No code from Intel, OpenSSL or
// CRYPTOGAMS was used.
//
// For each 64-byte block:
//
//   - W[0..15] are loaded with MOVOU and byte swapped with PSHUFB.
//   - W[16..31] use the definition W[i] = rol1(W[i-3] ^ W[i-8] ^ W[i-14] ^
//     W[i-16]). In a vector of four words, the last word depends on the
//     first, so the vector is computed with W[i] taken as zero and then
//     corrected with rol2 of the first lane's pre-rotation value.
//   - W[32..79] use the equivalent form W[i] = rol2(W[i-6] ^ W[i-16] ^
//     W[i-28] ^ W[i-32]), which has no dependency inside a vector.
//   - Each vector of W gets the round constant added (PADDD) and is stored
//     to a 16-byte aligned stack buffer, from which the scalar rounds add
//     W[t]+K[t] with a single ADDL.
//
// Vector v (W[4v..4v+3]) is computed during rounds 4(v-4)..4(v-4)+3, so it
// is ready 16 rounds before it is needed. During the last 16 rounds the
// first 16 words of the next block are loaded instead. For the last block
// the "next" block is the current one again, so the code never reads
// outside the input.
//
// Only legacy SSE encodings are used. Caller memory is only read with MOVOU
// (vectors) and MOVL-sized scalar loads; aligned SSE accesses touch only the
// explicitly aligned stack buffer.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// General purpose registers.
const (
	regT1   = "R9"  // scalar temporary
	regT2   = "R10" // scalar temporary
	regIn   = "SI"  // current block
	regEnd  = "DI"  // end of input
	regBuf  = "R11" // aligned W+K buffer
	regNext = "R12" // next block, or the current block on the last iteration
	regDig  = "R13" // *[5]uint32 state
)

// XMM registers. X0-X7 hold W as a ring of eight 4-word vectors.
const (
	xT0    = "X8"
	xT1    = "X9"
	xBswap = "X11"
	xK     = "X12"
)

func xw(v int) string { return fmt.Sprintf("X%d", v%8) }

// wk returns the buffer operand that holds W[t]+K[t].
func wk(t int) string { return fmt.Sprintf("%d(%s)", 4*t, regBuf) }

// kOffset returns the offset of the round constant vector for vector v in
// the sha1K table.
func kOffset(v int) int { return 16 * (v / 5) }

// Round function types.
const (
	fCh     = iota // rounds 0-19: Ch(b, c, d) = d ^ (b & (c ^ d))
	fParity        // rounds 20-39 and 60-79: b ^ c ^ d
	fMaj           // rounds 40-59: Maj(b, c, d) = (b & (c ^ d)) + (c & d)
)

func fType(t int) int {
	switch {
	case t < 20:
		return fCh
	case t >= 40 && t < 60:
		return fMaj
	}
	return fParity
}

// round returns the instructions of round t, given the registers holding
// a, b, c, d and e. The new a ends up in e's register.
//
// Two register-level choices keep the instruction count down:
//
//   - a is rotated left by 5 in place and added to e, instead of being
//     copied first. The register then holds rol5(a) rather than a while it
//     serves as b in the next round, where it is only rotated further, by
//     25, to reach rol30(a) for its later uses. After round 79 it is
//     rotated back by 27 (see fixup).
//   - Because b no longer holds its true value, each round computes the
//     part of the next round's f that involves the next b (that is, its
//     own a, before the rotation) and leaves it in R9 (and R10 for Maj).
//     The next round then needs at most one more instruction to finish f.
//
// Maj is written as (b & (c ^ d)) + (c & d); the two terms never have a
// bit set in common, so they can be added to e separately.
//
// Round 0 has no previous round and computes f directly from b, which
// holds its true value there.
func round(t int, a, b, c, d, e string) []string {
	p, q := regT1, regT2
	ins := []string{"ADDL " + wk(t) + ", " + e}

	// Finish f for this round.
	switch {
	case t == 0:
		ins = append(ins,
			"MOVL "+c+", "+p,
			"XORL "+d+", "+p,
			"ANDL "+b+", "+p,
			"XORL "+d+", "+p,
			"ADDL "+p+", "+e,
			"ROLL $30, "+b,
		)
	default:
		switch fType(t) {
		case fCh:
			// p = (c ^ d) & b
			ins = append(ins, "XORL "+d+", "+p, "ADDL "+p+", "+e)
		case fParity:
			// p = b ^ c ^ d
			ins = append(ins, "ADDL "+p+", "+e)
		case fMaj:
			// p = (c ^ d) & b, q = c & d
			ins = append(ins, "ADDL "+p+", "+e, "ADDL "+q+", "+e)
		}
		// b holds rol5 of its true value; make it rol30.
		ins = append(ins, "ROLL $25, "+b)
	}

	// Start f for the next round, whose b, c and d are this round's a,
	// rotated b and c. a still holds its true value here.
	if t < 79 {
		ins = append(ins, "MOVL "+b+", "+p, "XORL "+c+", "+p)
		switch fType(t + 1) {
		case fCh:
			ins = append(ins, "ANDL "+a+", "+p)
		case fParity:
			ins = append(ins, "XORL "+a+", "+p)
		case fMaj:
			ins = append(ins, "ANDL "+a+", "+p, "MOVL "+b+", "+q, "ANDL "+c+", "+q)
		}
	}

	return append(ins,
		"ROLL $5, "+a,
		"ADDL "+a+", "+e,
	)
}

// fixup returns the instruction that restores the true value of b after
// round 79. b is the register that was a in round 79.
func fixup(b string) []string {
	return []string{"ROLL $27, " + b}
}

// schedule returns the SSE instructions that compute vector v of W into
// its ring register and store W+K for it.
func schedule(v int) []string {
	var ins []string
	if v%5 == 0 {
		ins = append(ins, fmt.Sprintf("MOVOU sha1K<>+%d(SB), %s", kOffset(v), xK))
	}
	dst := xw(v)
	if v < 8 {
		// W[i..i+3] = rol1(W[i-3..i-1, 0] ^ W[i-8..] ^ W[i-14..] ^ W[i-16..]),
		// then W[i+3] ^= rol2(lane 0 before rotation).
		ins = append(ins,
			"MOVO "+xw(v-3)+", "+dst,
			"PALIGNR $8, "+xw(v-4)+", "+dst, // W[i-14..i-11]
			"MOVO "+xw(v-1)+", "+xT0,
			"PSRLO $4, "+xT0, // W[i-3..i-1], 0
			"PXOR "+xw(v-4)+", "+dst,
			"PXOR "+xw(v-2)+", "+xT0,
			"PXOR "+xT0+", "+dst,
			"MOVO "+dst+", "+xT1,
			"PSLLO $12, "+xT1, // lane 0 moved to lane 3
			"MOVO "+dst+", "+xT0,
			"PSLLL $1, "+dst,
			"PSRLL $31, "+xT0,
			"POR "+xT0+", "+dst,
			"MOVO "+xT1+", "+xT0,
			"PSLLL $2, "+xT1,
			"PSRLL $30, "+xT0,
			"PXOR "+xT1+", "+dst,
			"PXOR "+xT0+", "+dst,
		)
	} else {
		// W[i..i+3] = rol2(W[i-6..i-3] ^ W[i-16..] ^ W[i-28..] ^ W[i-32..]).
		// dst holds W[i-32..i-29] on entry.
		ins = append(ins,
			"MOVO "+xw(v-1)+", "+xT0,
			"PALIGNR $8, "+xw(v-2)+", "+xT0, // W[i-6..i-3]
			"PXOR "+xw(v-7)+", "+dst,
			"PXOR "+xw(v-4)+", "+xT0,
			"PXOR "+xT0+", "+dst,
			"MOVO "+dst+", "+xT0,
			"PSLLL $2, "+dst,
			"PSRLL $30, "+xT0,
			"POR "+xT0+", "+dst,
		)
	}
	return append(ins,
		"MOVO "+dst+", "+xT0,
		"PADDL "+xK+", "+xT0,
		fmt.Sprintf("MOVO %s, %d(%s)", xT0, 16*v, regBuf),
	)
}

// load returns the SSE instructions that load vector v (v < 4) of the
// block at ptr into its ring register and store W+K for it. The caller
// must have loaded the first round constant into xK.
func load(v int, ptr string) []string {
	return []string{
		fmt.Sprintf("MOVOU %d(%s), %s", 16*v, ptr, xw(v)),
		"PSHUFB " + xBswap + ", " + xw(v),
		"MOVO " + xw(v) + ", " + xT0,
		"PADDL " + xK + ", " + xT0,
		fmt.Sprintf("MOVO %s, %d(%s)", xT0, 16*v, regBuf),
	}
}

type writer struct{ bytes.Buffer }

func (w *writer) ins(s string) {
	op, args, _ := strings.Cut(s, " ")
	fmt.Fprintf(w, "\t%-7s %s\n", op, args)
}

func (w *writer) line(format string, args ...any) {
	fmt.Fprintf(w, format+"\n", args...)
}

// interleave merges vec into scalar, spreading the vector instructions
// evenly and starting with one so that loads issue early.
func interleave(scalar, vec []string) []string {
	out := make([]string, 0, len(scalar)+len(vec))
	j := 0
	for i, s := range scalar {
		for j < len(vec) && j*len(scalar) <= i*len(vec) {
			out = append(out, vec[j])
			j++
		}
		out = append(out, s)
	}
	return append(out, vec[j:]...)
}

func generate() []byte {
	var w writer
	w.line("// Code generated by command: go run . -out ../sha1block_ssse3_amd64.s. DO NOT EDIT.")
	w.line("")
	w.line("// Copyright 2026 Crux. All rights reserved.")
	w.line("// Use of this source code is governed by a BSD-style")
	w.line("// license that can be found in the LICENSE file.")
	w.line("")
	w.line("// SSSE3 SHA-1 block function. See _asm/main.go for the algorithm and its")
	w.line("// provenance: it is an independent implementation of the technique Intel")
	w.line("// published in 2010 and contains no code from Intel, OpenSSL or CRYPTOGAMS.")
	w.line("")
	w.line("//go:build !purego")
	w.line("")
	w.line(`#include "textflag.h"`)
	w.line("")

	w.line("// func blockSSSE3(dig *[5]uint32, p []byte)")
	w.line("// Requires: SSSE3")
	// 320 bytes of W+K plus up to 15 bytes of alignment padding.
	w.line("TEXT ·blockSSSE3(SB), 0, $336-32")
	for _, s := range []string{
		"MOVQ dig+0(FP), " + regDig,
		"MOVQ p_base+8(FP), " + regIn,
		"MOVQ p_len+16(FP), DX",
		"ANDQ $~63, DX",
		"JZ done",
		"LEAQ (" + regIn + ")(DX*1), " + regEnd,
		"",
		"// Align the W+K buffer to 16 bytes for MOVO.",
		"LEAQ 15(SP), " + regBuf,
		"ANDQ $~15, " + regBuf,
		"",
		"MOVOU bswapMask<>(SB), " + xBswap,
		"MOVOU sha1K<>+0(SB), " + xK,
	} {
		emitLine(&w, s)
	}
	for v := 0; v < 4; v++ {
		for _, s := range load(v, regIn) {
			w.ins(s)
		}
	}
	state := [5]string{"AX", "BX", "CX", "DX", "R8"}
	for i, r := range state {
		w.ins(fmt.Sprintf("MOVL %d(%s), %s", 4*i, regDig, r))
	}
	w.line("")
	w.line("loop:")
	w.line("\t// Load the next block during the last rounds, or the current block")
	w.line("\t// again if this is the last one.")
	w.ins("LEAQ 64(" + regIn + "), " + regNext)
	w.ins("CMPQ " + regNext + ", " + regEnd)
	w.ins("CMOVQEQ " + regIn + ", " + regNext)

	v := state
	for g := 0; g < 20; g++ {
		var vec []string
		var comment string
		switch {
		case g < 16:
			vec = schedule(g + 4)
			comment = fmt.Sprintf("// Rounds %d-%d; W[%d..%d].", 4*g, 4*g+3, 4*(g+4), 4*(g+4)+3)
		default:
			if g == 16 {
				vec = append(vec, "MOVOU sha1K<>+0(SB), "+xK)
			}
			vec = append(vec, load(g-16, regNext)...)
			comment = fmt.Sprintf("// Rounds %d-%d; next block W[%d..%d].", 4*g, 4*g+3, 4*(g-16), 4*(g-16)+3)
		}
		var scalar []string
		for t := 4 * g; t < 4*g+4; t++ {
			scalar = append(scalar, round(t, v[0], v[1], v[2], v[3], v[4])...)
			v = [5]string{v[4], v[0], v[1], v[2], v[3]}
		}
		w.line("")
		w.line("\t" + comment)
		for _, s := range interleave(scalar, vec) {
			w.ins(s)
		}
	}
	if v != state {
		log.Fatal("state registers did not rotate back")
	}
	for _, s := range fixup(v[1]) {
		w.ins(s)
	}

	w.line("")
	for i, r := range state {
		w.ins(fmt.Sprintf("ADDL %d(%s), %s", 4*i, regDig, r))
		w.ins(fmt.Sprintf("MOVL %s, %d(%s)", r, 4*i, regDig))
	}
	w.ins("ADDQ $64, " + regIn)
	w.ins("CMPQ " + regIn + ", " + regEnd)
	w.ins("JB loop")
	w.line("")
	w.line("done:")
	w.ins("RET")
	w.line("")

	w.line("// PSHUFB mask that byte swaps each 32-bit word.")
	w.line("DATA bswapMask<>+0(SB)/8, $0x0405060700010203")
	w.line("DATA bswapMask<>+8(SB)/8, $0x0c0d0e0f08090a0b")
	w.line("GLOBL bswapMask<>(SB), RODATA|NOPTR, $16")
	w.line("")
	w.line("// Round constants, each repeated four times.")
	for i, k := range []uint32{0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6} {
		for j := 0; j < 4; j++ {
			w.line("DATA sha1K<>+%d(SB)/4, $0x%08x", 16*i+4*j, k)
		}
	}
	w.line("GLOBL sha1K<>(SB), RODATA|NOPTR, $64")
	return w.Bytes()
}

func emitLine(w *writer, s string) {
	switch {
	case s == "":
		w.line("")
	case strings.HasPrefix(s, "//"):
		w.line("\t" + s)
	default:
		w.ins(s)
	}
}

func main() {
	out := flag.String("out", "", "output file (default: standard output)")
	flag.Parse()
	src := generate()
	if *out == "" {
		os.Stdout.Write(src)
		return
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		log.Fatal(err)
	}
}
