// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha1

import (
	stdsha1 "crypto/sha1"
	"fmt"
	"hash"
	"os"
	"strconv"
	"testing"
)

var benchSizes = []int{64, 1 << 10, 64 << 10, 1 << 20}

// cpuGHz is the fixed core clock in GHz given in SHA1GO_CPU_GHZ. When it
// is set, benchmarks also report cycles per byte. The number is only
// meaningful if the clock really is pinned to that frequency (turbo and
// frequency scaling disabled).
var cpuGHz, _ = strconv.ParseFloat(os.Getenv("SHA1GO_CPU_GHZ"), 64)

func reportCycles(b *testing.B, size int) {
	if cpuGHz > 0 {
		ns := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		b.ReportMetric(ns*cpuGHz/float64(size), "cycles/B")
	}
}

func benchmarkHash(b *testing.B, newHash func() hash.Hash, size int) {
	buf := make([]byte, size)
	h := newHash()
	sum := make([]byte, 0, Size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for b.Loop() {
		h.Reset()
		h.Write(buf)
		h.Sum(sum[:0])
	}
	reportCycles(b, size)
}

// BenchmarkHash measures New/Write/Sum for every code path. The names are
// stable across machines so that benchstat can compare runs; paths the CPU
// does not support are skipped. "crypto" is crypto/sha1 itself, which is
// what "stdlib" delegates to.
func BenchmarkHash(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("impl=crypto/size=%s", sizeName(size)), func(b *testing.B) {
			benchmarkHash(b, stdsha1.New, size)
		})
		for _, i := range []implementation{implStdlib, implSSSE3, implScalar, implGeneric} {
			b.Run(fmt.Sprintf("impl=%v/size=%s", i, sizeName(size)), func(b *testing.B) {
				if !supported(i) {
					b.Skipf("%v is not supported on this CPU", i)
				}
				defer setImpl(i)()
				benchmarkHash(b, New, size)
			})
		}
	}
}

// BenchmarkSum measures the one-shot Sum function with the default code
// path, which is what a consumer of this package gets.
func BenchmarkSum(b *testing.B) {
	for _, size := range benchSizes {
		b.Run("size="+sizeName(size), func(b *testing.B) {
			buf := make([]byte, size)
			b.SetBytes(int64(size))
			for b.Loop() {
				Sum(buf)
			}
			reportCycles(b, size)
		})
	}
}

func supported(i implementation) bool {
	for _, s := range supportedImpls() {
		if s == i {
			return true
		}
	}
	return false
}

func sizeName(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", n>>10)
	}
	return fmt.Sprintf("%dB", n)
}
