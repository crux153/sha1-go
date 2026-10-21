// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha1

import (
	"bytes"
	stdsha1 "crypto/sha1"
	"syscall"
	"testing"
)

// TestGuardPages places inputs directly before and directly after an
// inaccessible page. A block function that reads even one byte outside its
// input crashes the test.
func TestGuardPages(t *testing.T) {
	pageSize := syscall.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, 3*pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Skipf("mmap: %v", err)
	}
	defer syscall.Munmap(mem)
	// Layout: guard page, data page, guard page.
	if err := syscall.Mprotect(mem[:pageSize], syscall.PROT_NONE); err != nil {
		t.Skipf("mprotect: %v", err)
	}
	if err := syscall.Mprotect(mem[2*pageSize:], syscall.PROT_NONE); err != nil {
		t.Skipf("mprotect: %v", err)
	}
	page := mem[pageSize : 2*pageSize]
	r := newRand(t)
	copy(page, randBytes(r, pageSize))

	forEachImpl(t, func(t *testing.T) {
		for n := 0; n <= pageSize; n++ {
			if n > 300 && n%BlockSize != 0 && n%BlockSize != 1 && n%BlockSize != 63 {
				continue
			}
			for _, p := range [][]byte{page[:n], page[pageSize-n:]} {
				want := stdsha1.Sum(p)
				if got := Sum(p); got != want {
					t.Fatalf("len %d: got %x, want %x", n, got, want)
				}
				h := New()
				h.Write(p)
				if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
					t.Fatalf("len %d: got %x, want %x", n, got, want)
				}
			}
			if impl != implStdlib && n%BlockSize == 0 {
				for _, p := range [][]byte{page[:n], page[pageSize-n:]} {
					var got, want digest
					got.Reset()
					want.Reset()
					block(&got, p)
					blockGeneric(&want, p)
					if got.h != want.h {
						t.Fatalf("block, %d bytes: got %08x, want %08x", n, got.h, want.h)
					}
				}
			}
		}
	})
}
