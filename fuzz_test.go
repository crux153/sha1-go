// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha1

import (
	"bytes"
	stdsha1 "crypto/sha1"
	"encoding"
	"hash"
	"strings"
	"testing"
)

// FuzzSum compares Sum and a single Write on every supported code path
// against crypto/sha1. off shifts the start of the input to vary its
// alignment.
func FuzzSum(f *testing.F) {
	f.Add([]byte(""), uint8(0))
	f.Add([]byte("abc"), uint8(1))
	f.Add(bytes.Repeat([]byte{0xa5}, 55), uint8(2))
	f.Add(bytes.Repeat([]byte{0x5a}, 64), uint8(3))
	f.Add([]byte(strings.Repeat("0123456789abcdef", 50)), uint8(7))
	f.Fuzz(func(t *testing.T, data []byte, off uint8) {
		if k := int(off % 16); k <= len(data) {
			data = data[k:]
		}
		want := stdsha1.Sum(data)
		for _, i := range supportedImpls() {
			restore := setImpl(i)
			got := Sum(data)
			h := New()
			h.Write(data)
			got2 := h.Sum(nil)
			restore()
			if got != want {
				t.Fatalf("%v: Sum = %x, want %x", i, got, want)
			}
			if !bytes.Equal(got2, want[:]) {
				t.Fatalf("%v: New().Write.Sum = %x, want %x", i, got2, want)
			}
		}
	})
}

// FuzzWrite feeds data to every supported code path in chunks whose sizes
// come from splits, takes intermediate sums, and moves the state through
// crypto/sha1 and back with MarshalBinary/UnmarshalBinary halfway through.
func FuzzWrite(f *testing.F) {
	f.Add([]byte("hello, world"), []byte{1, 2, 3})
	f.Add(bytes.Repeat([]byte("x"), 300), []byte{64, 0, 63, 65, 128})
	f.Add(bytes.Repeat([]byte("y"), 1000), []byte{255, 200, 7})
	f.Fuzz(func(t *testing.T, data, splits []byte) {
		want := stdsha1.Sum(data)
		for _, i := range supportedImpls() {
			restore := setImpl(i)
			h := New()
			p := data
			for j := 0; len(p) > 0; j++ {
				k := len(p)
				if j < len(splits) {
					// Sizes up to 255*4 bytes, so that large and
					// multi-block writes happen too.
					k = min(int(splits[j])*(1+j%4), len(p))
				}
				h.Write(p[:k])
				p = p[k:]
				prefix := data[:len(data)-len(p)]
				wantPrefix := stdsha1.Sum(prefix)
				if got := h.Sum(nil); !bytes.Equal(got, wantPrefix[:]) {
					restore()
					t.Fatalf("%v: sum of %d-byte prefix = %x, want %x", i, len(prefix), got, wantPrefix)
				}
				if j == len(splits)/2 {
					h = roundTrip(t, h)
				}
			}
			got := h.Sum(nil)
			restore()
			if !bytes.Equal(got, want[:]) {
				t.Fatalf("%v: got %x, want %x", i, got, want)
			}
		}
	})
}

// roundTrip moves the state of h into crypto/sha1 and back into a new hash
// from this package.
func roundTrip(t *testing.T, h hash.Hash) hash.Hash {
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	std := stdsha1.New()
	if err := std.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		t.Fatal(err)
	}
	state, err = std.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	h2 := New()
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		t.Fatal(err)
	}
	return h2
}
