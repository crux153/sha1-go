// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha1

import (
	"bytes"
	stdsha1 "crypto/sha1"
	"encoding"
	"encoding/hex"
	"fmt"
	"hash"
	"math/rand/v2"
	"strings"
	"testing"
	"unsafe"
)

// setImpl forces the code path used by New, Sum and block and returns a
// function that restores the previous one. Tests that call it must not run
// in parallel.
func setImpl(i implementation) (restore func()) {
	old := impl
	impl = i
	return func() { impl = old }
}

// forEachImpl runs f as a subtest once per code path this machine supports.
func forEachImpl(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	for _, i := range supportedImpls() {
		t.Run(i.String(), func(t *testing.T) {
			defer setImpl(i)()
			f(t)
		})
	}
}

func newRand(t testing.TB) *rand.Rand {
	t.Helper()
	seed := rand.Uint64()
	t.Logf("random seed %#x", seed)
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i += 8 {
		v := r.Uint64()
		for j := i; j < n && j < i+8; j++ {
			b[j] = byte(v)
			v >>= 8
		}
	}
	return b
}

// checkAll compares every way of hashing data with this package against
// crypto/sha1.
func checkAll(t *testing.T, data []byte) {
	t.Helper()
	want := stdsha1.Sum(data)
	if got := Sum(data); got != want {
		t.Fatalf("Sum(len %d) = %x, want %x", len(data), got, want)
	}
	h := New()
	h.Write(data)
	if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
		t.Fatalf("New().Write(len %d).Sum = %x, want %x", len(data), got, want)
	}
}

func TestNISTVectors(t *testing.T) {
	// FIPS 180-4 examples and the NIST CSRC SHA-1 example values.
	vectors := []struct {
		in, out string
	}{
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
		{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259"},
		{strings.Repeat("a", 1000000), "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
	}
	forEachImpl(t, func(t *testing.T) {
		for _, v := range vectors {
			sum := Sum([]byte(v.in))
			if got := hex.EncodeToString(sum[:]); got != v.out {
				t.Errorf("Sum(%.20q... len %d) = %s, want %s", v.in, len(v.in), got, v.out)
			}
			h := New()
			for i := 0; i < len(v.in); i += 1000 {
				h.Write([]byte(v.in[i:min(i+1000, len(v.in))]))
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != v.out {
				t.Errorf("New().Sum(%.20q... len %d) = %s, want %s", v.in, len(v.in), got, v.out)
			}
		}
	})
}

func TestEveryLength(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 4096)
	forEachImpl(t, func(t *testing.T) {
		for n := 0; n <= len(data); n++ {
			checkAll(t, data[:n])
		}
	})
}

func TestRandomLongLengths(t *testing.T) {
	r := newRand(t)
	const maxLen = 8 << 20
	data := randBytes(r, maxLen)
	lengths := []int{maxLen, maxLen - 1, 1 << 20, 1<<20 + 63}
	iters := 24
	if testing.Short() {
		iters = 4
	}
	for range iters {
		lengths = append(lengths, r.IntN(maxLen+1))
	}
	forEachImpl(t, func(t *testing.T) {
		for _, n := range lengths {
			checkAll(t, data[:n])
		}
	})
}

func TestRandomWriteSplits(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 64<<10)
	forEachImpl(t, func(t *testing.T) {
		for range 300 {
			n := r.IntN(len(data) + 1)
			want := stdsha1.Sum(data[:n])
			h := New()
			for p := data[:n]; len(p) > 0; {
				// Mix tiny, block-sized and large writes.
				var k int
				switch r.IntN(4) {
				case 0:
					k = r.IntN(4)
				case 1:
					k = r.IntN(130)
				case 2:
					k = 64 * r.IntN(5)
				default:
					k = r.IntN(len(p) + 1)
				}
				k = min(k, len(p))
				if nn, err := h.Write(p[:k]); nn != k || err != nil {
					t.Fatalf("Write returned %d, %v; want %d, nil", nn, err, k)
				}
				p = p[k:]
			}
			if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("split writes of %d bytes: got %x, want %x", n, got, want)
			}
		}
	})
}

func TestSumDoesNotChangeState(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 1000)
	forEachImpl(t, func(t *testing.T) {
		for _, split := range []int{0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 999} {
			h := New()
			h.Write(data[:split])
			want1 := stdsha1.Sum(data[:split])
			for range 3 {
				if got := h.Sum(nil); !bytes.Equal(got, want1[:]) {
					t.Fatalf("Sum after %d bytes = %x, want %x", split, got, want1)
				}
			}
			h.Write(data[split:])
			want2 := stdsha1.Sum(data)
			if got := h.Sum([]byte("prefix")); !bytes.Equal(got, append([]byte("prefix"), want2[:]...)) {
				t.Fatalf("Sum after Sum at %d = %x, want prefix+%x", split, got, want2)
			}
		}
	})
}

func TestReset(t *testing.T) {
	forEachImpl(t, func(t *testing.T) {
		h := New()
		h.Write([]byte(strings.Repeat("garbage", 100)))
		h.Reset()
		h.Write([]byte("abc"))
		if got := hex.EncodeToString(h.Sum(nil)); got != "a9993e364706816aba3e25717850c26c9cd0d89d" {
			t.Errorf("after Reset: got %s", got)
		}
	})
}

func TestSizes(t *testing.T) {
	if Size != stdsha1.Size || BlockSize != stdsha1.BlockSize {
		t.Fatalf("Size, BlockSize = %d, %d; want %d, %d", Size, BlockSize, stdsha1.Size, stdsha1.BlockSize)
	}
	forEachImpl(t, func(t *testing.T) {
		h := New()
		if h.Size() != Size || h.BlockSize() != BlockSize {
			t.Errorf("Size(), BlockSize() = %d, %d", h.Size(), h.BlockSize())
		}
	})
}

func TestInterfaces(t *testing.T) {
	forEachImpl(t, func(t *testing.T) {
		h := New()
		if _, ok := h.(encoding.BinaryMarshaler); !ok {
			t.Error("not an encoding.BinaryMarshaler")
		}
		if _, ok := h.(encoding.BinaryUnmarshaler); !ok {
			t.Error("not an encoding.BinaryUnmarshaler")
		}
		if _, ok := h.(encoding.BinaryAppender); !ok {
			t.Error("not an encoding.BinaryAppender")
		}
		if _, ok := h.(hash.Cloner); !ok {
			t.Error("not a hash.Cloner")
		}
	})
}

func TestClone(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 300)
	forEachImpl(t, func(t *testing.T) {
		h := New()
		h.Write(data[:100])
		c, err := h.(hash.Cloner).Clone()
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte("diverge"))
		c.Write(data[100:])
		want := stdsha1.Sum(data)
		if got := c.Sum(nil); !bytes.Equal(got, want[:]) {
			t.Errorf("clone: got %x, want %x", got, want)
		}
	})
}

type marshaler interface {
	hash.Hash
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	encoding.BinaryAppender
}

func TestMarshalRoundTrip(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 1000)
	forEachImpl(t, func(t *testing.T) {
		for _, split := range []int{0, 1, 55, 63, 64, 65, 128, 500, 999, 1000} {
			h := New().(marshaler)
			h.Write(data[:split])
			state, err := h.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			appended, err := h.AppendBinary([]byte("xyz"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(appended, append([]byte("xyz"), state...)) {
				t.Fatalf("AppendBinary does not match MarshalBinary")
			}
			h2 := New().(marshaler)
			h2.Write([]byte("junk that the unmarshal must overwrite"))
			if err := h2.UnmarshalBinary(state); err != nil {
				t.Fatal(err)
			}
			h.Write(data[split:])
			h2.Write(data[split:])
			want := stdsha1.Sum(data)
			if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("original after marshal at %d: %x, want %x", split, got, want)
			}
			if got := h2.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("unmarshalled at %d: %x, want %x", split, got, want)
			}
		}
	})
}

// TestMarshalCompatibility checks that the marshalled state is byte for
// byte the same as crypto/sha1's and that each package accepts the other's.
func TestMarshalCompatibility(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 1000)
	forEachImpl(t, func(t *testing.T) {
		for _, split := range []int{0, 1, 55, 63, 64, 65, 128, 500, 999, 1000} {
			ours := New().(marshaler)
			std := stdsha1.New().(marshaler)
			ours.Write(data[:split])
			std.Write(data[:split])
			ourState, err := ours.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			stdState, err := std.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ourState, stdState) {
				t.Fatalf("state at %d differs:\n ours %x\n std  %x", split, ourState, stdState)
			}

			toStd := stdsha1.New().(marshaler)
			if err := toStd.UnmarshalBinary(ourState); err != nil {
				t.Fatalf("crypto/sha1 rejects our state: %v", err)
			}
			toOurs := New().(marshaler)
			if err := toOurs.UnmarshalBinary(stdState); err != nil {
				t.Fatalf("we reject crypto/sha1's state: %v", err)
			}
			toStd.Write(data[split:])
			toOurs.Write(data[split:])
			want := stdsha1.Sum(data)
			if got := toStd.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("crypto/sha1 from our state at %d: %x, want %x", split, got, want)
			}
			if got := toOurs.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Fatalf("ours from crypto/sha1 state at %d: %x, want %x", split, got, want)
			}
		}
	})
}

func TestUnmarshalErrors(t *testing.T) {
	forEachImpl(t, func(t *testing.T) {
		h := New().(marshaler)
		h.Write([]byte("abc"))
		good, _ := h.MarshalBinary()
		std := stdsha1.New().(marshaler)
		for _, bad := range [][]byte{
			nil,
			[]byte("sha"),
			[]byte("sha\x02" + string(good[4:])),
			good[:len(good)-1],
			append(append([]byte{}, good...), 0),
		} {
			gotErr := New().(marshaler).UnmarshalBinary(bad)
			wantErr := std.UnmarshalBinary(bad)
			if gotErr == nil || wantErr == nil || gotErr.Error() != wantErr.Error() {
				t.Errorf("UnmarshalBinary(%x) = %v, crypto/sha1 says %v", bad, gotErr, wantErr)
			}
		}
	})
}

// TestAlignment hashes inputs that start at every offset from a 16-byte
// boundary. Legacy SSE memory operands fault on unaligned addresses, so
// this catches any that slip into the assembly.
func TestAlignment(t *testing.T) {
	r := newRand(t)
	buf := randBytes(r, 16+8192+64)
	base := int(-uintptr(unsafe.Pointer(&buf[0])) & 15)
	forEachImpl(t, func(t *testing.T) {
		for off := 0; off < 16; off++ {
			p := buf[base+off:]
			if uintptr(unsafe.Pointer(&p[0]))&15 != uintptr(off) {
				t.Fatalf("offset %d: misaligned test buffer", off)
			}
			for _, n := range []int{0, 1, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 257, 1000, 4096, 8192} {
				checkAll(t, p[:n])
				// A digest that already holds a partial block feeds the
				// block function from p at a different alignment.
				for _, pre := range []int{1, 7, 33} {
					h := New()
					h.Write(p[:pre])
					h.Write(p[pre : n+pre])
					want := stdsha1.Sum(p[:n+pre])
					if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
						t.Fatalf("offset %d, len %d+%d: got %x, want %x", off, pre, n, got, want)
					}
				}
			}
		}
	})
}

// TestBlockDirect calls block with multi-block inputs directly, so that
// every possible number of blocks per call up to 40 is covered regardless
// of how Write splits its input.
func TestBlockDirect(t *testing.T) {
	r := newRand(t)
	data := randBytes(r, 40*BlockSize)
	forEachImpl(t, func(t *testing.T) {
		if impl == implStdlib {
			t.Skip("block is not used")
		}
		for n := 0; n <= 40; n++ {
			var got, want digest
			got.Reset()
			want.Reset()
			block(&got, data[:n*BlockSize])
			blockGeneric(&want, data[:n*BlockSize])
			if got.h != want.h {
				t.Fatalf("%d blocks: got %08x, want %08x", n, got.h, want.h)
			}
		}
	})
}

func TestImplString(t *testing.T) {
	for _, i := range supportedImpls() {
		if s := i.String(); s == "unknown" || s == "" {
			t.Errorf("implementation %d has no name", i)
		}
	}
	t.Logf("default implementation: %v; supported: %v", defaultImpl(), fmt.Sprint(supportedImpls()))
}
