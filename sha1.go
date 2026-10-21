// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha1 is a drop-in replacement for [crypto/sha1] that is fast on
// x86-64 CPUs with SSSE3 but without AVX2 or SHA-NI.
//
// The standard library ships SHA-1 assembly for amd64 only for CPUs with
// SHA-NI or AVX2; everything else runs a pure Go block function. This
// package keeps the standard library on CPUs it already handles well and
// otherwise uses its own SSSE3 assembly, or a scalar assembly fallback on
// CPUs without SSSE3. Other architectures and builds with the purego tag
// always use [crypto/sha1].
//
// The API, the digests and the marshalled hash state are identical to
// [crypto/sha1], so state marshalled by one package can be unmarshalled by
// the other.
//
// SHA-1 is cryptographically broken and should not be used for secure
// applications.
package sha1

import (
	"crypto/fips140"
	stdsha1 "crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
)

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

// The error messages below match crypto/sha1 so that callers which inspect
// them behave the same with either package.
var (
	errFIPSOnly     = errors.New("crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode")
	errInvalidIdent = errors.New("crypto/sha1: invalid hash state identifier")
	errInvalidSize  = errors.New("crypto/sha1: invalid hash state size")
)

// digest represents the partial evaluation of a checksum.
//
// The layout matches crypto/sha1. The assembly block functions rely on h
// being the first field.
type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic         = "sha\x01"
	marshaledSize = len(magic) + 5*4 + chunk + 8
)

func (d *digest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, marshaledSize))
}

func (d *digest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, magic...)
	b = binary.BigEndian.AppendUint32(b, d.h[0])
	b = binary.BigEndian.AppendUint32(b, d.h[1])
	b = binary.BigEndian.AppendUint32(b, d.h[2])
	b = binary.BigEndian.AppendUint32(b, d.h[3])
	b = binary.BigEndian.AppendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-d.nx)...)
	b = binary.BigEndian.AppendUint64(b, d.len)
	return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errInvalidIdent
	}
	if len(b) != marshaledSize {
		return errInvalidSize
	}
	b = b[len(magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], binary.BigEndian.Uint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], binary.BigEndian.Uint32(b)
}

func (d *digest) Clone() (hash.Cloner, error) {
	r := *d
	return &r, nil
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

// New returns a new [hash.Hash] computing the SHA1 checksum. The Hash
// also implements [encoding.BinaryMarshaler], [encoding.BinaryAppender] and
// [encoding.BinaryUnmarshaler] to marshal and unmarshal the internal
// state of the hash.
//
// On CPUs where [crypto/sha1] is already fast, New returns the result of
// [crypto/sha1.New].
func New() hash.Hash {
	if impl == implStdlib {
		return stdsha1.New()
	}
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	if fips140.Enforced() {
		return 0, errFIPSOnly
	}
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	if fips140.Enforced() {
		panic(errFIPSOnly.Error())
	}

	len := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	binary.BigEndian.PutUint64(padlen[t:], len)
	d.Write(padlen)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])

	return digest
}

// Sum returns the SHA-1 checksum of the data.
func Sum(data []byte) [Size]byte {
	if impl == implStdlib {
		return stdsha1.Sum(data)
	}
	if fips140.Enforced() {
		panic(errFIPSOnly.Error())
	}
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
