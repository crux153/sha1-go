// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha1

// implementation identifies a SHA-1 code path.
type implementation uint8

const (
	// implStdlib delegates New and Sum to crypto/sha1.
	implStdlib implementation = iota
	// implGeneric is this package's digest with a pure Go block function.
	// It is never selected automatically; tests use it to exercise the
	// digest wrapper on every architecture.
	implGeneric
	// implScalar is the scalar amd64 assembly from Go 1.24.
	implScalar
	// implSSSE3 is the SSSE3 assembly.
	implSSSE3
)

func (i implementation) String() string {
	switch i {
	case implStdlib:
		return "stdlib"
	case implGeneric:
		return "generic"
	case implScalar:
		return "scalar"
	case implSSSE3:
		return "ssse3"
	}
	return "unknown"
}

// impl is the code path used by New, Sum and the digest's block function.
// It is chosen once at init time and only changed by tests.
var impl = defaultImpl()
