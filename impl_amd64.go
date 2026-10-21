// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package sha1

// blockAMD64 is the scalar block function from Go 1.24.
//
//go:noescape
func blockAMD64(dig *[5]uint32, p []byte)

// stdlibIsFast reports whether crypto/sha1 uses assembly on this CPU. The
// conditions are copied from Go 1.26's crypto/sha1/sha1block_amd64.go.
func stdlibIsFast() bool {
	useAVX2 := x86.hasAVX && x86.hasAVX2 && x86.hasBMI1 && x86.hasBMI2
	useSHANI := x86.hasAVX && x86.hasSHA && x86.hasSSE41 && x86.hasSSSE3
	return useAVX2 || useSHANI
}

func defaultImpl() implementation {
	if stdlibIsFast() {
		return implStdlib
	}
	return assemblyImpl()
}

// assemblyImpl returns the fastest of this package's assembly code paths
// that the CPU supports.
func assemblyImpl() implementation {
	return implScalar
}

// supportedImpls returns the code paths that can run on this machine.
func supportedImpls() []implementation {
	return []implementation{implStdlib, implGeneric, implScalar}
}

func block(dig *digest, p []byte) {
	switch impl {
	case implScalar:
		blockAMD64(&dig.h, p)
	default:
		blockGeneric(dig, p)
	}
}
