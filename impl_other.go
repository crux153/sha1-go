// Copyright 2026 Crux. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package sha1

func defaultImpl() implementation {
	return implStdlib
}

// supportedImpls returns the code paths that can run on this machine.
func supportedImpls() []implementation {
	return []implementation{implStdlib, implGeneric}
}

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
