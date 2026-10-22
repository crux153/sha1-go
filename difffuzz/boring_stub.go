//go:build !difffuzz_boringssl

package difffuzz

// haveBoring reports whether BoringSSL is linked in as the reference.
// Build with -tags difffuzz_boringssl (after boringssl.sh) to enable it;
// without it, crypto/sha1 is the reference.
const haveBoring = false

type boringCtx struct{}

const noBoring = "difffuzz: built without the difffuzz_boringssl tag"

func (b *boringCtx) init()                                       { panic(noBoring) }
func (b *boringCtx) write(p []byte)                              { panic(noBoring) }
func (b *boringCtx) sum() [20]byte                               { panic(noBoring) }
func (b *boringCtx) set(h *[5]uint32, x *[64]byte, n uint64)     { panic(noBoring) }
func (b *boringCtx) get(h *[5]uint32, x *[64]byte) (uint64, int) { panic(noBoring) }
func boringSum(p []byte) [20]byte                                { panic(noBoring) }
