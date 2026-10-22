//go:build difffuzz_boringssl

package difffuzz

/*
#cgo CFLAGS: -I${SRCDIR}/.cache/boringssl/src/include
#cgo LDFLAGS: ${SRCDIR}/.cache/boringssl/libcrypto.a -lstdc++ -lpthread
#include <openssl/sha.h>
#include <string.h>

static void boring_set(SHA_CTX *c, const uint32_t *h, const uint8_t *data, uint64_t len) {
	memcpy(c->h, h, sizeof(c->h));
	uint64_t bits = len << 3;
	c->Nl = (uint32_t)bits;
	c->Nh = (uint32_t)(bits >> 32);
	memcpy(c->data, data, sizeof(c->data));
	c->num = (unsigned)(len % 64);
}

static void boring_get(const SHA_CTX *c, uint32_t *h, uint8_t *data, uint64_t *bits, unsigned *num) {
	memcpy(h, c->h, sizeof(c->h));
	memcpy(data, c->data, sizeof(c->data));
	*bits = (uint64_t)c->Nh << 32 | c->Nl;
	*num = c->num;
}

static void boring_sum(const SHA_CTX *c, uint8_t *out) {
	SHA_CTX d = *c;
	SHA1_Final(out, &d);
}
*/
import "C"

import "unsafe"

// haveBoring reports whether BoringSSL is linked in as the reference.
const haveBoring = true

// boringCtx is a BoringSSL SHA_CTX. It holds no Go pointers, so it can
// live in Go memory and be copied to clone it.
type boringCtx struct {
	c C.SHA_CTX
}

func (b *boringCtx) init() {
	C.SHA1_Init(&b.c)
}

func (b *boringCtx) write(p []byte) {
	C.SHA1_Update(&b.c, unsafe.Pointer(cptr(p)), C.size_t(len(p)))
}

func (b *boringCtx) sum() (out [20]byte) {
	C.boring_sum(&b.c, (*C.uint8_t)(&out[0]))
	return
}

// set loads chaining values h, the block buffer x and a length of n
// bytes, of which n%64 are buffered.
func (b *boringCtx) set(h *[5]uint32, x *[64]byte, n uint64) {
	C.boring_set(&b.c, (*C.uint32_t)(&h[0]), (*C.uint8_t)(&x[0]), C.uint64_t(n))
}

// get returns the chaining values, the block buffer, the length in bits
// and the number of buffered bytes.
func (b *boringCtx) get(h *[5]uint32, x *[64]byte) (bits uint64, num int) {
	var cb C.uint64_t
	var cn C.unsigned
	C.boring_get(&b.c, (*C.uint32_t)(&h[0]), (*C.uint8_t)(&x[0]), &cb, &cn)
	return uint64(cb), int(cn)
}

// boringSum is BoringSSL's one-shot SHA1.
func boringSum(p []byte) (out [20]byte) {
	C.SHA1(cptr(p), C.size_t(len(p)), (*C.uint8_t)(&out[0]))
	return
}

func cptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
