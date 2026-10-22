package difffuzz

import (
	"bytes"
	stdsha1 "crypto/sha1"
	"encoding"
	"encoding/binary"
	"fmt"
	"hash"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	sha1 "github.com/crux153/sha1-go"
)

// refKind selects a reference implementation.
type refKind int

const (
	refBoring refKind = iota // BoringSSL, linked with cgo
	refStd                   // crypto/sha1
)

func (k refKind) String() string {
	if k == refBoring {
		return "BoringSSL"
	}
	return "crypto/sha1"
}

// primary is the reference every check compares with: BoringSSL when it
// is linked in, crypto/sha1 otherwise.
var primary = func() refKind {
	if haveBoring {
		return refBoring
	}
	return refStd
}()

// refHash is a running hash of a reference implementation.
type refHash interface {
	write(p []byte)
	sum() [20]byte
	// appendState appends the state in crypto/sha1's marshalled format.
	appendState(b []byte) ([]byte, error)
	// setState loads a valid state in crypto/sha1's marshalled format.
	setState(st []byte)
	clone() refHash
	reset()
}

func newRef(k refKind) refHash {
	if k == refBoring {
		r := &boringRef{}
		r.c.init()
		return r
	}
	return &stdRef{stdsha1.New()}
}

// refSum is the one-shot digest of p with reference k.
func refSum(k refKind, p []byte) [20]byte {
	if k == refBoring {
		return boringSum(p)
	}
	return stdsha1.Sum(p)
}

type stdRef struct{ h hash.Hash }

func (r *stdRef) write(p []byte) { r.h.Write(p) }

func (r *stdRef) sum() (out [20]byte) {
	r.h.Sum(out[:0])
	return
}

func (r *stdRef) appendState(b []byte) ([]byte, error) {
	return r.h.(encoding.BinaryAppender).AppendBinary(b)
}

func (r *stdRef) setState(st []byte) {
	if err := r.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		panic(err)
	}
}

func (r *stdRef) clone() refHash {
	c, err := r.h.(hash.Cloner).Clone()
	if err != nil {
		panic(err)
	}
	return &stdRef{c.(hash.Hash)}
}

func (r *stdRef) reset() { r.h.Reset() }

// boringRef keeps the length in bytes next to the SHA_CTX, which only
// counts bits and so cannot hold the top three bits of the length that
// crypto/sha1's state carries.
type boringRef struct {
	c boringCtx
	n uint64
}

func (r *boringRef) write(p []byte) {
	r.c.write(p)
	r.n += uint64(len(p))
}

func (r *boringRef) sum() [20]byte { return r.c.sum() }

func (r *boringRef) appendState(b []byte) ([]byte, error) {
	var h [5]uint32
	var x [64]byte
	bits, num := r.c.get(&h, &x)
	if bits != r.n<<3 || num != int(r.n%64) {
		return b, fmt.Errorf("BoringSSL counts %d bits with %d buffered bytes after %d bytes", bits, num, r.n)
	}
	b = append(b, "sha\x01"...)
	for _, v := range h {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	b = append(b, x[:num]...)
	b = append(b, make([]byte, 64-num)...)
	return binary.BigEndian.AppendUint64(b, r.n), nil
}

func (r *boringRef) setState(st []byte) {
	var h [5]uint32
	var x [64]byte
	for i := range h {
		h[i] = binary.BigEndian.Uint32(st[4+4*i:])
	}
	copy(x[:], st[24:88])
	r.n = binary.BigEndian.Uint64(st[88:])
	r.c.set(&h, &x, r.n)
}

func (r *boringRef) clone() refHash {
	c := *r
	return &c
}

func (r *boringRef) reset() {
	r.c.init()
	r.n = 0
}

// triage annotates a failed check against BoringSSL by running it again
// against crypto/sha1, which tells a bug in the package under test from a
// reference bug.
func triage(err error, rerun func(refKind) error) error {
	if err == nil || primary == refStd {
		return err
	}
	if rerun(refStd) != nil {
		return fmt.Errorf("%w [crypto/sha1 agrees with BoringSSL]", err)
	}
	return fmt.Errorf("%w [crypto/sha1 DISAGREES with BoringSSL: check the references]", err)
}

// fillSize is the size of each filler pool: enough for the longest input
// at the largest offset.
const fillSize = 8<<20 + 4096

// Filler pools. Inputs longer than the fuzzer's bytes continue with one of
// them, so long inputs cost a copy (or nothing) instead of generating
// fresh random bytes on every execution. The random pool comes from a
// fixed seed, so failures found by TestHunt can be reproduced from their
// offsets alone.
var (
	poolRand = func() []byte {
		b := make([]byte, fillSize)
		r := rand.NewChaCha8([32]byte{'s', 'h', 'a', '1', '-', 'g', 'o'})
		r.Read(b)
		return b
	}()
	poolZero = make([]byte, fillSize)
	poolOnes = bytes.Repeat([]byte{0xff}, fillSize)
)

// filler returns the pool selected by mode.
func filler(mode uint8) []byte {
	switch mode % 4 {
	case 2:
		return poolZero
	case 3:
		return poolOnes
	}
	return poolRand
}

// expandTo fills dst with b followed by bytes of the pool selected by
// mode, starting at offset salt in the pool, and returns dst.
func expandTo(dst, b []byte, mode uint8, salt uint32) []byte {
	n := copy(dst, b)
	if n < len(dst) {
		pool := filler(mode)
		off := int(salt) % (len(pool) - (len(dst) - n) + 1)
		copy(dst[n:], pool[off:])
	}
	return dst
}

// source hands out consecutive pieces of an input stream: the fuzzer's
// bytes first, then a filler pool. Pieces are subslices of the fuzzer's
// bytes or the pool where possible, so writing even megabytes costs no
// copy; only a piece that straddles the two is copied into buf.
type source struct {
	seed []byte
	pool []byte
	salt int // pool offset of the stream position len(seed)
	pos  int
	buf  *[]byte
}

func newSource(seed []byte, mode uint8, salt uint32, buf *[]byte) source {
	return source{seed: seed, pool: filler(mode), salt: int(salt % 4096), buf: buf}
}

// next returns the next n bytes of the stream. The pool wraps around, so
// the stream never ends.
func (s *source) next(n int) []byte {
	start := s.pos
	s.pos += n
	if s.pos <= len(s.seed) {
		return s.seed[start:s.pos]
	}
	if start >= len(s.seed) {
		off := (start - len(s.seed) + s.salt) % (len(s.pool) - n + 1)
		return s.pool[off : off+n]
	}
	out := grow(s.buf, n)
	k := copy(out, s.seed[start:])
	copy(out[k:], s.pool[s.salt:])
	return out
}

// scratch holds buffers that are reused across executions, so that
// inputs of up to a few MiB do not churn the heap and the GC on every
// call.
type scratch struct {
	data, piece, stOurs, stRef, sum []byte
}

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

func getScratch() *scratch   { return scratchPool.Get().(*scratch) }
func putScratch(sc *scratch) { scratchPool.Put(sc) }

// grow returns (*p)[:n], reallocating only if *p is too small. The
// contents are not cleared.
func grow(p *[]byte, n int) []byte {
	if cap(*p) < n {
		*p = make([]byte, n)
	}
	return (*p)[:n]
}

// ownPath reports whether sha1.New returns this package's own digest
// rather than crypto/sha1's.
func ownPath() bool {
	return reflect.TypeOf(sha1.New()).Elem().PkgPath() == "github.com/crux153/sha1-go"
}

// requireOwn fails when DIFFFUZZ_REQUIRE_OWN is set and the package under
// test delegates to crypto/sha1, which the fuzz targets would then test
// instead.
func requireOwn(tb testing.TB) {
	if os.Getenv("DIFFFUZZ_REQUIRE_OWN") != "" && !ownPath() {
		tb.Fatal("sha1.New returns crypto/sha1's hash; hide AVX2 and SHA-NI with GODEBUG=cpu.avx2=off,cpu.sha=off")
	}
}

// TestPath reports which implementation sha1.New uses and the reference,
// and checks DIFFFUZZ_REQUIRE_OWN.
func TestPath(t *testing.T) {
	requireOwn(t)
	t.Logf("GODEBUG=%q, own digest: %v, reference: %v", os.Getenv("GODEBUG"), ownPath(), primary)
}

// pair is a hash from the package under test and a reference hash that
// are fed the same operations.
type pair struct {
	ours hash.Hash
	ref  refHash
}

func newPair(k refKind) pair {
	return pair{sha1.New(), newRef(k)}
}

func (p pair) write(b []byte) {
	p.ours.Write(b)
	p.ref.write(b)
}

// compareState compares the marshalled states, which include the
// chaining values, so a block function that diverges is caught before
// the final padding hides where.
func (p pair) compareState(sc *scratch) error {
	a, err := p.ours.(encoding.BinaryAppender).AppendBinary(sc.stOurs[:0])
	if err != nil {
		return fmt.Errorf("AppendBinary: %v", err)
	}
	sc.stOurs = a
	b, err := p.ref.appendState(sc.stRef[:0])
	if err != nil {
		return err
	}
	sc.stRef = b
	if !bytes.Equal(a, b) {
		return fmt.Errorf("state differs:\n got %x\nwant %x", a, b)
	}
	return nil
}

// compareSum compares Sum appended to a prefix of prefixLen bytes.
func (p pair) compareSum(sc *scratch, prefixLen int) error {
	got := p.ours.Sum(grow(&sc.sum, prefixLen))
	sc.sum = got
	if want := p.ref.sum(); !bytes.Equal(got[prefixLen:], want[:]) {
		return fmt.Errorf("Sum = %x, want %x", got[prefixLen:], want)
	}
	return nil
}

// checkSum compares Sum and a single Write with reference k on p.
func checkSum(sc *scratch, k refKind, p []byte) error {
	want := refSum(k, p)
	if got := sha1.Sum(p); got != want {
		return fmt.Errorf("Sum of %d bytes = %x, want %x", len(p), got, want)
	}
	h := sha1.New()
	h.Write(p)
	got := h.Sum(grow(&sc.sum, 3))
	sc.sum = got
	if !bytes.Equal(got[3:], want[:]) {
		return fmt.Errorf("New().Write.Sum of %d bytes = %x, want %x", len(p), got[3:], want)
	}
	return nil
}

// unmarshalErr returns the error crypto/sha1 reports for state st, which
// the package under test must match.
func unmarshalErr(st []byte) error {
	return stdsha1.New().(encoding.BinaryUnmarshaler).UnmarshalBinary(st)
}

// record writes a failing case to failures/ so it survives the log.
var recordMu sync.Mutex

func record(kind, msg string) string {
	recordMu.Lock()
	defer recordMu.Unlock()
	dir := os.Getenv("DIFFFUZZ_FAILDIR")
	if dir == "" {
		dir = "failures"
	}
	_ = os.MkdirAll(dir, 0o755)
	name := filepath.Join(dir, fmt.Sprintf("%s-%d.txt", kind, time.Now().UnixNano()))
	_ = os.WriteFile(name, []byte(msg+"\n"), 0o644)
	return name
}

// TestReferencesAgree checks BoringSSL against crypto/sha1 on every
// length up to 4 KiB and some up to 8 MiB, written whole and in pieces,
// and from random marshalled states, including lengths near 2^61 and
// 2^64 bytes where the bit count wraps. This also checks the glue that
// moves states in and out of BoringSSL's SHA_CTX.
func TestReferencesAgree(t *testing.T) {
	if !haveBoring {
		t.Skip("built without -tags difffuzz_boringssl")
	}
	for n := 0; n <= 8<<20; {
		p := poolRand[n%61 : n%61+n]
		if refSum(refBoring, p) != refSum(refStd, p) {
			t.Fatalf("one-shot digest of %d bytes differs", n)
		}
		b, s := newRef(refBoring), newRef(refStd)
		for q := p; len(q) > 0; {
			k := min(len(q), 1+n%97)
			b.write(q[:k])
			s.write(q[:k])
			q = q[k:]
		}
		if b.sum() != s.sum() {
			t.Fatalf("digest of %d bytes in pieces differs", n)
		}
		if n < 4096 {
			n++
		} else {
			n = n*5/4 + 1
		}
	}

	r := rand.New(rand.NewPCG(1, 2))
	for i := range 100000 {
		st := make([]byte, 4, 96)
		copy(st, "sha\x01")
		st = append(st, poolRand[i*7%(len(poolRand)-84):][:84]...)
		n := r.Uint64() >> (r.Uint64() % 64)
		switch i % 4 {
		case 1:
			n = 1<<61 - n%4096
		case 2:
			n = -(n % 4096)
		}
		st = binary.BigEndian.AppendUint64(st, n)
		b, s := newRef(refBoring), newRef(refStd)
		b.setState(st)
		s.setState(st)
		k := r.IntN(300)
		b.write(poolRand[:k])
		s.write(poolRand[:k])
		sb, err := b.appendState(nil)
		if err != nil {
			t.Fatal(err)
		}
		ss, _ := s.appendState(nil)
		if !bytes.Equal(sb, ss) || b.sum() != s.sum() {
			t.Fatalf("state %x after %d more bytes:\nBoringSSL   %x\ncrypto/sha1 %x", st, k, sb, ss)
		}
	}
}
