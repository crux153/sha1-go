package difffuzz

import (
	"bytes"
	stdsha1 "crypto/sha1"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"testing"

	sha1 "github.com/crux153/sha1-go"
)

// maxSum is the longest input FuzzSum builds.
const maxSum = 4 << 20

// FuzzSum: Sum and a single Write against the reference. With flags&1,
// ext stretches the input to up to 4 MiB (see stretch) with filler
// selected by flags>>3.
// The input is placed at offset off%64 of a buffer, or (flags>>1&3 = 1 or
// 2) right before or right after an inaccessible page, so that a read
// past either end of the input crashes.
func FuzzSum(f *testing.F) {
	requireOwn(f)
	f.Add([]byte(""), uint8(0), uint8(0), uint32(0))
	f.Add([]byte("abc"), uint8(1), uint8(2), uint32(0))
	f.Add(bytes.Repeat([]byte{0xa5}, 55), uint8(2), uint8(4), uint32(0))
	f.Add([]byte("x"), uint8(3), uint8(1|2), uint32(64*1000+63))
	f.Add([]byte("y"), uint8(5), uint8(1|4|8), uint32(1<<20))
	f.Add([]byte("z"), uint8(9), uint8(1|16), uint32(maxSum-1))
	f.Fuzz(func(t *testing.T, data []byte, off, flags uint8, ext uint32) {
		sc := getScratch()
		defer putScratch(sc)
		n := min(len(data), maxSum)
		if flags&1 != 0 {
			n = stretch(ext, maxSum)
		}
		var p []byte
		switch flags >> 1 & 3 {
		case 1, 2:
			guarded.Lock()
			defer guarded.Unlock()
			p = guardedSlice(n, flags>>1&3 == 1)
		}
		if p == nil {
			k := int(off % 64)
			p = grow(&sc.data, k+n)[k:]
		}
		expandTo(p, data, flags>>3, ext)
		check := func(k refKind) error { return checkSum(sc, k, p) }
		if err := triage(check(primary), check); err != nil {
			t.Fatalf("offset %d, placement %d: %v", off%64, flags>>1&3, err)
		}
	})
}

// FuzzOps feeds the same sequence of operations to a hash from the
// package under test and to the reference, and compares the marshalled
// states after every operation. Each operation is two bytes: op&7 picks
// it and op>>3 and arg parameterize it.
//
//   - 0, 1: Write a piece of the input stream (seed, then filler) of up to
//     255 bytes, 255 blocks, 255 blocks plus a tail, or about 1 MiB.
//   - 2: Sum appended to a prefix.
//   - 3: Clone, write to the original, and continue with the clone.
//   - 4: move the state through MarshalBinary or AppendBinary into
//     crypto/sha1 and back into a new hash.
//   - 5: Reset.
//   - 6: Write nil and an empty slice; check Size and BlockSize.
//   - 7: UnmarshalBinary of a corrupt state, which must fail with
//     crypto/sha1's error and leave the state alone.
func FuzzOps(f *testing.F) {
	requireOwn(f)
	f.Add([]byte("seed"), uint8(0), uint32(0), []byte{0, 3, 2, 0})
	f.Add([]byte("seed"), uint8(1), uint32(7), []byte{0, 0x45, 2, 7, 3, 9, 0, 1 << 3, 4, 0, 0, 200, 2, 0})
	f.Add([]byte("hello"), uint8(2), uint32(99), []byte{8, 17, 0, 63, 3 << 3, 2, 4, 0, 5, 0, 1, 64, 7, 3, 2, 1})
	f.Add([]byte("big"), uint8(0), uint32(1), []byte{3 << 3, 255, 2, 0, 1 << 3, 255, 4, 0, 2, 0})
	f.Fuzz(func(t *testing.T, seed []byte, mode uint8, salt uint32, ops []byte) {
		sc := getScratch()
		defer putScratch(sc)
		run := func(k refKind) error { return runOps(sc, k, seed, mode, salt, ops) }
		if err := triage(run(primary), run); err != nil {
			t.Fatal(err)
		}
	})
}

func runOps(sc *scratch, k refKind, seed []byte, mode uint8, salt uint32, ops []byte) error {
	src := newSource(seed, mode, salt, &sc.piece)
	p := newPair(k)
	for i := 0; i+1 < len(ops) && i < 1024; i += 2 {
		op, ex, arg := ops[i]&7, int(ops[i]>>3), int(ops[i+1])
		switch op {
		case 0, 1:
			p.write(src.next(writeSize(ex, arg)))
		case 2:
			if err := p.compareSum(sc, ex&7); err != nil {
				return fmt.Errorf("op %d: %v", i/2, err)
			}
		case 3:
			c, err := p.ours.(hash.Cloner).Clone()
			if err != nil {
				return err
			}
			junk := src.next(arg)
			p.ours.Write(junk)
			p.ours.Write(junk)
			p = pair{c.(hash.Hash), p.ref.clone()}
		case 4:
			h, err := throughStd(p.ours, ex)
			if err != nil {
				return fmt.Errorf("op %d: %v", i/2, err)
			}
			p.ours = h
		case 5:
			p.ours.Reset()
			p.ref.reset()
		case 6:
			p.ours.Write(nil)
			p.ours.Write([]byte{})
			if p.ours.Size() != sha1.Size || p.ours.BlockSize() != sha1.BlockSize {
				return fmt.Errorf("Size %d, BlockSize %d", p.ours.Size(), p.ours.BlockSize())
			}
		case 7:
			st, err := p.ref.appendState(sc.data[:0])
			if err != nil {
				return err
			}
			sc.data = st
			bad := corrupt(st, ex, arg)
			if err := checkUnmarshalErr(p.ours, bad); err != nil {
				return fmt.Errorf("op %d: %v", i/2, err)
			}
		}
		if err := p.compareState(sc); err != nil {
			return fmt.Errorf("after op %d (%d): %v", i/2, op, err)
		}
	}
	if err := p.compareSum(sc, 0); err != nil {
		return fmt.Errorf("final: %v", err)
	}
	return nil
}

// stretch maps ext to a length below max, a power of two: the low bits
// give the length and the top five bits shift it right, so short lengths
// are about as common as long ones of each order of magnitude.
func stretch(ext uint32, max int) int {
	return int(ext&uint32(max-1)) >> ((ext >> 27) % 24)
}

// writeSize maps an operation's parameters to a write size. Exact
// multiples of the block size and sizes just off them are common, so that
// the buffered and direct paths of Write meet at every offset.
func writeSize(ex, arg int) int {
	switch ex & 3 {
	case 0:
		return arg
	case 1:
		return arg * 64
	case 2:
		return arg*64 + ex>>2
	}
	return arg<<12 + (ex>>2)*67
}

// throughStd moves the state of h into crypto/sha1 and back into a new
// hash of the package under test, which checks that the two packages
// read each other's states; ex&1 selects MarshalBinary or AppendBinary
// to a prefix.
func throughStd(h hash.Hash, ex int) (hash.Hash, error) {
	marshal := func(h hash.Hash) ([]byte, error) {
		if ex&1 == 0 {
			return h.(encoding.BinaryMarshaler).MarshalBinary()
		}
		b, err := h.(encoding.BinaryAppender).AppendBinary([]byte{1, 2, 3})
		if len(b) < 3 || !bytes.Equal(b[:3], []byte{1, 2, 3}) {
			return nil, fmt.Errorf("AppendBinary clobbered its prefix: %x", b)
		}
		return b[3:], err
	}
	st, err := marshal(h)
	if err != nil {
		return nil, err
	}
	std := stdsha1.New()
	if err := std.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		return nil, fmt.Errorf("crypto/sha1 rejects state %x: %v", st, err)
	}
	st2, err := marshal(std)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(st, st2) {
		return nil, fmt.Errorf("state changed in crypto/sha1:\n got %x\nwant %x", st2, st)
	}
	h2 := sha1.New()
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(st2); err != nil {
		return nil, fmt.Errorf("UnmarshalBinary(%x): %v", st2, err)
	}
	return h2, nil
}

// corrupt modifies a marshalled state in place, or returns a shortened or
// extended one, so that it has a wrong identifier or size.
func corrupt(st []byte, ex, arg int) []byte {
	switch ex % 3 {
	case 0:
		st[arg%4] ^= 1 << (ex >> 2 & 7)
		return st
	case 1:
		return st[:arg%len(st)]
	}
	return append(st, byte(arg))
}

// checkUnmarshalErr checks that h rejects the corrupt state bad with the
// error crypto/sha1 reports.
func checkUnmarshalErr(h hash.Hash, bad []byte) error {
	want := unmarshalErr(bad)
	got := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(bad)
	if want == nil {
		return errors.New("difffuzz: corrupt state accepted by crypto/sha1")
	}
	if got == nil || got.Error() != want.Error() {
		return fmt.Errorf("UnmarshalBinary(%x) = %v, want %v", bad, got, want)
	}
	return nil
}

// FuzzState starts from an arbitrary marshalled state: arbitrary chaining
// values, buffered bytes and length, with the length optionally just
// below 2^29, 2^61 or 2^64 bytes, where the bit count crosses 2^32 or
// wraps. It then writes up to 256 KiB (see stretch) in pieces sized by splits and
// compares the states after every write. Writing whole blocks compares
// the block functions directly on arbitrary chaining values. With
// kind>>2&3 != 0 the state is corrupted instead and must be rejected with
// crypto/sha1's error.
func FuzzState(f *testing.F) {
	requireOwn(f)
	f.Add([]byte("h"), []byte("x"), uint64(0), uint8(0), []byte("data"), []byte{}, uint32(0))
	f.Add([]byte("h"), []byte("x"), uint64(55), uint8(1), []byte("data"), []byte{1, 63}, uint32(200))
	f.Add([]byte("h"), []byte("x"), uint64(9), uint8(2), []byte("d"), []byte{64, 0, 3}, uint32(4096))
	f.Add([]byte("h"), []byte("x"), uint64(1), uint8(3), []byte("d"), []byte{255, 255}, uint32(70000))
	f.Add([]byte("h"), []byte("x"), uint64(3), uint8(1<<2), []byte("d"), []byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, hb, xb []byte, length uint64, kind uint8, seed, splits []byte, ext uint32) {
		sc := getScratch()
		defer putScratch(sc)
		switch kind & 3 {
		case 1:
			length = 1<<29 - length&0xfff
		case 2:
			length = 1<<61 - length&0xfff
		case 3:
			length = -(length & 0xfff)
		}
		st := expandTo(grow(&sc.data, 96)[:88], nil, 0, uint32(length))
		copy(st, "sha\x01")
		copy(st[4:24], hb)
		copy(st[24:88], xb)
		st = binary.BigEndian.AppendUint64(st, length)
		if c := kind >> 2 & 3; c != 0 {
			if err := checkUnmarshalErr(sha1.New(), corrupt(st, int(c-1), int(ext))); err != nil {
				t.Fatal(err)
			}
			return
		}
		run := func(k refKind) error { return runState(sc, k, st, kind>>4, seed, splits, ext) }
		if err := triage(run(primary), run); err != nil {
			t.Fatal(err)
		}
	})
}

func runState(sc *scratch, k refKind, st []byte, mode uint8, seed, splits []byte, ext uint32) error {
	p := newPair(k)
	if err := p.ours.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		return err
	}
	p.ref.setState(st)
	if err := p.compareState(sc); err != nil {
		return fmt.Errorf("after UnmarshalBinary: %v", err)
	}
	src := newSource(seed, mode, ext, &sc.piece)
	left := stretch(ext, 256<<10)
	for j := 0; left > 0; j++ {
		n := left
		if j < len(splits) {
			n = min(writeSize(int(splits[j]>>6), int(splits[j]&63)<<2|j&3), left)
		}
		p.write(src.next(n))
		left -= n
		if err := p.compareState(sc); err != nil {
			return fmt.Errorf("after write %d (%d bytes): %v", j, n, err)
		}
	}
	if err := p.compareSum(sc, 0); err != nil {
		return err
	}
	if err := p.compareSum(sc, 1); err != nil {
		return fmt.Errorf("second Sum: %v", err)
	}
	return nil
}
