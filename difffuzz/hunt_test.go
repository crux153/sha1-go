package difffuzz

import (
	cryptorand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHunt checks inputs against the reference without the fuzzing
// engine, which has a fixed cost per execution and gets little coverage
// signal from assembly. It first sweeps every length up to sweepSum at
// every alignment 0-15 and every two-write split of every length up to
// sweepSplit, then checks random inputs until the deadline: lengths up to
// 8 MiB, alignments 0-63, up to 16 writes with intermediate sums.
//
// Enabled by HUNT=<duration>; HUNT_WORKERS sets the goroutine count
// (default GOMAXPROCS); progress goes to HUNT_LOG every minute. Inputs
// are slices of the fixed random pool, so a failure is recorded as
// offsets into it.
func TestHunt(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("HUNT"))
	if err != nil {
		t.Skip("set HUNT=<duration> to run")
	}
	requireOwn(t)
	workers := runtime.GOMAXPROCS(0)
	if w, err := strconv.Atoi(os.Getenv("HUNT_WORKERS")); err == nil && w > 0 {
		workers = w
	}
	logPath := os.Getenv("HUNT_LOG")
	if logPath == "" {
		logPath = "hunt.progress"
	}

	h := &hunt{deadline: time.Now().Add(d), start: time.Now()}
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var seed [32]byte
			cryptorand.Read(seed[:])
			seed[0] ^= byte(w)
			h.work(t, rand.New(rand.NewChaCha8(seed)))
		}()
	}
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				h.write(logPath)
			case <-done:
				return
			}
		}
	}()
	wg.Wait()
	close(done)
	h.write(logPath)
}

const (
	sweepSum   = 256 << 10
	sweepSplit = 2048
)

type hunt struct {
	deadline, start time.Time
	nextSum         atomic.Int64 // next length of the Sum sweep
	nextSplit       atomic.Int64 // next length of the split sweep
	sweepDone       atomic.Int64 // workers finished with the sweeps
	cases, bytes    atomic.Int64
	failures        atomic.Int64
}

func (h *hunt) write(path string) {
	line := fmt.Sprintf("%s elapsed=%s sweep_sum=%d/%d sweep_split=%d/%d cases=%d bytes=%d failures=%d\n",
		time.Now().Format(time.RFC3339), time.Since(h.start).Truncate(time.Second),
		min(h.nextSum.Load(), sweepSum+1), sweepSum+1, min(h.nextSplit.Load(), sweepSplit+1), sweepSplit+1,
		h.cases.Load(), h.bytes.Load(), h.failures.Load())
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		f.WriteString(line)
		f.Close()
	}
}

func (h *hunt) fail(t *testing.T, err error) {
	h.failures.Add(1)
	name := record("hunt", err.Error())
	fmt.Fprintf(os.Stderr, "HUNT FAILURE (%s): %v\n", name, err)
	t.Error(err)
}

func (h *hunt) work(t *testing.T, r *rand.Rand) {
	sc := new(scratch)
	for time.Now().Before(h.deadline) {
		n := int(h.nextSum.Add(1) - 1)
		if n > sweepSum {
			break
		}
		for off := range 16 {
			p := poolRand[off : off+n]
			check := func(k refKind) error { return checkSum(sc, k, p) }
			if err := triage(check(primary), check); err != nil {
				h.fail(t, fmt.Errorf("sweep: pool[%d:%d]: %v", off, off+n, err))
			}
		}
		h.cases.Add(16)
		h.bytes.Add(int64(16 * n))
	}
	for time.Now().Before(h.deadline) {
		n := int(h.nextSplit.Add(1) - 1)
		if n > sweepSplit {
			break
		}
		off := n % 16
		var cuts [1]int
		for s := 0; s <= n; s++ {
			cuts[0] = s
			run := func(k refKind) error { return checkWrites(sc, k, off, n, cuts[:], -1) }
			if err := triage(run(primary), run); err != nil {
				h.fail(t, fmt.Errorf("sweep: pool[%d:%d] split at %d: %v", off, off+n, s, err))
			}
		}
		h.cases.Add(int64(n + 1))
		h.bytes.Add(int64(n * (n + 1)))
	}
	cuts := make([]int, 0, 16)
	for time.Now().Before(h.deadline) {
		var n int
		switch x := r.IntN(10); {
		case x < 5:
			n = r.IntN(4097)
		case x < 8:
			n = r.IntN(256<<10 + 1)
		default:
			n = r.IntN(8<<20 + 1)
		}
		off := r.IntN(64)
		cuts = cuts[:0]
		for range r.IntN(16) {
			cuts = append(cuts, r.IntN(n+1))
		}
		slices.Sort(cuts)
		mid := r.IntN(len(cuts) + 1)
		run := func(k refKind) error { return checkWrites(sc, k, off, n, cuts, mid) }
		if err := triage(run(primary), run); err != nil {
			h.fail(t, fmt.Errorf("random: pool[%d:%d] cuts %v, sum after %d: %v", off, off+n, cuts, mid, err))
		}
		h.cases.Add(1)
		h.bytes.Add(int64(n))
	}
}

// checkWrites writes poolRand[off:off+n] split at the sorted offsets
// cuts, compares the state after write number mid (if any), and compares
// the final digest; a single cut also checks Sum.
func checkWrites(sc *scratch, k refKind, off, n int, cuts []int, mid int) error {
	p := poolRand[off : off+n]
	pr := newPair(k)
	last := 0
	for i, c := range cuts {
		pr.write(p[last:c])
		last = c
		if i == mid {
			if err := pr.compareState(sc); err != nil {
				return fmt.Errorf("after %d bytes: %v", c, err)
			}
		}
	}
	pr.write(p[last:])
	return pr.compareSum(sc, 0)
}
