package difffuzz

import (
	"sync"
	"syscall"
)

// guarded is a region of memory between two inaccessible pages, so that a
// read even one byte outside an input placed at either end of the region
// crashes. Each fuzz worker process uses it from one goroutine at a time.
var guarded struct {
	sync.Mutex
	region []byte
}

// guardedSlice returns an n-byte slice that starts right after an
// inaccessible page (atEnd false) or ends right before one (atEnd true),
// or nil if the region cannot be mapped or n is too large. The caller
// must hold guarded's lock while it uses the slice.
func guardedSlice(n int, atEnd bool) []byte {
	if guarded.region == nil {
		page := syscall.Getpagesize()
		size := (fillSize + page - 1) &^ (page - 1)
		mem, err := syscall.Mmap(-1, 0, size+2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			return nil
		}
		if syscall.Mprotect(mem[:page], syscall.PROT_NONE) != nil ||
			syscall.Mprotect(mem[page+size:], syscall.PROT_NONE) != nil {
			return nil
		}
		guarded.region = mem[page : page+size : page+size]
	}
	if n > len(guarded.region) {
		return nil
	}
	if atEnd {
		return guarded.region[len(guarded.region)-n:]
	}
	return guarded.region[:n:n]
}
