//go:build !linux

package difffuzz

import "sync"

var guarded sync.Mutex

func guardedSlice(n int, atEnd bool) []byte { return nil }
