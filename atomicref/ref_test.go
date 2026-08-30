package atomicref_test

import (
	"testing"

	"github.com/iqhive/prefixlookup/atomicref"
)

// TestPublication just checks the obvious Store/Load swap
// if this fails the atomic.Pointer wrapper is broken and everything above it is toast
func TestPublication(t *testing.T) {
	a, b := 1, 2
	// start on a
	ref := atomicref.New(&a)
	if got := *ref.Load(); got != 1 {
		t.Fatalf("Load() = %d, want 1", got)
	}
	// swap to b, readers should see it immediately
	ref.Store(&b)
	if got := *ref.Load(); got != 2 {
		t.Fatalf("Load() = %d, want 2", got)
	}
}
