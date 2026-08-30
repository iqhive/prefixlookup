package tests_test

import (
	"sync/atomic"
	"testing"

	"github.com/iqhive/prefixlookup/internal/benchutil"
)

// TestParallelRangesCoverEachOperationOnce is our "did we actually shard the
// work correctly" check for benchutil.RunParallelRanges - we pretend we've got
// a slightly awkward operation count (10_003, not a nice power of two) and
// walk a handful of worker counts so we catch both the 1-worker trivial split
// and the "way more workers than ops" case
//
// we hand each op an atomic slot, bump it from the callback, then insist every
// slot is exactly 1 and the completed count matches - that's the whole
// contract, no fancy fixtures
func TestParallelRangesCoverEachOperationOnce(t *testing.T) {
	const operations = 10_003
	for _, workers := range []int{1, 4, 8, 32, 64} {
		// one counter per op so we can see double-fires without a map
		seen := make([]atomic.Uint32, operations)
		completed := benchutil.RunParallelRanges(operations, workers, func(operation uint64, _ int) {
			seen[operation].Add(1)
		})
		if completed != operations {
			t.Fatalf("%d workers completed %d operations, want %d", workers, completed, operations)
		}
		for operation := range seen {
			if count := seen[operation].Load(); count != 1 {
				t.Fatalf("%d workers executed operation %d %d times", workers, operation, count)
			}
		}
	}
}
