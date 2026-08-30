// Package benchutil contains shared benchmark work-distribution helpers
package benchutil

import (
	"sync"
	"sync/atomic"
)

// RunParallelRanges visits every operation in [0, operations) exactly once
// across workers goroutines and returns the completed operation count - workers
// grab 256-op batches off an atomic cursor so we don't bounce on a mutex, then
// we close(start) so they all enter the loop together
func RunParallelRanges(operations, workers int, visit func(operation uint64, worker int)) uint64 {
	if operations <= 0 || workers <= 0 {
		// nothing to do, don't spawn
		return 0
	}
	const batchSize = uint64(256)
	var next atomic.Uint64
	var completed atomic.Uint64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		// one worker: claim 256-op batches off next until we're past operations
		go func(id int) {
			defer wg.Done()
			<-start
			for {
				// claim a batch; Add returns the new cursor so we subtract to get first
				first := next.Add(batchSize) - batchSize
				if first >= uint64(operations) {
					return
				}
				last := min(first+batchSize, uint64(operations))
				for operation := first; operation < last; operation++ {
					visit(operation, id)
				}
				completed.Add(last - first)
			}
		}(worker)
	}
	// let them all in at once so the timed region isn't the spawn
	close(start)
	wg.Wait()
	return completed.Load()
}
