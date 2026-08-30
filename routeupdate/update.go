// Package routeupdate is the mutation/batching bits shared by the managed tables
//
// we got tired of each table inventing its own Apply options so this is the common shape
package routeupdate

import (
	"net/netip"
	"time"
)

// Mutation is one insert/replace or delete against a prefix
// Delete=true means yank it, otherwise Value is the new payload
type Mutation[V any] struct {
	Prefix netip.Prefix
	Value  V
	Delete bool
}

// Options is how the writer goroutine batches work
// leave them zero and Normalize fills in the defaults we actually run with
type Options struct {
	// QueueSize is how many requests can sit waiting for the writer
	QueueSize int
	// MaxBatchSize caps how many we coalesce into one publish
	// zero becomes 64
	MaxBatchSize int
	// MaxBatchDelay is a short wait after the first request in case more turn up
	// zero means just drain what's already queued and publish
	MaxBatchDelay time.Duration
}

// normalized fills in the defaults we use when someone passes a zero Options
// QueueSize 256 / MaxBatchSize 64, delay stays zero unless they set it
func (o Options) normalized() Options {
	if o.QueueSize <= 0 {
		// enough that a burst doesn't stall Submit
		o.QueueSize = 256
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = 64
	}
	return o
}

// Normalize is the exported wrapper around normalized
// call this once at New, not on the hot path
func (o Options) Normalize() Options { return o.normalized() }

// Result comes back on the done channel after a batch actually publishes
// Generation is the number that landed, Err is set if the writer bailed
type Result struct {
	Generation uint64
	Err        error
}
