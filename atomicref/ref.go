// Package atomicref is a tiny wrapper around atomic.Pointer for publishing immutable gens
//
// we use this when we don't want a full managed writer, just "swap the whole thing"
package atomicref

import "sync/atomic"

// Ref publishes one immutable value with a single atomic store
// readers should Load once and hang onto the pointer for the whole query, don't reload mid-walk
type Ref[T any] struct {
	current atomic.Pointer[T]
}

// New stands up a publication point already holding value
// just Store into a fresh Ref, nothing else to set up
func New[T any](value *T) *Ref[T] {
	r := &Ref[T]{}
	// publish before we hand it out so the first Load can't see nil
	r.current.Store(value)
	return r
}

// Load is the reader side, one atomic load
// keep the result, don't call this again in the same lookup
func (r *Ref[T]) Load() *T { return r.current.Load() }

// Store publishes a fully built generation
// caller has to have finished building value first, we don't copy
func (r *Ref[T]) Store(value *T) { r.current.Store(value) }
