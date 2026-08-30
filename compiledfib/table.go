// Package compiledfib is the managed, versioned wrapper around a compiled
// block-LPM index plus copy-on-write payload pages
//
// one writer goroutine, readers do one atomic load. payload-only updates share
// the index, structural ones rebuild. we got the name from the old compiled
// FIB experiments and then never renamed it
package compiledfib

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iqhive/prefixlookup/internal/routepages"
	blockindex "github.com/iqhive/prefixlookup/old/blocklpm"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// ErrClosed is what Submit hands back once Close has started
var ErrClosed = errors.New("compiledfib: table closed")

// generation is one immutable published snapshot
// index is the LPM, payloads are paged values, routes maps prefix->id so we
// can decide payload-vs-structural without enumerating
type generation[V any] struct {
	index      *blockindex.Table[routeid.ID]
	payloads   *routepages.Pages[V]
	routes     map[netip.Prefix]routeid.ID
	generation uint64
}

// request is one Submit sitting on the writer queue
// done is buffered so the writer never blocks on the caller
type request[V any] struct {
	mutations []routeupdate.Mutation[V]
	done      chan routeupdate.Result
}

// Stats is successful publications split by kind
// payload means we reused the index, structural means we rebuilt it
type Stats struct {
	PayloadPublications    uint64
	StructuralPublications uint64
}

// Table is a lock-free lookup table with one dedicated writer goroutine
// readers Load current, writers enqueue onto queue. closeOnce so Close is idempotent
type Table[V any] struct {
	current atomic.Pointer[generation[V]]
	queue   chan request[V]
	stop    chan struct{}
	done    chan struct{}
	options routeupdate.Options

	submitMu  sync.Mutex
	closed    bool
	closeOnce sync.Once

	payloadPublications    atomic.Uint64
	structuralPublications atomic.Uint64
}

// New builds the initial immutable generation and starts the writer
// duplicate normalised prefixes: last value in entries wins. we catalogue into
// a map, buildGeneration, then kick off manage
func New[V any](entries []prefixentry.Entry[V], options routeupdate.Options) (*Table[V], error) {
	catalog := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		catalog[prefix] = entry.Value
	}
	g, err := buildGeneration(catalog, 1)
	if err != nil {
		return nil, err
	}
	options = options.Normalize()
	t := &Table[V]{
		queue:   make(chan request[V], options.QueueSize),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		options: options,
	}
	t.current.Store(g)
	go t.manage(catalog)
	return t, nil
}

// Lookup does lock-free LPM
// one atomic load, index.Lookup, then payloads.Get. miss returns zero V
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	g := t.current.Load()
	id, ok := g.index.Lookup(addr)
	if !ok {
		var zero V
		return zero, false
	}
	return g.payloads.Get(id), true
}

// Lookup4 is the decoded IPv4 fast path
// same as Lookup but we skip netip.Addr and go straight to the uint32 index
func (t *Table[V]) Lookup4(addr uint32) (V, bool) {
	g := t.current.Load()
	id, ok := g.index.Lookup4(addr)
	if !ok {
		var zero V
		return zero, false
	}
	return g.payloads.Get(id), true
}

// Lookup6 is the decoded IPv6 fast path
// hi/lo already unpacked, we don't touch netip on the hot path
func (t *Table[V]) Lookup6(hi, lo uint64) (V, bool) {
	g := t.current.Load()
	id, ok := g.index.Lookup6(hi, lo)
	if !ok {
		var zero V
		return zero, false
	}
	return g.payloads.Get(id), true
}

// Generation returns the currently published generation number
// just Load().generation, readers use this to notice a swap
func (t *Table[V]) Generation() uint64 { return t.current.Load().generation }

// ApplyBatch submits mutations and waits until their generation is published
// it's Submit plus a receive, we don't have a separate sync path
func (t *Table[V]) ApplyBatch(mutations []routeupdate.Mutation[V]) error {
	return (<-t.Submit(mutations)).Err
}

// Submit queues mutations for async publication
// we normalise prefixes first, reject junk immediately, then lock submitMu
// so we can't race Close. invalid/closed get an immediate result on the
// buffered done channel
func (t *Table[V]) Submit(mutations []routeupdate.Mutation[V]) <-chan routeupdate.Result {
	done := make(chan routeupdate.Result, 1)
	normalized := make([]routeupdate.Mutation[V], len(mutations))
	for i, mutation := range mutations {
		prefix, ok := prefixentry.NormalizePrefix(mutation.Prefix)
		if !ok {
			done <- routeupdate.Result{Generation: t.Generation(), Err: prefixentry.ErrBadIP}
			close(done)
			return done
		}
		normalized[i] = mutation
		normalized[i].Prefix = prefix
	}

	t.submitMu.Lock()
	if t.closed {
		t.submitMu.Unlock()
		done <- routeupdate.Result{Generation: t.Generation(), Err: ErrClosed}
		close(done)
		return done
	}
	t.queue <- request[V]{mutations: normalized, done: done}
	t.submitMu.Unlock()
	return done
}

// Close stops accepting updates and waits for queued work to publish
// safe to call more than once: closeOnce flips closed and closes stop, then
// we wait on done which manage closes on the way out
func (t *Table[V]) Close() {
	t.closeOnce.Do(func() {
		t.submitMu.Lock()
		t.closed = true
		close(t.stop)
		t.submitMu.Unlock()
	})
	<-t.done
}

// Stats returns a point-in-time publication count
// two atomic loads, no lock
func (t *Table[V]) Stats() Stats {
	return Stats{
		PayloadPublications:    t.payloadPublications.Load(),
		StructuralPublications: t.structuralPublications.Load(),
	}
}

// manage is the writer loop
// we sit on queue/stop, coalesce with collect, publish, and on stop we drain
// whatever's left with collectQueued then return
func (t *Table[V]) manage(catalog map[netip.Prefix]V) {
	defer close(t.done)
	for {
		select {
		case first := <-t.queue:
			catalog = t.publish(catalog, t.collect(first))
		case <-t.stop:
			for {
				select {
				case first := <-t.queue:
					catalog = t.publish(catalog, t.collectQueued(first))
				default:
					return
				}
			}
		}
	}
}

// collect gathers a batch starting with first
// if MaxBatchDelay is zero we just drain what's already queued, otherwise we
// wait up to the delay or MaxBatchSize. stop during the wait flushes queued
func (t *Table[V]) collect(first request[V]) []request[V] {
	batch := []request[V]{first}
	if t.options.MaxBatchDelay <= 0 {
		return t.appendQueued(batch)
	}
	timer := time.NewTimer(t.options.MaxBatchDelay)
	defer timer.Stop()
	for len(batch) < t.options.MaxBatchSize {
		select {
		case req := <-t.queue:
			batch = append(batch, req)
		case <-timer.C:
			return batch
		case <-t.stop:
			return t.appendQueued(batch)
		}
	}
	return batch
}

// collectQueued is collect without the delay, used while draining on Close
func (t *Table[V]) collectQueued(first request[V]) []request[V] {
	return t.appendQueued([]request[V]{first})
}

// appendQueued non-blockingly drains queue onto batch until MaxBatchSize
// default branch of the select is how we stop without waiting
func (t *Table[V]) appendQueued(batch []request[V]) []request[V] {
	for len(batch) < t.options.MaxBatchSize {
		select {
		case req := <-t.queue:
			batch = append(batch, req)
		default:
			return batch
		}
	}
	return batch
}

// publish applies a coalesced batch and stores the new generation
// last mutation per prefix wins. if any prefix is added or deleted we rebuild
// the whole index (structural), otherwise we just With() the payload pages
func (t *Table[V]) publish(catalog map[netip.Prefix]V, batch []request[V]) map[netip.Prefix]V {
	current := t.current.Load()
	mutations := make(map[netip.Prefix]routeupdate.Mutation[V])
	for _, req := range batch {
		for _, mutation := range req.mutations {
			mutations[mutation.Prefix] = mutation
		}
	}

	structural := false
	for prefix, mutation := range mutations {
		_, exists := current.routes[prefix]
		if exists == mutation.Delete {
			structural = true
			break
		}
	}

	var next *generation[V]
	var err error
	var nextCatalog map[netip.Prefix]V
	if structural {
		nextCatalog = cloneCatalog(catalog)
		for prefix, mutation := range mutations {
			if mutation.Delete {
				delete(nextCatalog, prefix)
			} else {
				nextCatalog[prefix] = mutation.Value
			}
		}
		next, err = buildGeneration(nextCatalog, current.generation+1)
	} else {
		updates := make(map[routeid.ID]V, len(mutations))
		for prefix, mutation := range mutations {
			if !mutation.Delete {
				updates[current.routes[prefix]] = mutation.Value
			}
		}
		payloads := current.payloads
		if len(updates) != 0 {
			payloads = payloads.With(updates, routeid.ID(len(current.routes)))
		}
		next = &generation[V]{
			index:      current.index,
			payloads:   payloads,
			routes:     current.routes,
			generation: current.generation + 1,
		}
	}
	result := routeupdate.Result{Generation: current.generation, Err: err}
	if err == nil {
		t.current.Store(next)
		result.Generation = next.generation
		if structural {
			t.structuralPublications.Add(1)
		} else {
			t.payloadPublications.Add(1)
			for prefix, mutation := range mutations {
				if !mutation.Delete {
					catalog[prefix] = mutation.Value
				}
			}
		}
		if structural {
			catalog = nextCatalog
		}
	}
	for _, req := range batch {
		req.done <- result
		close(req.done)
	}
	return catalog
}

// buildGeneration compiles the catalogue into an immutable generation numbered number
// we sort prefixes (addr then bits), assign dense routeid.IDs from 1, then
// hand the ID-valued entries to blocklpm
func buildGeneration[V any](catalog map[netip.Prefix]V, number uint64) (*generation[V], error) {
	prefixes := make([]netip.Prefix, 0, len(catalog))
	for prefix := range catalog {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr() == prefixes[j].Addr() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
	routes := make(map[netip.Prefix]routeid.ID, len(prefixes))
	values := make(map[routeid.ID]V, len(prefixes))
	indexed := make([]prefixentry.Entry[routeid.ID], len(prefixes))
	for i, prefix := range prefixes {
		id := routeid.ID(i + 1)
		routes[prefix] = id
		values[id] = catalog[prefix]
		indexed[i] = prefixentry.Entry[routeid.ID]{Prefix: prefix, Value: id}
	}
	// index, err := New(indexed, routeupdate.Options{})
	index, err := blockindex.New(indexed)
	if err != nil {
		return nil, err
	}
	return &generation[V]{
		index:      index,
		payloads:   routepages.New(values, routeid.ID(len(prefixes))),
		routes:     routes,
		generation: number,
	}, nil
}

// cloneCatalog shallow-copies a prefix->value map
// used before a structural rebuild so we don't mutate the live catalogue on failure
func cloneCatalog[V any](catalog map[netip.Prefix]V) map[netip.Prefix]V {
	clone := make(map[netip.Prefix]V, len(catalog))
	for prefix, value := range catalog {
		clone[prefix] = value
	}
	return clone
}
