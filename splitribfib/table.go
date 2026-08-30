// Package splitribfib is a managed table with separate immutable FIB and RIB
// indexes, published together
//
// lookups go through compiledfib, hierarchy walks through bitwalk. one writer
// goroutine, readers do one atomic load. payload updates share both indexes
package splitribfib

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/internal/routepages"
	"github.com/iqhive/prefixlookup/old/bitwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// ErrClosed is what Submit hands back once Close has started
var ErrClosed = errors.New("splitribfib: table closed")

// generation is one immutable published snapshot
// fib for LPM, rib for parent/descendant walks, ids maps prefix->id, payloads
// are paged values. maxID is the dense id ceiling for With()
type generation[V any] struct {
	number   uint64
	fib      *compiledfib.Table[routeid.ID]
	rib      *bitwalk.Table[routeid.ID]
	ids      map[netip.Prefix]routeid.ID
	payloads *routepages.Pages[V]
	maxID    routeid.ID
}

// request is one Submit sitting on the writer queue
type request[V any] struct {
	mutations []routeupdate.Mutation[V]
	done      chan routeupdate.Result
}

// Table manages immutable RIB/FIB generations
// reads do one atomic load and never sync with the writer goroutine
type Table[V any] struct {
	current atomic.Pointer[generation[V]]
	queue   chan request[V]
	stop    chan struct{}
	done    chan struct{}
	opts    routeupdate.Options

	submitMu  sync.Mutex
	closed    bool
	closeOnce sync.Once
}

// New builds the initial generation and starts the update writer
// duplicate prefixes: last value in entries wins. we catalogue, build, Store,
// then kick off writer
func New[V any](entries []prefixentry.Entry[V], options routeupdate.Options) (*Table[V], error) {
	values := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		values[prefix] = entry.Value
	}

	initial, err := buildGeneration(values, 1)
	if err != nil {
		return nil, err
	}
	options = options.Normalize()
	t := &Table[V]{
		queue: make(chan request[V], options.QueueSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		opts:  options,
	}
	t.current.Store(initial)
	go t.writer()
	return t, nil
}

// Lookup returns the LPM from one immutable generation
// Load, fib.Lookup, then generationResult to fetch the payload
func (t *Table[V]) Lookup(addr netip.Addr) (routeid.ID, V, bool) {
	g := t.current.Load()
	id, ok := g.fib.Lookup(addr)
	return generationResult(g, id, ok)
}

// Lookup4 is the decoded IPv4 fast path
// same as Lookup, uint32 instead of netip.Addr
func (t *Table[V]) Lookup4(addr uint32) (routeid.ID, V, bool) {
	g := t.current.Load()
	id, ok := g.fib.Lookup4(addr)
	return generationResult(g, id, ok)
}

// Lookup6 is the decoded IPv6 fast path
// hi/lo already unpacked
func (t *Table[V]) Lookup6(hi, lo uint64) (routeid.ID, V, bool) {
	g := t.current.Load()
	id, ok := g.fib.Lookup6(hi, lo)
	return generationResult(g, id, ok)
}

// generationResult turns an id+ok from the FIB into (id, payload, ok)
// miss returns zero V, we don't touch payloads
func generationResult[V any](g *generation[V], id routeid.ID, ok bool) (routeid.ID, V, bool) {
	if ok {
		return id, g.payloads.Get(id), true
	}
	var zero V
	return 0, zero, false
}

// WalkParents visits matching routes from most-specific to least-specific
// we Load once then walk the RIB, fetching payloads as we go
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(routeid.ID, netip.Prefix, V) bool) {
	g := t.current.Load()
	g.rib.WalkParents(addr, func(prefix netip.Prefix, id routeid.ID) bool {
		return yield(id, prefix, g.payloads.Get(id))
	})
}

// WalkDescendants visits an exact route and all recursively contained routes
// same Load-once pattern as WalkParents
func (t *Table[V]) WalkDescendants(prefix netip.Prefix, yield func(routeid.ID, netip.Prefix, V) bool) bool {
	g := t.current.Load()
	return g.rib.WalkDescendants(prefix, func(found netip.Prefix, id routeid.ID) bool {
		return yield(id, found, g.payloads.Get(id))
	})
}

// Generation returns the currently published generation number
func (t *Table[V]) Generation() uint64 { return t.current.Load().number }

// ApplyBatch submits mutations to the writer and waits for publication
// mutations are applied in order, later mutations for a prefix win
func (t *Table[V]) ApplyBatch(mutations []routeupdate.Mutation[V]) error {
	return (<-t.Submit(mutations)).Err
}

// Submit queues mutations and returns a channel that receives exactly one result
// we copy/normalise the slice before returning. junk prefixes and Close get an
// immediate result on the buffered channel
func (t *Table[V]) Submit(mutations []routeupdate.Mutation[V]) <-chan routeupdate.Result {
	done := make(chan routeupdate.Result, 1)
	normalized, err := normalizeMutations(mutations)
	if err != nil {
		done <- routeupdate.Result{Generation: t.Generation(), Err: err}
		close(done)
		return done
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

// Close stops the writer after processing every accepted request
// safe to call more than once: closeOnce, then wait on done
func (t *Table[V]) Close() {
	t.closeOnce.Do(func() {
		t.submitMu.Lock()
		t.closed = true
		close(t.stop)
		t.submitMu.Unlock()
	})
	<-t.done
}

// writer is the dedicated loop: collect a batch, process, repeat
// on stop we drain then return, defer closes done
func (t *Table[V]) writer() {
	defer close(t.done)
	for {
		select {
		case first := <-t.queue:
			t.process(t.collect(first))
		case <-t.stop:
			t.drain()
			return
		}
	}
}

// collect gathers a batch starting with first
// MaxBatchSize==1 short-circuits, delay==0 drains without waiting, otherwise
// we sit on a timer until size or stop
func (t *Table[V]) collect(first request[V]) []request[V] {
	requests := make([]request[V], 1, t.opts.MaxBatchSize)
	requests[0] = first
	if t.opts.MaxBatchSize == 1 {
		return requests
	}
	if t.opts.MaxBatchDelay == 0 {
		for len(requests) < t.opts.MaxBatchSize {
			select {
			case req := <-t.queue:
				requests = append(requests, req)
			default:
				return requests
			}
		}
		return requests
	}

	timer := time.NewTimer(t.opts.MaxBatchDelay)
	defer timer.Stop()
	for len(requests) < t.opts.MaxBatchSize {
		select {
		case req := <-t.queue:
			requests = append(requests, req)
		case <-timer.C:
			return requests
		case <-t.stop:
			return requests
		}
	}
	return requests
}

// drain empties the queue after stop, processing full batches as we go
// used so Close doesn't drop accepted Submits
func (t *Table[V]) drain() {
	for {
		requests := make([]request[V], 0, t.opts.MaxBatchSize)
		for len(requests) < t.opts.MaxBatchSize {
			select {
			case req := <-t.queue:
				requests = append(requests, req)
			default:
				if len(requests) != 0 {
					t.process(requests)
				}
				return
			}
		}
		t.process(requests)
	}
}

// process concatenates mutations, apply's them, Store's the next gen, then
// finish's every request in the batch with the same result
func (t *Table[V]) process(requests []request[V]) {
	mutations := make([]routeupdate.Mutation[V], 0)
	for _, req := range requests {
		mutations = append(mutations, req.mutations...)
	}

	next, err := t.apply(t.current.Load(), mutations)
	result := routeupdate.Result{Generation: t.Generation(), Err: err}
	if err == nil {
		t.current.Store(next)
		result.Generation = next.number
	}
	for _, req := range requests {
		t.finish(req, result)
	}
}

// finish sends result on req.done and closes it
// buffered so we never block on a caller that's gone
func (t *Table[V]) finish(req request[V], result routeupdate.Result) {
	req.done <- result
	close(req.done)
}

// normalizeMutations copies mutations and Masked()'s every prefix
// one junk prefix fails the whole batch, we don't apply partials
func normalizeMutations[V any](mutations []routeupdate.Mutation[V]) ([]routeupdate.Mutation[V], error) {
	normalized := make([]routeupdate.Mutation[V], len(mutations))
	for i, mutation := range mutations {
		prefix, ok := prefixentry.NormalizePrefix(mutation.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		mutation.Prefix = prefix
		normalized[i] = mutation
	}
	return normalized, nil
}

// apply decides payload-vs-structural then builds the next generation
// we scan mutations tracking live/dead per prefix (later wins). any add or
// delete of a prefix that changes membership is structural and rebuilds both
// indexes, otherwise we With() the payload pages and share fib/rib/ids
func (t *Table[V]) apply(current *generation[V], mutations []routeupdate.Mutation[V]) (*generation[V], error) {
	structural := false
	live := make(map[netip.Prefix]bool, len(mutations))
	for _, mutation := range mutations {
		exists, seen := live[mutation.Prefix]
		if !seen {
			_, exists = current.ids[mutation.Prefix]
		}
		if mutation.Delete {
			if exists {
				structural = true
			}
			live[mutation.Prefix] = false
		} else {
			if !exists {
				structural = true
			}
			live[mutation.Prefix] = true
		}
	}
	if structural {
		values := make(map[netip.Prefix]V, len(current.ids)+len(mutations))
		for prefix, id := range current.ids {
			values[prefix] = current.payloads.Get(id)
		}
		for _, mutation := range mutations {
			if mutation.Delete {
				delete(values, mutation.Prefix)
			} else {
				values[mutation.Prefix] = mutation.Value
			}
		}
		next, err := buildGeneration(values, current.number+1)
		return next, err
	}

	updates := make(map[routeid.ID]V, len(mutations))
	for _, mutation := range mutations {
		if !mutation.Delete {
			updates[current.ids[mutation.Prefix]] = mutation.Value
		}
	}
	next := &generation[V]{
		number:   current.number + 1,
		fib:      current.fib,
		rib:      current.rib,
		ids:      current.ids,
		payloads: current.payloads.With(updates, current.maxID),
		maxID:    current.maxID,
	}
	return next, nil
}

// buildGeneration compiles values into a numbered snapshot
// sort, assign dense ids from 1, then build fib and rib in parallel because
// they're independent and both expensive
func buildGeneration[V any](values map[netip.Prefix]V, number uint64) (*generation[V], error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for prefix := range values {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixLess(prefixes[i], prefixes[j]) })

	ids := make(map[netip.Prefix]routeid.ID, len(prefixes))
	indexed := make([]prefixentry.Entry[routeid.ID], len(prefixes))
	pageValues := make(map[routeid.ID]V, len(prefixes))
	for i, prefix := range prefixes {
		id := routeid.ID(i + 1)
		ids[prefix] = id
		indexed[i] = prefixentry.Entry[routeid.ID]{Prefix: prefix, Value: id}
		pageValues[id] = values[prefix]
	}

	var fib *compiledfib.Table[routeid.ID]
	var rib *bitwalk.Table[routeid.ID]
	var fibErr, ribErr error
	var builds sync.WaitGroup
	builds.Add(2)
	go func() {
		defer builds.Done()
		fib, fibErr = compiledfib.New(indexed, routeupdate.Options{})
	}()
	go func() {
		defer builds.Done()
		rib, ribErr = bitwalk.New(indexed)
	}()
	builds.Wait()
	if fibErr != nil {
		return nil, fibErr
	}
	if ribErr != nil {
		return nil, ribErr
	}

	maxID := routeid.ID(len(prefixes))
	return &generation[V]{
		number:   number,
		fib:      fib,
		rib:      rib,
		ids:      ids,
		payloads: routepages.New(pageValues, maxID),
		maxID:    maxID,
	}, nil
}

// prefixLess is the sort order we use when assigning dense ids
// v4 before v6, then addr, then bits. keeps ids stable across rebuilds of the
// same set
func prefixLess(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if a.Addr() == b.Addr() {
		return a.Bits() < b.Bits()
	}
	return a.Addr().Less(b.Addr())
}
