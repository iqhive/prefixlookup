// Package flatlpm is our managed value-returning LPM table on the flatart
// arena core
//
// value-lookup member of the lookup1 family - compared with compiledfib,
// which it's meant to replace on the forwarding path, it changes three things:
//
//   - the index is a compact arena trie rather than a leaf-pushed direct-index
//     table - compiledfib expands every prefix into 256-entry blocks, which
//     costs hundreds of bytes per prefix and pushes the deep levels out of
//     cache - the queries in this repo's bench suite are deliberately
//     cache-adverse, so that footprint is the dominant term in its latency
//
//   - the matched value is one load from a flat slice indexed by the slot the
//     index returns - compiledfib reaches its payload through a paged
//     copy-on-write structure (a dependent load) and a separate values array
//     (another)
//
//   - the catalogue needed to rebuild after a structural change is recovered
//     by enumerating the index instead of being retained as a
//     map[netip.Prefix]V - that map is the largest single chunk of
//     compiledfib's retained size
//
// payload updates copy the value slice and publish a new generation, so a
// writer never blocks or slows a reader beyond one atomic pointer load
// structural changes rebuild the index
package flatlpm

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iqhive/prefixlookup/internal/flatart"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// ErrClosed is what Submit returns once Close has started
var ErrClosed = errors.New("flatlpm: table closed")

// generation is one immutable published state
// the index is held by value so a read reaches the root array one pointer
// hop after the atomic load - don't box it
type generation[V any] struct {
	index  flatart.Index
	values []V
	number uint64
}

type request[V any] struct {
	mutations []routeupdate.Mutation[V]
	done      chan routeupdate.Result
}

// Stats is a snapshot of successful publications, split by whether we
// rebuilt the index or just swapped values
type Stats struct {
	PayloadPublications    uint64
	StructuralPublications uint64
}

// Table is the lock-free value lookup we publish from one dedicated writer
// readers only ever see an atomic pointer to a generation
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

// New builds the initial generation and kicks off the dedicated writer
// last duplicate after we normalise wins
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
	// publish before the writer goroutine can race a reader
	t.current.Store(g)
	go t.manage()
	return t, nil
}

// Lookup is the forwarding path we actually hit
// one atomic load, then the arena, then one value-slice index
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	g := t.current.Load()
	if slot := g.index.Lookup(addr); slot != 0 {
		return g.values[slot], true
	}
	var zero V
	return zero, false
}

// Lookup4 is the decoded IPv4 fast path - skip netip, we've already got the key
func (t *Table[V]) Lookup4(key uint32) (V, bool) {
	g := t.current.Load()
	if slot := g.index.Lookup4(key); slot != 0 {
		return g.values[slot], true
	}
	var zero V
	return zero, false
}

// Lookup6 is the decoded IPv6 fast path, same idea
func (t *Table[V]) Lookup6(hi, lo uint64) (V, bool) {
	g := t.current.Load()
	if slot := g.index.Lookup6(hi, lo); slot != 0 {
		return g.values[slot], true
	}
	var zero V
	return zero, false
}

// Exact returns the value stored for exactly this prefix, not a covering one
func (t *Table[V]) Exact(prefix netip.Prefix) (V, bool) {
	g := t.current.Load()
	if slot := g.index.Exact(prefix); slot != 0 {
		return g.values[slot], true
	}
	var zero V
	return zero, false
}

// Generation is the currently published generation number - readers just load it
func (t *Table[V]) Generation() uint64 { return t.current.Load().number }

// Stats returns a point-in-time publication count, two atomics, no lock
func (t *Table[V]) Stats() Stats {
	return Stats{
		PayloadPublications:    t.payloadPublications.Load(),
		StructuralPublications: t.structuralPublications.Load(),
	}
}

// IndexBytes reports the retained size of the forwarding index, excluding
// payload storage
func (t *Table[V]) IndexBytes() int { return t.current.Load().index.Bytes() }

// ApplyBatch submits mutations and waits until their generation is published
func (t *Table[V]) ApplyBatch(mutations []routeupdate.Mutation[V]) error {
	return (<-t.Submit(mutations)).Err
}

// Submit queues mutations for async publication
// invalid requests and requests after Close get an immediate result so the
// caller doesn't block on a writer that will never see them
func (t *Table[V]) Submit(mutations []routeupdate.Mutation[V]) <-chan routeupdate.Result {
	// Let's make a channel that'll hold exactly one result.
	done := make(chan routeupdate.Result, 1)
	// Prealloc our soon-to-be-normalized batch of mutations (because copying is better than reallocating all the time, right?)
	normalized := make([]routeupdate.Mutation[V], len(mutations))
	for i, mutation := range mutations {
		// Let's try and normalize that prefix
		prefix, ok := prefixentry.NormalizePrefix(mutation.Prefix)
		if !ok {
			// Nope, that prefix is garbage, bail
			done <- routeupdate.Result{Generation: t.Generation(), Err: prefixentry.ErrBadIP}
			close(done)
			return done
		}
		// valid. let's store this mutation, but with the cleaned-up prefix
		normalized[i] = mutation
		normalized[i].Prefix = prefix
	}

	t.submitMu.Lock()
	if t.closed {
		// table's closed for updates
		t.submitMu.Unlock()
		done <- routeupdate.Result{Generation: t.Generation(), Err: ErrClosed}
		close(done)
		return done
	}
	// All good, push our shiny normalized batch onto the request queue
	t.queue <- request[V]{mutations: normalized, done: done}
	t.submitMu.Unlock()
	// Here you go, caller: you get a future (sort of) with your result
	return done
}

// Close stops accepting updates and waits for queued work to publish
// Only the first closer gets to touch the special stuff.
func (t *Table[V]) Close() {
	t.closeOnce.Do(func() {
		t.submitMu.Lock()
		t.closed = true // No more writes
		close(t.stop)   // Signal manager to start shutting down
		t.submitMu.Unlock()
	})
	<-t.done // Wait for graceful shutdown. Go make a coffee, or not
}

// The one loop to rule them all - manages the write-side of the table
func (t *Table[V]) manage() {
	defer close(t.done) // When this exits, we're totally done forever
	for {
		select {
		case first := <-t.queue:
			// Got a request! Might as well see if there are more (batch for efficiency)
			t.publish(t.collect(first))
		case <-t.stop:
			// All done, but drain whatever's left in the queue before we go dark
			for {
				select {
				case first := <-t.queue:
					// This one's on the house-handle it immediately.
					t.publish(t.appendQueued([]request[V]{first}))
				default:
					// Nothing left! We out.
					return
				}
			}
		}
	}
}

// collect tries to batch up as many requests as possible, but doesn't wait forever.
func (t *Table[V]) collect(first request[V]) []request[V] {
	batch := []request[V]{first}
	// If we're told not to wait for batching, just get whatever is there and move on.
	if t.options.MaxBatchDelay <= 0 {
		return t.appendQueued(batch)
	}
	// Otherwise, set up a timer and see how many buddies we can cram in before it expires.
	timer := time.NewTimer(t.options.MaxBatchDelay)
	defer timer.Stop()
	for len(batch) < t.options.MaxBatchSize {
		select {
		case req := <-t.queue:
			batch = append(batch, req) // Found another! Group hug.
		case <-timer.C:
			// Time's up-good enough.
			return batch
		case <-t.stop:
			// Oh, we're shutting down. Don't keep the next guy waiting.
			return t.appendQueued(batch)
		}
	}
	return batch
}

// appendQueued just drains the queue for whoever's waiting-no blocking, no nonsense.
func (t *Table[V]) appendQueued(batch []request[V]) []request[V] {
	for len(batch) < t.options.MaxBatchSize {
		select {
		case req := <-t.queue:
			batch = append(batch, req)
		default:
			// No more requests hiding; let's move on.
			return batch
		}
	}
	return batch
}

// publish: this is where the magic happens (well, some of it)
// Takes a batch, figures out what it all means, and updates the table
func (t *Table[V]) publish(batch []request[V]) {
	current := t.current.Load() // Grab the current state for reference.
	// We'll flatten out the mutations so only the last change per prefix matters (last writer wins)
	mutations := make(map[netip.Prefix]routeupdate.Mutation[V], len(batch))
	for _, req := range batch {
		for _, mutation := range req.mutations {
			mutations[mutation.Prefix] = mutation
		}
	}

	// Do we need a full-blown structural rebuild, or just tweak the values in-place?
	structural := false
	for prefix, mutation := range mutations {
		// If this prefix pops in or out of existence, get the hammer
		if (current.index.Exact(prefix) == 0) != mutation.Delete {
			structural = true
			break
		}
	}

	var next *generation[V]
	var err error
	if structural {
		next, err = t.rebuild(current, mutations)
	} else {
		// shuffling values around
		next = t.repayload(current, mutations)
	}

	result := routeupdate.Result{Generation: current.number, Err: err}
	if err == nil {
		t.current.Store(next) // publish the result
		result.Generation = next.number
		if structural {
			t.structuralPublications.Add(1)
		} else {
			t.payloadPublications.Add(1)
		}
	}
	// now send the result to every request in our batch-good news or bad
	for _, req := range batch {
		req.done <- result
		close(req.done)
	}
}

// repayload handles quick value-only updates. No structure, all speed!
// It's like a "find and replace" for your table
func (t *Table[V]) repayload(current *generation[V], mutations map[netip.Prefix]routeupdate.Mutation[V]) *generation[V] {
	// Copy the whole value slice. Expensive? Not really, considering the alternatives
	values := make([]V, len(current.values))
	copy(values, current.values)
	for prefix, mutation := range mutations {
		if slot := current.index.Exact(prefix); slot != 0 {
			values[slot] = mutation.Value // Just patching in the new value at the right slot
		}
	}
	// Package up the new generation
	return &generation[V]{index: current.index, values: values, number: current.number + 1}
}

// rebuild goes nuclear: rebuilds index and value slice from scratch
// Great for a fresh start, not your daily driver
func (t *Table[V]) rebuild(current *generation[V], mutations map[netip.Prefix]routeupdate.Mutation[V]) (*generation[V], error) {
	// Start off by reconstructing the existing catalogue
	catalog := make(map[netip.Prefix]V, len(current.values)+len(mutations))
	current.index.All(func(prefix netip.Prefix, slot uint32) bool {
		catalog[prefix] = current.values[slot]
		return true
	})
	// Apply the latest changes (add, update, delete)
	for prefix, mutation := range mutations {
		if mutation.Delete {
			delete(catalog, prefix)
		} else {
			catalog[prefix] = mutation.Value
		}
	}
	// Build shiny new generation
	return buildGeneration(catalog, current.number+1)
}

// buildGeneration - the makeover show
// Sort everything, put it through the Builder, and hand you a new, shiny, matching index and value array
func buildGeneration[V any](catalog map[netip.Prefix]V, number uint64) (*generation[V], error) {
	// Gather up our prefixes so we can sort them.
	prefixes := make([]netip.Prefix, 0, len(catalog))
	for prefix := range catalog {
		prefixes = append(prefixes, prefix)
	}
	// Sorting isn't for correctness, but because we like our data neat and predictable
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr() == prefixes[j].Addr() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})

	// Builder time! Insert the prefixes in sorted order
	builder := flatart.NewBuilder(flatart.Options{Exact: true})
	for i, prefix := range prefixes {
		if !builder.Insert(prefix, uint32(i+1)) {
			// Someone tried to sneak in a bad prefix. Not on our watch
			return nil, prefixentry.ErrBadIP
		}
	}
	index, refOf, err := builder.Build()
	if err != nil {
		// If the builder blew up, let's not make things worse
		return nil, err
	}
	// The Builder gets to pick the value order. We've got to follow its lead
	values := make([]V, len(refOf))
	for value, ref := range refOf {
		if ref != 0 {
			values[value] = catalog[prefixes[ref-1]]
		}
	}
	// new indexed generation
	return &generation[V]{index: *index, values: values, number: number}, nil
}
