// Package preorder2 is a managed, versioned wrapper around immutable
// fiborderwalk routing tables
//
// same writer-goroutine story as compiledfib, but the index is fiborderwalk
// so we get parent/descendant walks as well as LPM. payload updates share
// topology, structural ones rebuild
package preorder2

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iqhive/prefixlookup/internal/routepages"
	"github.com/iqhive/prefixlookup/old/fiborderwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// ErrClosed is what Submit hands back once the table is closed
var ErrClosed = errors.New("preorder2: table closed")

// snapshot is one immutable published generation
// topology is the fiborderwalk index, pages the payloads, exact is prefix->id
// so we can do Exact() without a walk
type snapshot[V any] struct {
	topology   *fiborderwalk.Table[routeid.ID]
	pages      *routepages.Pages[V]
	exact      map[netip.Prefix]routeid.ID
	maxID      routeid.ID
	generation uint64
}

// request is one Submit sitting on the writer queue
type request[V any] struct {
	mutations []routeupdate.Mutation[V]
	result    chan routeupdate.Result
}

// Stats is successful publications split by kind
type Stats struct {
	PayloadPublications    uint64
	StructuralPublications uint64
}

// Table publishes immutable routing generations
// reads take one atomic snapshot and never coordinate with the writer
type Table[V any] struct {
	current atomic.Pointer[snapshot[V]]
	options routeupdate.Options
	queue   chan request[V]

	submitMu sync.Mutex
	closed   bool
	done     chan struct{}

	payloadPublications    atomic.Uint64
	structuralPublications atomic.Uint64
}

// New builds the initial generation and starts the dedicated writer
// last value wins on duplicate prefixes. we catalogue, buildSnapshot, Store,
// then runWriter
func New[V any](entries []prefixentry.Entry[V], options routeupdate.Options) (*Table[V], error) {
	catalog := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		catalog[prefix] = entry.Value
	}

	initial, err := buildSnapshot(catalog, 1)
	if err != nil {
		return nil, err
	}
	options = options.Normalize()
	t := &Table[V]{
		options: options,
		queue:   make(chan request[V], options.QueueSize),
		done:    make(chan struct{}),
	}
	t.current.Store(initial)
	go t.runWriter(catalog)
	return t, nil
}

// Lookup returns the LPM from one immutable generation
// Load, topology.Lookup, then snapshot.result to fetch the payload
func (t *Table[V]) Lookup(addr netip.Addr) (routeid.ID, V, bool) {
	s := t.current.Load()
	_, id, ok := s.topology.Lookup(addr)
	return s.result(id, ok)
}

// Lookup4 is the decoded IPv4 fast path
func (t *Table[V]) Lookup4(addr uint32) (routeid.ID, V, bool) {
	s := t.current.Load()
	_, id, ok := s.topology.Lookup4(addr)
	return s.result(id, ok)
}

// Lookup6 is the decoded IPv6 fast path
func (t *Table[V]) Lookup6(hi, lo uint64) (routeid.ID, V, bool) {
	s := t.current.Load()
	_, id, ok := s.topology.Lookup6(hi, lo)
	return s.result(id, ok)
}

// result turns an id+ok from the topology into (id, payload, ok)
// miss returns zero V
func (s *snapshot[V]) result(id routeid.ID, ok bool) (routeid.ID, V, bool) {
	if ok {
		return id, s.pages.Get(id), true
	}
	var zero V
	return 0, zero, false
}

// Exact returns the route for an exact canonicalised prefix
// we normalise then map-lookup, no LPM. junk prefix is a miss
func (t *Table[V]) Exact(input netip.Prefix) (routeid.ID, V, bool) {
	s := t.current.Load()
	prefix, ok := prefixentry.NormalizePrefix(input)
	if ok {
		id, found := s.exact[prefix]
		return s.result(id, found)
	}
	var zero V
	return 0, zero, false
}

// WalkParents visits the longest match and its stored ancestors, longest first
// Load once, walk topology, fetch payloads as we go
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(routeid.ID, netip.Prefix, V) bool) {
	s := t.current.Load()
	s.topology.WalkParents(addr, func(_ routeid.ID, prefix netip.Prefix, id routeid.ID) bool {
		return yield(id, prefix, s.pages.Get(id))
	})
}

// WalkDescendants visits an exact route and its descendants in fiborderwalk
func (t *Table[V]) WalkDescendants(prefix netip.Prefix, yield func(routeid.ID, netip.Prefix, V) bool) bool {
	s := t.current.Load()
	return s.topology.WalkDescendants(prefix, func(_ routeid.ID, actual netip.Prefix, id routeid.ID) bool {
		return yield(id, actual, s.pages.Get(id))
	})
}

// Generation returns the currently published generation
func (t *Table[V]) Generation() uint64 { return t.current.Load().generation }

// Stats returns a point-in-time publication count
// two atomic loads
func (t *Table[V]) Stats() Stats {
	return Stats{
		PayloadPublications:    t.payloadPublications.Load(),
		StructuralPublications: t.structuralPublications.Load(),
	}
}

// ApplyBatch synchronously applies one atomic batch
// Submit plus a receive
func (t *Table[V]) ApplyBatch(mutations []routeupdate.Mutation[V]) error {
	return (<-t.Submit(mutations)).Err
}

// Submit queues one atomic batch and returns a channel that receives exactly
// one result. mutations are copied before we return. junk/closed get an
// immediate result
func (t *Table[V]) Submit(mutations []routeupdate.Mutation[V]) <-chan routeupdate.Result {
	result := make(chan routeupdate.Result, 1)
	normalized, err := normalizeMutations(mutations)
	if err != nil {
		result <- routeupdate.Result{Generation: t.Generation(), Err: err}
		close(result)
		return result
	}

	t.submitMu.Lock()
	if t.closed {
		t.submitMu.Unlock()
		result <- routeupdate.Result{Generation: t.Generation(), Err: ErrClosed}
		close(result)
		return result
	}
	t.queue <- request[V]{mutations: normalized, result: result}
	t.submitMu.Unlock()
	return result
}

// Close stops the writer after all accepted requests have completed
// we close the queue (range in runWriter exits) rather than a stop chan
// safe to call more than once
func (t *Table[V]) Close() {
	t.submitMu.Lock()
	if !t.closed {
		t.closed = true
		close(t.queue)
	}
	t.submitMu.Unlock()
	<-t.done
}

// normalizeMutations copies mutations and Masked()'s every prefix
// one junk prefix fails the whole batch
func normalizeMutations[V any](mutations []routeupdate.Mutation[V]) ([]routeupdate.Mutation[V], error) {
	normalized := make([]routeupdate.Mutation[V], len(mutations))
	for i, mutation := range mutations {
		prefix, ok := prefixentry.NormalizePrefix(mutation.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		normalized[i] = mutation
		normalized[i].Prefix = prefix
	}
	return normalized, nil
}

// runWriter ranges the queue until Close, coalescing with collect then publish
// defer closes done so Close can wait
func (t *Table[V]) runWriter(catalog map[netip.Prefix]V) {
	defer close(t.done)
	for first := range t.queue {
		batch := []request[V]{first}
		batch = t.collect(batch)
		catalog = t.publish(catalog, batch)
	}
}

// collect gathers more requests onto batch up to MaxBatchSize
// delay<=0 drains without waiting, otherwise we sit on a timer. a closed
// queue (!ok) means Close, we return what we've got
func (t *Table[V]) collect(batch []request[V]) []request[V] {
	limit := t.options.MaxBatchSize
	if t.options.MaxBatchDelay <= 0 {
		for len(batch) < limit {
			select {
			case request, ok := <-t.queue:
				if !ok {
					return batch
				}
				batch = append(batch, request)
			default:
				return batch
			}
		}
		return batch
	}

	timer := time.NewTimer(t.options.MaxBatchDelay)
	defer timer.Stop()
	for len(batch) < limit {
		select {
		case request, ok := <-t.queue:
			if !ok {
				return batch
			}
			batch = append(batch, request)
		case <-timer.C:
			return batch
		}
	}
	return batch
}

// publish applies a coalesced batch and stores the next snapshot
// last mutation per prefix wins. add/delete of membership is structural
// (rebuild topology), otherwise we With() the pages and share topology/exact
func (t *Table[V]) publish(catalog map[netip.Prefix]V, batch []request[V]) map[netip.Prefix]V {
	current := t.current.Load()
	mutations := make(map[netip.Prefix]routeupdate.Mutation[V])
	for _, request := range batch {
		for _, mutation := range request.mutations {
			mutations[mutation.Prefix] = mutation
		}
	}

	structural := false
	for prefix, mutation := range mutations {
		_, exists := current.exact[prefix]
		if exists == mutation.Delete {
			structural = true
			break
		}
	}

	generation := current.generation + 1
	var next *snapshot[V]
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
		next, err = buildSnapshot(nextCatalog, generation)
	} else {
		updates := make(map[routeid.ID]V, len(mutations))
		for prefix, mutation := range mutations {
			if !mutation.Delete {
				updates[current.exact[prefix]] = mutation.Value
			}
		}
		pages := current.pages
		if len(updates) != 0 {
			pages = pages.With(updates, current.maxID)
		}
		next = &snapshot[V]{
			topology:   current.topology,
			pages:      pages,
			exact:      current.exact,
			maxID:      current.maxID,
			generation: generation,
		}
	}
	if err == nil {
		t.current.Store(next)
		if structural {
			t.structuralPublications.Add(1)
			catalog = nextCatalog
		} else {
			t.payloadPublications.Add(1)
			for prefix, mutation := range mutations {
				if !mutation.Delete {
					catalog[prefix] = mutation.Value
				}
			}
		}
	} else {
		generation = current.generation
	}
	for _, request := range batch {
		request.result <- routeupdate.Result{Generation: generation, Err: err}
		close(request.result)
	}
	return catalog
}

// cloneCatalog shallow-copies a prefix->value map
// used before a structural rebuild so a failed build doesn't trash the live catalogue
func cloneCatalog[V any](catalog map[netip.Prefix]V) map[netip.Prefix]V {
	clone := make(map[netip.Prefix]V, len(catalog))
	for prefix, value := range catalog {
		clone[prefix] = value
	}
	return clone
}

// buildSnapshot compiles the catalogue into an immutable snapshot numbered generation
// sort v4 first then addr then bits, assign dense ids from 1, fiborderwalk.New
func buildSnapshot[V any](catalog map[netip.Prefix]V, generation uint64) (*snapshot[V], error) {
	prefixes := make([]netip.Prefix, 0, len(catalog))
	for prefix := range catalog {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr().Is4() != prefixes[j].Addr().Is4() {
			return prefixes[i].Addr().Is4()
		}
		if prefixes[i].Addr() == prefixes[j].Addr() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})

	indexed := make([]prefixentry.Entry[routeid.ID], len(prefixes))
	values := make(map[routeid.ID]V, len(prefixes))
	exact := make(map[netip.Prefix]routeid.ID, len(prefixes))
	for i, prefix := range prefixes {
		id := routeid.ID(i + 1)
		indexed[i] = prefixentry.Entry[routeid.ID]{Prefix: prefix, Value: id}
		values[id] = catalog[prefix]
		exact[prefix] = id
	}
	topology, err := fiborderwalk.New(indexed)
	if err != nil {
		return nil, err
	}
	maxID := routeid.ID(len(prefixes))
	return &snapshot[V]{
		topology:   topology,
		pages:      routepages.New(values, maxID),
		exact:      exact,
		maxID:      maxID,
		generation: generation,
	}, nil
}
