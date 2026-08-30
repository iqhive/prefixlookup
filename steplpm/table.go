package steplpm

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// snapshot is one published generation: an immutable index plus the value
// vector it indexes into - the two are separate so that changing a value does not
// touch the index
type snapshot[V any] struct {
	index  *Index
	values []V // values[0] is the no-match zero value
}

// stored is the authoritative state of one prefix: its value, and the route id
// the currently published index assigned to it
type stored[V any] struct {
	value V
	id    uint32
}

// Table is a managed value LPM table - readers perform one atomic load, one
// index lookup and one value load, and never block
//
// # Why the index and the values are separate
//
// Changing the value attached to an existing prefix leaves the step function
// untouched: the same addresses map to the same route ids, only the payload
// behind an id differs - splitting the index from the value vector turns such an
// update into a copy of the value vector alone - four bytes per route for a
// uint32 payload, tens of microseconds for a hundred thousand routes - instead
// of a full recompile - structural changes, which do move the boundaries, still
// rebuild the index
//
// This is the same division compiledfib makes, and it is what makes read-heavy
// churn cheap: readers keep hitting a stable index while the writer publishes a
// new value vector beside it
//
// The route id of each prefix is remembered alongside its value - it cannot be
// recovered from the index by looking the prefix up, because the index answers
// longest-prefix-match: asking it about 10.0.0.0/8 when 10.0.0.0/16 is also
// stored returns the /16
type Table[V any] struct {
	current atomic.Pointer[snapshot[V]]

	mu     sync.Mutex
	routes map[netip.Prefix]stored[V]
}

// Entry is a prefix and its value
type Entry[V any] struct {
	Prefix netip.Prefix
	Value  V
}

// New builds a Table from entries - duplicate prefixes take the last value
// We just construct and Reset - that's the only way the first generation gets
// published, so empty input is a valid empty table
func New[V any](entries []Entry[V]) (*Table[V], error) {
	t := new(Table[V])
	if err := t.Reset(entries); err != nil {
		return nil, err
	}
	return t, nil
}

// Lookup returns the value of the longest prefix covering addr
// One atomic load of the published snapshot, then index then values - readers
// never take mu
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	s := t.current.Load()
	if id := s.index.Lookup(addr); id != 0 {
		return s.values[id], true
	}
	var zero V
	return zero, false
}

// Lookup4 is the decoded IPv4 fast path through the published snapshot
func (t *Table[V]) Lookup4(key uint32) (V, bool) {
	s := t.current.Load()
	if id := s.index.Lookup4(key); id != 0 {
		return s.values[id], true
	}
	var zero V
	return zero, false
}

// Lookup6 is the decoded IPv6 fast path through the published snapshot
func (t *Table[V]) Lookup6(high, low uint64) (V, bool) {
	s := t.current.Load()
	if id := s.index.Lookup6(high, low); id != 0 {
		return s.values[id], true
	}
	var zero V
	return zero, false
}

// Index returns the currently published immutable index
func (t *Table[V]) Index() *Index { return t.current.Load().index }

// Size returns the number of stored prefixes
// We lock because the map is the writer's copy, not the published snapshot
func (t *Table[V]) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.routes)
}

// Reset replaces the whole table
// Canonicalise everything first so a bad prefix fails before we take the lock,
// then swap the map and rebuild
func (t *Table[V]) Reset(entries []Entry[V]) error {
	routes := make(map[netip.Prefix]stored[V], len(entries))
	for _, entry := range entries {
		prefix, ok := canonical(entry.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		routes[prefix] = stored[V]{value: entry.Value}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = routes
	return t.rebuild()
}

// Insert adds or updates one prefix - just a one-entry ApplyBatch
func (t *Table[V]) Insert(prefix netip.Prefix, value V) error {
	return t.ApplyBatch([]Mutation[V]{{Prefix: prefix, Value: value}})
}

// Delete removes a prefix - it reports whether the prefix was present
// Missing prefixes don't rebuild - we'd just republish the same index
func (t *Table[V]) Delete(prefix netip.Prefix) bool {
	canonicalPrefix, ok := canonical(prefix)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.routes[canonicalPrefix]; !exists {
		return false
	}
	delete(t.routes, canonicalPrefix)
	_ = t.rebuild()
	return true
}

// Mutation is one requested change
type Mutation[V any] struct {
	Prefix netip.Prefix
	Value  V
	Delete bool
}

// ApplyBatch applies mutations in order and publishes one generation - when no
// mutation adds or removes a prefix, the index is reused and only the value
// vector is republished
func (t *Table[V]) ApplyBatch(mutations []Mutation[V]) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// if there's no routes map yet, better make one to hold stuff
	if t.routes == nil {
		t.routes = make(map[netip.Prefix]stored[V], len(mutations))
	}
	structural := false
	for i := range mutations {
		prefix, ok := canonical(mutations[i].Prefix)
		if !ok {
			return ErrBadPrefix
		}
		mutations[i].Prefix = prefix
		// this bit is checking if the new change actually changes the structure (like adding or deleting a key)
		if _, exists := t.routes[prefix]; exists == mutations[i].Delete {
			structural = true
		}
	}

	// this chunk applies if we're changing the structure, not just fiddling values
	if structural {
		for _, mutation := range mutations {
			if mutation.Delete {
				// removing the prefix from routes here, so it's gone for good
				delete(t.routes, mutation.Prefix)
				continue
			}
			// updating or adding a new value for that prefix
			t.routes[mutation.Prefix] = stored[V]{value: mutation.Value}
		}
		// after structural change, gotta rebuild the index from scratch to keep things right
		return t.rebuild()
	}

	// right, if we're just changing values and not the shape, keep the index and just do a value vector copy
	current := t.current.Load()
	values := make([]V, len(current.values))
	copy(values, current.values)
	for _, mutation := range mutations {
		// get old stored value so we can patch it
		existing := t.routes[mutation.Prefix]
		existing.value = mutation.Value
		t.routes[mutation.Prefix] = existing
		// put new value in the correct slot by id, so the index stays valid
		values[existing.id] = mutation.Value
	}
	// swap in the new snapshot with the fresh value vector-readers get the update in one hit
	t.current.Store(&snapshot[V]{index: current.index, values: values})
	return nil
}

// rebuild recompiles the index and the value vector, and records the new route
// ids - the caller holds mu
func (t *Table[V]) rebuild() error {
	builder := NewBuilder()

	// loop over every prefix we've got to register it with the builder
	for prefix, entry := range t.routes {
		id, err := builder.Add(prefix)
		if err != nil {
			return err
		}
		// record the new ID the builder just gave this prefix
		entry.id = id
		t.routes[prefix] = entry
	}

	// allocate enough slots for every value, plus a default at index 0
	values := make([]V, builder.Routes()+1)
	for _, entry := range t.routes {
		// stuff the value in at the slot for its id
		values[entry.id] = entry.value
	}
	// slap in the new snapshot atomically for readers – now they're all set
	t.current.Store(&snapshot[V]{index: builder.Build(), values: values})
	return nil
}

// canonical masks the prefix and rejects invalid / zoned input
func canonical(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}
