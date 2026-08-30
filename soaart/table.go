package soaart

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// Index is the compiled SoA ART: two trees (v4/v6) plus a route count
//
// route id 0 means no match. we publish this as an immutable value so readers
// never take a lock - the managed Table just atomically swaps a pointer to a
// new one when the prefix set changes
type Index struct {
	v4     tree
	v6     tree
	routes int
}

// Routes returns how many distinct prefixes we stored
// just the counter Build stamped on us, we don't walk the trees
func (x *Index) Routes() int { return x.routes }

// Nodes returns the node count per family, for tests and reporting
// pfxBase is one uint32 per node so its length is the node count
func (x *Index) Nodes() (v4, v6 int) { return len(x.v4.pfxBase), len(x.v6.pfxBase) }

// RetainedBytes reports the bytes the compiled index actually holds
// we walk each SoA slice at its element width rather than using unsafe.Sizeof
// on the struct, because the struct is just headers
func (x *Index) RetainedBytes() int {
	// size is the retained footprint of one family's compiled tree
	// bitsets are 8, bases/items 4, leaves 24 (two uint64s + uint8 + pad + id)
	size := func(t *tree) int {
		return 8*len(t.pfx) + 8*len(t.kids) + 4*len(t.pfxBase) + 4*len(t.kidBase) +
			4*len(t.pfxItems) + 4*len(t.kidItems) + 24*len(t.leaves)
	}
	return size(&x.v4) + size(&x.v6)
}

// Lookup returns the route id of the longest prefix covering addr, or 0
//
// we pick the family, pack the addr into the 128-bit key the tree walks, and
// hand off - IPv4 lives in the high word shifted up 32 so octetAt at depth 0..3
// still pulls the right octet - same helper as v6, no second code path in the
// trie. mapped 4in6 gets Unmap'd and sent to the v4 tree; invalid addrs miss
func (x *Index) Lookup(addr netip.Addr) (uint32, bool) {
	if addr.Is4() {
		return x.v4.lookup(uint64(be32(addr.As4()))<<32, 0)
	}
	if addr.Is4In6() {
		// mapped v4-in-v6 is still a v4 lookup - Unmap then the same shift
		return x.v4.lookup(uint64(be32(addr.Unmap().As4()))<<32, 0)
	}
	if !addr.IsValid() {
		return 0, false
	}
	high, low := words16(addr.As16())
	return x.v6.lookup(high, low)
}

// Exact returns the route id stored for exactly this prefix
//
// decomposeKey masks and family-splits; we don't build a canonical netip.Prefix
// because AddrFrom4/16 is wasted work the tree never reads. then one exact
// descent on the matching family
func (x *Index) Exact(prefix netip.Prefix) (uint32, bool) {
	high, low, bits, is4, ok := decomposeKey(prefix)
	if !ok {
		return 0, false
	}
	if is4 {
		return x.v4.exact(high, low, bits)
	}
	return x.v6.exact(high, low, bits)
}

// WalkSupernets visits every stored prefix covering addr, most specific first
//
// same family split as Lookup, then the tree yields packed matches and we
// rebuild netip.Prefix from the key + the original addr's family. we use addrOf
// on the match's masked key so a /8 comes out as 10.0.0.0/8 not 10.1.2.3/8
func (x *Index) WalkSupernets(addr netip.Addr, yield func(uint32, netip.Prefix) bool) {
	is4 := true
	var high, low uint64
	switch {
	case addr.Is4():
		high = uint64(be32(addr.As4())) << 32
	case addr.Is4In6():
		high = uint64(be32(addr.Unmap().As4())) << 32
	case !addr.IsValid():
		return
	default:
		is4 = false
		high, low = words16(addr.As16())
	}
	t := &x.v4
	if !is4 {
		t = &x.v6
	}
	t.walkSupernets(high, low, func(m match) bool {
		bits := int(m.bits)
		return yield(m.id, netip.PrefixFrom(addrOf(m.high, m.low, is4), bits))
	})
}

// WalkSubnets visits prefix and every stored prefix contained in it. reports
// whether prefix itself is stored
//
// decomposeKey then walkSubnets; same match-to-Prefix rebuild as WalkSupernets
// false means the query isn't in the table, not "no descendants" - if it's
// stored we yield it even when it has no kids
func (x *Index) WalkSubnets(prefix netip.Prefix, yield func(uint32, netip.Prefix) bool) bool {
	high, low, bits, is4, ok := decomposeKey(prefix)
	if !ok {
		return false
	}
	t := &x.v4
	if !is4 {
		t = &x.v6
	}
	return t.walkSubnets(high, low, bits, func(m match) bool {
		return yield(m.id, netip.PrefixFrom(addrOf(m.high, m.low, is4), int(m.bits)))
	})
}

// ---------------------------------------------------------------- managed form

// snapshot is one published generation: the compiled index plus the value
// vector it indexes into. we keep them separate so a value-only change copies
// the vector and reuses the index - same trick as steplpm
type snapshot[V any] struct {
	index  *Index
	values []V
}

// stored is the writer's copy of one prefix: its value, and the route id the
// currently published index assigned it. we need the id to patch the value
// vector without a rebuild
type stored[V any] struct {
	value V
	id    uint32
}

// Entry is a prefix and its value
type Entry[V any] struct {
	Prefix netip.Prefix
	Value  V
}

// Mutation is one requested change
type Mutation[V any] struct {
	Prefix netip.Prefix
	Value  V
	Delete bool
}

// Table is a managed value LPM table with hierarchy traversal. readers do one
// atomic load and never block
//
// as in steplpm, the index and the value vector are separate, so changing a
// value republishes only the vector. the writer's authoritative set is
// routes - a map[netip.Prefix] because we need the assigned id next to the
// value and this package didn't go down aosart's packed-slice path
type Table[V any] struct {
	current atomic.Pointer[snapshot[V]]

	mu     sync.Mutex
	routes map[netip.Prefix]stored[V]
}

// New builds a Table from entries. duplicate prefixes take the last value
// we just construct and Reset - that's how the first generation gets published,
// so empty input is a valid empty table
func New[V any](entries []Entry[V]) (*Table[V], error) {
	t := new(Table[V])
	if err := t.Reset(entries); err != nil {
		return nil, err
	}
	return t, nil
}

// Lookup returns the value of the longest prefix covering addr
// one atomic load of the published snapshot, then index then values - readers
// never take mu
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	s := t.current.Load()
	if id, ok := s.index.Lookup(addr); ok {
		return s.values[id], true
	}
	var zero V
	return zero, false
}

// Exact returns the value stored for exactly this prefix
// same snapshot load as Lookup, then Exact on the index and index into values
func (t *Table[V]) Exact(prefix netip.Prefix) (V, bool) {
	s := t.current.Load()
	if id, ok := s.index.Exact(prefix); ok {
		return s.values[id], true
	}
	var zero V
	return zero, false
}

// WalkSupernets visits every stored prefix covering addr, most specific first
// we close over the snapshot's value vector so the tree's id yields become
// (prefix, value) for the caller
func (t *Table[V]) WalkSupernets(addr netip.Addr, yield func(netip.Prefix, V) bool) {
	s := t.current.Load()
	s.index.WalkSupernets(addr, func(id uint32, prefix netip.Prefix) bool {
		return yield(prefix, s.values[id])
	})
}

// WalkSubnets visits prefix and every stored prefix contained in it
// same id-to-value wrap as WalkSupernets; the bool is whether the query itself
// was stored
func (t *Table[V]) WalkSubnets(prefix netip.Prefix, yield func(netip.Prefix, V) bool) bool {
	s := t.current.Load()
	return s.index.WalkSubnets(prefix, func(id uint32, found netip.Prefix) bool {
		return yield(found, s.values[id])
	})
}

// Index returns the currently published immutable index
// just the snapshot's pointer - callers that want to hold the compiled form
// across lookups grab this
func (t *Table[V]) Index() *Index { return t.current.Load().index }

// Size returns the number of stored prefixes
// we lock because routes is the writer's copy, not the published snapshot
func (t *Table[V]) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.routes)
}

// Reset replaces the whole table
// we canonicalise everything first so a bad prefix fails before we take the
// lock, then swap the map and rebuild. last duplicate wins because we just
// overwrite the map entry
func (t *Table[V]) Reset(entries []Entry[V]) error {
	routes := make(map[netip.Prefix]stored[V], len(entries))
	for _, entry := range entries {
		canonical, _, _, _, _, ok := decompose(entry.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		routes[canonical] = stored[V]{value: entry.Value}
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

// Delete removes a prefix. reports whether the prefix was present
// missing / invalid prefixes don't rebuild - we'd just republish the same index
func (t *Table[V]) Delete(prefix netip.Prefix) bool {
	canonical, _, _, _, _, ok := decompose(prefix)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.routes[canonical]; !exists {
		return false
	}
	delete(t.routes, canonical)
	_ = t.rebuild()
	return true
}

// ApplyBatch applies mutations in order and publishes one generation
//
// first pass: canonicalise and decide whether anything is structural. exists ==
// Delete means either "it's there and we're removing it" or "it isn't and we're
// inserting" - both change the prefix set. a value update on an existing prefix
// leaves that false
//
// structural: apply every mutation to the map then rebuild. value-only: copy
// the published vector, patch the slots we already know the ids for, Store a
// new snapshot that reuses the index. that's the cheap path
func (t *Table[V]) ApplyBatch(mutations []Mutation[V]) error {
	t.mu.Lock()
	// grab the lock before we do anything so we keep things safe
	defer t.mu.Unlock()
	if t.routes == nil {
		// if we haven't got a routes map yet, make one sized just right
		t.routes = make(map[netip.Prefix]stored[V], len(mutations))
	}

	canonicals := make([]netip.Prefix, len(mutations))
	// track if anything in this batch actually changes the prefix set
	structural := false
	for i, mutation := range mutations {
		// turn every prefix into normalised form, ready to use/order
		canonical, _, _, _, _, ok := decompose(mutation.Prefix)
		if !ok {
			// ah, bad prefix, bail here eh
			return ErrBadPrefix
		}
		canonicals[i] = canonical
		// check for add or delete (not just a value bump), that's structural
		if _, exists := t.routes[canonical]; exists == mutation.Delete {
			structural = true
		}
	}

	if structural {
		for i, mutation := range mutations {
			if mutation.Delete {
				// go on, drop it out of the routes
				delete(t.routes, canonicals[i])
				continue
			}
			// for an add or update, just slap in the new value
			t.routes[canonicals[i]] = stored[V]{value: mutation.Value}
		}
		// big changes, so time to rebuild the index from scratch
		return t.rebuild()
	}

	// value-only: keep the compiled index, republish a patched vector
	current := t.current.Load()
	// make a new copy of current values, so nothing tramples stuff in use
	values := make([]V, len(current.values))
	copy(values, current.values)
	for i, mutation := range mutations {
		// grab the entry and tweak its value
		entry := t.routes[canonicals[i]]
		entry.value = mutation.Value
		t.routes[canonicals[i]] = entry
		// flip the value at the right index too, so everything lines up
		values[entry.id] = mutation.Value
	}
	// stash the shiny new snapshot so everyone sees the right data
	t.current.Store(&snapshot[V]{index: current.index, values: values})
	return nil
}

// rebuild recompiles the index and records the new route ids. caller holds mu
//
// we feed every live prefix through a fresh Builder (ids get reassigned), write
// the ids back onto routes, then build a values vector indexed by those ids
// slot 0 stays the zero value - the trees never yield id 0 as a hit
func (t *Table[V]) rebuild() error {
	builder := NewBuilder()
	for prefix, entry := range t.routes {
		id, err := builder.Add(prefix)
		if err != nil {
			return err
		}
		entry.id = id
		t.routes[prefix] = entry
	}
	values := make([]V, builder.Routes()+1)
	for _, entry := range t.routes {
		values[entry.id] = entry.value
	}
	t.current.Store(&snapshot[V]{index: builder.Build(), values: values})
	return nil
}
