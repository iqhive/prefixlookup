package aosart

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
)

// Index is the compiled AoS ART: two trees (v4/v6) plus a route count
//
// same ART as soaart, but each node is one struct so a descent touches two
// cache lines not four. route id 0 means no match. immutable, readers never
// lock - Table atomically swaps a pointer to a new one
type Index struct {
	v4     tree
	v6     tree
	routes int
}

// Routes returns how many distinct prefixes we stored
// just the counter Build stamped on us, we don't walk the trees
func (x *Index) Routes() int { return x.routes }

// Nodes returns the node count per family, for tests and reporting
// len(nodes) is the count - empty trees set nodes to nil so this is 0
func (x *Index) Nodes() (v4, v6 int) { return len(x.v4.nodes), len(x.v6.nodes) }

// RetainedBytes reports the bytes the compiled index actually holds
// a node is 96 bytes (two cache lines, padding included). items 4, leaves 24
// we count slice lengths not unsafe.Sizeof on the headers
func (x *Index) RetainedBytes() int {
	// size is the retained footprint of one family's compiled tree
	size := func(t *tree) int {
		return 96*len(t.nodes) + 4*len(t.pfxItems) + 4*len(t.kidItems) + 24*len(t.leaves)
	}
	return size(&x.v4) + size(&x.v6)
}

// Lookup returns the route id of the longest prefix covering addr, or 0
//
// we pick the family, pack the addr into the 128-bit key the tree walks, and
// hand off - IPv4 lives in the high word shifted up 32 so octetAt at depth 0..3
// still works. mapped 4in6 gets Unmap'd into the v4 tree; invalid addrs miss
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
// decomposeKey masks and family-splits; we don't build a canonical
// netip.Prefix because AddrFrom4/16 is wasted on this path
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
// rebuild netip.Prefix from the masked key so a /8 comes out as 10.0.0.0/8
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
// decomposeKey then walkSubnets; false means the query isn't in the table, not
// "no descendants"
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
// the vector and reuses the index
type snapshot[V any] struct {
	index  *Index
	values []V
}

// key6 is one stored IPv6 prefix, masked
// 16-byte addr plus a length, packed so the writer's catalogue isn't a
// map[netip.Prefix]
type key6 struct {
	high, low uint64
	bits      uint8
}

// less6 orders key6 by high, then low, then bits
// that's the packed-slice sort key: address first, shorter prefix first when
// the addr ties - same preorder the rebuild walks
func less6(a, b key6) bool {
	if a.high != b.high {
		return a.high < b.high
	}
	if a.low != b.low {
		return a.low < b.low
	}
	return a.bits < b.bits
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
// the authoritative prefix set is held in sorted packed slices - eight bytes
// per IPv4 prefix, twenty-four per IPv6 - rather than a map[netip.Prefix],
// whose 32-byte key plus control bytes and load-factor slack measured at 76
// bytes per prefix, six times the compiled index it exists to rebuild. route
// ids follow the packed order, IPv4 first, so a rebuild needs no prefix-to-id
// map
type Table[V any] struct {
	current atomic.Pointer[snapshot[V]]

	mu    sync.Mutex
	keys4 []uint64 // key<<8 | bits, ascending, unique
	vals4 []V
	keys6 []key6
	vals6 []V
}

// New builds a Table from entries. duplicate prefixes take the last value
// we just construct and Reset - that's how the first generation gets published
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
//
// the tree is driven directly rather than through Index.WalkSupernets, so a
// yielded prefix passes through one closure instead of two. with a mean chain
// of two to three ancestors, that indirection was a measurable share of the
// cost. treeFor decodes the addr once
func (t *Table[V]) WalkSupernets(addr netip.Addr, yield func(netip.Prefix, V) bool) {
	s := t.current.Load()
	tree, high, low, is4, ok := s.index.treeFor(addr)
	if !ok {
		return
	}
	values := s.values
	tree.walkSupernets(high, low, func(m match) bool {
		return yield(netip.PrefixFrom(addrOf(m.high, m.low, is4), int(m.bits)), values[m.id])
	})
}

// WalkSubnets visits prefix and every stored prefix contained in it
// we skip Index.WalkSubnets the same way WalkSupernets does - one closure, not
// two. decomposeKey then pick the family tree
func (t *Table[V]) WalkSubnets(prefix netip.Prefix, yield func(netip.Prefix, V) bool) bool {
	s := t.current.Load()
	high, low, bits, is4, ok := decomposeKey(prefix)
	if !ok {
		return false
	}
	tree := &s.index.v4
	if !is4 {
		tree = &s.index.v6
	}
	values := s.values
	return tree.walkSubnets(high, low, bits, func(m match) bool {
		return yield(netip.PrefixFrom(addrOf(m.high, m.low, is4), int(m.bits)), values[m.id])
	})
}

// treeFor decodes an address once and selects the family's tree
// same 4 / 4in6 / invalid / v6 split as Lookup, but we return the packed key
// and a bool so WalkSupernets doesn't decode twice
func (x *Index) treeFor(addr netip.Addr) (*tree, uint64, uint64, bool, bool) {
	switch {
	case addr.Is4():
		return &x.v4, uint64(be32(addr.As4())) << 32, 0, true, true
	case addr.Is4In6():
		return &x.v4, uint64(be32(addr.Unmap().As4())) << 32, 0, true, true
	case !addr.IsValid():
		return nil, 0, 0, false, false
	}
	high, low := words16(addr.As16())
	return &x.v6, high, low, false, true
}

// Index returns the currently published immutable index
// just the snapshot's pointer
func (t *Table[V]) Index() *Index { return t.current.Load().index }

// Size returns the number of stored prefixes
// we lock because the packed slices are the writer's copy
func (t *Table[V]) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys4) + len(t.keys6)
}

// Reset replaces the whole table
//
// we pack into two lists, sort stably so last duplicate keeps its value, then
// under the lock compact unique keys into the writer's slices and rebuild
// SliceStable not Slice because "last entry wins" has to survive the sort
func (t *Table[V]) Reset(entries []Entry[V]) error {
	type packed4 struct {
		key   uint64
		value V
	}
	type packed6 struct {
		key   key6
		value V
	}
	// prepping up the slices for the two families, size them right from the get-go
	list4 := make([]packed4, 0, len(entries))
	list6 := make([]packed6, 0, len(entries)/8+1)
	for _, entry := range entries {
		high, low, bits, is4, ok := decomposeKey(entry.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		if is4 {
			// smashing the important bits from high and bits into a lovely packed uint64 for v4
			list4 = append(list4, packed4{key: uint64(uint32(high>>32))<<8 | uint64(bits), value: entry.Value})
			continue
		}
		// bundle up v6 stuff into our key6 type, hangs onto high, low, and bits snug
		list6 = append(list6, packed6{key: key6{high: high, low: low, bits: bits}, value: entry.Value})
	}
	// gotta get all the v4 keys sorted, but keep duplicates in original order, so later values win
	sort.SliceStable(list4, func(i, j int) bool { return list4[i].key < list4[j].key })
	// v6's a bit trickier, so we rely on less6 to do the job properly
	sort.SliceStable(list6, func(i, j int) bool { return less6(list6[i].key, list6[j].key) })

	t.mu.Lock()
	defer t.mu.Unlock()
	// slice clearout: start with fresh (but same-backed) key and value slices
	t.keys4, t.vals4 = t.keys4[:0], t.vals4[:0]
	for _, item := range list4 {
		// last one wins for dups: if the current key matches the previous, update only
		if n := len(t.keys4); n > 0 && t.keys4[n-1] == item.key {
			t.vals4[n-1] = item.value
			continue
		}
		// new key, so slide it in, keeping slices lined up
		t.keys4 = append(t.keys4, item.key)
		t.vals4 = append(t.vals4, item.value)
	}
	// do the same dance for v6 stuff
	t.keys6, t.vals6 = t.keys6[:0], t.vals6[:0]
	for _, item := range list6 {
		if n := len(t.keys6); n > 0 && t.keys6[n-1] == item.key {
			t.vals6[n-1] = item.value
			continue
		}
		t.keys6 = append(t.keys6, item.key)
		t.vals6 = append(t.vals6, item.value)
	}
	// right, time to rebuild the index with the new slices
	return t.rebuild()
}

// Insert adds or updates one prefix - just a one-entry ApplyBatch
func (t *Table[V]) Insert(prefix netip.Prefix, value V) error {
	return t.ApplyBatch([]Mutation[V]{{Prefix: prefix, Value: value}})
}

// Delete removes a prefix. reports whether the prefix was present
// bsearch the packed slice, splice out both key and value, rebuild. missing /
// invalid don't rebuild
func (t *Table[V]) Delete(prefix netip.Prefix) bool {
	high, low, bits, is4, ok := decomposeKey(prefix)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if is4 {
		packed := uint64(uint32(high>>32))<<8 | uint64(bits)
		at := sort.Search(len(t.keys4), func(i int) bool { return t.keys4[i] >= packed })
		if at >= len(t.keys4) || t.keys4[at] != packed {
			return false
		}
		t.keys4 = append(t.keys4[:at], t.keys4[at+1:]...)
		t.vals4 = append(t.vals4[:at], t.vals4[at+1:]...)
	} else {
		want := key6{high: high, low: low, bits: bits}
		at := sort.Search(len(t.keys6), func(i int) bool { return !less6(t.keys6[i], want) })
		if at >= len(t.keys6) || t.keys6[at] != want {
			return false
		}
		t.keys6 = append(t.keys6[:at], t.keys6[at+1:]...)
		t.vals6 = append(t.vals6[:at], t.vals6[at+1:]...)
	}
	_ = t.rebuild()
	return true
}

// ApplyBatch applies mutations in order and publishes one generation
//
// first pass: locate every prefix in the packed slices and decide structural
// vs value-only. exists == Delete means the prefix set changes
//
// structural: apply() each mutation (re-bsearch because earlier ones in the
// batch may have shifted indices) then rebuild. value-only: copy the published
// vector and patch. v4 ids are at+1, v6 ids are len(keys4)+at+1, because id 0
// is unused and IPv4 is numbered first
func (t *Table[V]) ApplyBatch(mutations []Mutation[V]) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	type located struct {
		at       int
		is4      bool
		exists   bool
		packed   uint64
		key      key6
		mutation Mutation[V]
	}
	found := make([]located, len(mutations))
	structural := false
	for i, mutation := range mutations {
		high, low, bits, is4, ok := decomposeKey(mutation.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		item := located{is4: is4, mutation: mutation}
		if is4 {
			// packed up the ipv4 prefix into a single number so it's easy to bsearch
			item.packed = uint64(uint32(high>>32))<<8 | uint64(bits)

			// bsearch the v4 keys to find where this one's hiding (or should go)
			item.at = sort.Search(len(t.keys4), func(j int) bool { return t.keys4[j] >= item.packed })

			// double check if this is an exact key match sitting at that spot
			item.exists = item.at < len(t.keys4) && t.keys4[item.at] == item.packed
		} else {
			// slap together the key6 for v6 prefixes
			item.key = key6{high: high, low: low, bits: bits}

			// find the insert or match spot for v6 - careful with less6 here
			item.at = sort.Search(len(t.keys6), func(j int) bool { return !less6(t.keys6[j], item.key) })

			// ok, did we get an exact v6 match? have a squiz
			item.exists = item.at < len(t.keys6) && t.keys6[item.at] == item.key
		}
		// if the mutation is actually flipping the presence (eg, deleting one that exists)
		if item.exists == mutation.Delete {
			structural = true
		}
		found[i] = item
	}

	if structural {
		// right, something actually changed the shape of the set, so full rebuild
		for _, item := range found {
			t.apply(item.is4, item.packed, item.key, item.mutation)
		}
		return t.rebuild()
	}

	// just value changes, so reuse the structure but patch values
	current := t.current.Load()
	values := make([]V, len(current.values))
	copy(values, current.values)
	for _, item := range found {
		// skip if there's nothing at this spot to update
		if !item.exists {
			continue
		}
		if item.is4 {
			// sweet, patch ipv4 value in place, also do the published snapshot
			t.vals4[item.at] = item.mutation.Value

			// +1 'cause route IDs start at 1 for v4
			values[item.at+1] = item.mutation.Value
			continue
		}
		// update ipv6 in place, fix up right slot in values too (offset by len(keys4)+1)
		t.vals6[item.at] = item.mutation.Value
		values[len(t.keys4)+item.at+1] = item.mutation.Value
	}
	// snap in the new set of values for current reads
	t.current.Store(&snapshot[V]{index: current.index, values: values})
	return nil
}

// apply performs one structural change. caller holds mu
//
// we re-bsearch because a prior mutation in the batch may have inserted or
// deleted and shifted `at`. delete-and-exists splices out, insert-and-exists
// overwrites the value, insert-and-missing splices in. delete-and-missing is
// a no-op
func (t *Table[V]) apply(is4 bool, packed uint64, wanted key6, mutation Mutation[V]) {
	if is4 {
		// use sort.Search to find where this packed v4 key should be sitting
		at := sort.Search(len(t.keys4), func(i int) bool { return t.keys4[i] >= packed })

		// check if there's actually something at that exact spot
		exists := at < len(t.keys4) && t.keys4[at] == packed

		switch {
		case mutation.Delete && exists:
			// yank the key and matching value straight out of their slices, nice and tidy
			t.keys4 = append(t.keys4[:at], t.keys4[at+1:]...)
			t.vals4 = append(t.vals4[:at], t.vals4[at+1:]...)
		case !mutation.Delete && exists:
			// just swapping the value in place if it already exists
			t.vals4[at] = mutation.Value
		case !mutation.Delete:
			// chucking in a new key/value at the right spot - slices stay sorted
			t.keys4 = insertSlice(t.keys4, at, packed)
			t.vals4 = insertSlice(t.vals4, at, mutation.Value)
		}
		return
	}
	// deal with IPv6 if we made it this far
	// similar vibe: use sort.Search to figure out where the v6 key belongs by using less6
	at := sort.Search(len(t.keys6), func(i int) bool { return !less6(t.keys6[i], wanted) })

	// now see if it's actually there or just would've gone there if it were present
	exists := at < len(t.keys6) && t.keys6[at] == wanted

	switch {
	case mutation.Delete && exists:
		// snip out the matching v6 key and value if we're deleting and it actually exists
		t.keys6 = append(t.keys6[:at], t.keys6[at+1:]...)
		t.vals6 = append(t.vals6[:at], t.vals6[at+1:]...)
	case !mutation.Delete && exists:
		// update the value at its spot, nothing else changes
		t.vals6[at] = mutation.Value
	case !mutation.Delete:
		// it was missing, so slot key and value in where they belong to keep us sorted
		t.keys6 = insertSlice(t.keys6, at, wanted)
		t.vals6 = insertSlice(t.vals6, at, mutation.Value)
	}
}

// insertSlice splices value into items at at, shifting the tail up
// append a zero then copy the tail forward - same as soaart's insertAt
func insertSlice[T any](items []T, at int, value T) []T {
	var zero T
	items = append(items, zero)
	copy(items[at+1:], items[at:])
	items[at] = value
	return items
}

// rebuild recompiles the index. route ids follow the packed order, IPv4 first
// caller holds mu
//
// AddKey4/AddKey6 skip the builder's ids map because the slices are already
// unique. values[0] stays zero, then vals4, then vals6 - that's why a value-
// only patch can compute the slot as at+1 / len(keys4)+at+1
func (t *Table[V]) rebuild() error {
	builder := NewBuilder()
	// each packed v4 key gets added, slicing out address bits and mask bits
	for _, packed := range t.keys4 {
		// chuck the address into AddKey4, top bits for IP, bottom 8 for prefix size
		builder.AddKey4(uint32(packed>>8), uint8(packed&0xff))
	}
	for _, k := range t.keys6 {
		// add every v6 key, which already comes split out into high, low, and bits
		builder.AddKey6(k.high, k.low, k.bits)
	}
	values := make([]V, 1+len(t.vals4)+len(t.vals6))
	// first slot is always zero, then bang in all v4 values after that
	copy(values[1:], t.vals4)
	// v6 values come after the v4s - gotta keep this order for route ids to match
	copy(values[1+len(t.vals4):], t.vals6)
	// slam the freshly built index and value list into t.current.atomic for readers
	t.current.Store(&snapshot[V]{index: builder.Build(), values: values})
	return nil
}
