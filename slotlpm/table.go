package slotlpm

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
)

// snapshot is one published generation: an immutable index plus the value
// vector it indexes into
type snapshot[V any] struct {
	index  *Index
	values []V
}

// key6 is one stored IPv6 prefix, masked
type key6 struct {
	high, low uint64
	bits      uint8
}

// less6 orders IPv6 keys by (high, low, bits) - the packed slice order
func less6(a, b key6) bool {
	if a.high != b.high {
		return a.high < b.high
	}
	if a.low != b.low {
		return a.low < b.low
	}
	return a.bits < b.bits
}

// Table is a managed value LPM table - readers perform one atomic load, one index
// lookup and one value load, and never block
//
// # The authoritative set is packed, not a map
//
// steplpm keeps its prefixes in a map[netip.Prefix]. That key is 32 bytes and
// Go's map adds control bytes and load-factor slack on top: measured at 100k
// prefixes the map alone retained 77 bytes per prefix, five times the compiled
// index it exists to rebuild - here the prefixes live in sorted packed slices -
// eight bytes per IPv4 prefix, twenty-four per IPv6 - searched by binary search
// and mutated by a splice, alongside a parallel value slice
//
// Route ids follow that order, IPv4 first, so a rebuild assigns them by walking
// the slices and needs no map at all - insert and delete become O(n) moves rather
// than O(1) hash operations, which is the right trade for a structure whose
// reads outnumber its writes by orders of magnitude
type Table[V any] struct {
	current atomic.Pointer[snapshot[V]]

	mu    sync.Mutex
	keys4 []uint64 // key<<8 | bits, ascending, unique
	vals4 []V
	keys6 []key6 // ascending, unique
	vals6 []V
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

// New builds a Table from entries - duplicate prefixes take the last value
func New[V any](entries []Entry[V]) (*Table[V], error) {
	t := new(Table[V])
	if err := t.Reset(entries); err != nil {
		return nil, err
	}
	return t, nil
}

// Lookup returns the value of the longest prefix covering addr
// Readers never take mu - one atomic load of the published snapshot
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
func (t *Table[V]) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys4) + len(t.keys6)
}

// Reset replaces the whole table
// We pack, stable-sort so later duplicates sit last, then collapse them while
// holding the lock and rebuild
func (t *Table[V]) Reset(entries []Entry[V]) error {
	type packed4 struct {
		key   uint64
		value V
	}
	type packed6 struct {
		key   key6
		value V
	}
	list4 := make([]packed4, 0, len(entries))
	list6 := make([]packed6, 0, len(entries)/8+1)
	for _, entry := range entries {
		key, high, low, bits, is4, ok := decompose(entry.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		if is4 {
			list4 = append(list4, packed4{key: uint64(key)<<8 | uint64(bits), value: entry.Value})
			continue
		}
		list6 = append(list6, packed6{key: key6{high: high, low: low, bits: bits}, value: entry.Value})
	}
	sort.SliceStable(list4, func(i, j int) bool { return list4[i].key < list4[j].key })
	sort.SliceStable(list6, func(i, j int) bool { return less6(list6[i].key, list6[j].key) })

	t.mu.Lock()
	defer t.mu.Unlock()
	t.keys4 = t.keys4[:0]
	t.vals4 = t.vals4[:0]
	for _, item := range list4 {
		// later duplicates win, matching every other index here
		if n := len(t.keys4); n > 0 && t.keys4[n-1] == item.key {
			t.vals4[n-1] = item.value
			continue
		}
		t.keys4 = append(t.keys4, item.key)
		t.vals4 = append(t.vals4, item.value)
	}
	t.keys6 = t.keys6[:0]
	t.vals6 = t.vals6[:0]
	for _, item := range list6 {
		if n := len(t.keys6); n > 0 && t.keys6[n-1] == item.key {
			t.vals6[n-1] = item.value
			continue
		}
		t.keys6 = append(t.keys6, item.key)
		t.vals6 = append(t.vals6, item.value)
	}
	return t.rebuild()
}

// Insert adds or updates one prefix - one-entry ApplyBatch
func (t *Table[V]) Insert(prefix netip.Prefix, value V) error {
	return t.ApplyBatch([]Mutation[V]{{Prefix: prefix, Value: value}})
}

// Delete removes a prefix - it reports whether the prefix was present
// Binary search the packed slice, splice it out, rebuild
func (t *Table[V]) Delete(prefix netip.Prefix) bool {
	key, high, low, bits, is4, ok := decompose(prefix)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if is4 {
		packed := uint64(key)<<8 | uint64(bits)
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

// ApplyBatch applies mutations in order and publishes one generation - when no
// mutation adds or removes a prefix, the index is reused and only the value
// vector is republished
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
		key, high, low, bits, is4, ok := decompose(mutation.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		item := located{is4: is4, mutation: mutation}
		if is4 {
			item.packed = uint64(key)<<8 | uint64(bits)
			item.at = sort.Search(len(t.keys4), func(j int) bool { return t.keys4[j] >= item.packed })
			item.exists = item.at < len(t.keys4) && t.keys4[item.at] == item.packed
		} else {
			item.key = key6{high: high, low: low, bits: bits}
			item.at = sort.Search(len(t.keys6), func(j int) bool { return !less6(t.keys6[j], item.key) })
			item.exists = item.at < len(t.keys6) && t.keys6[item.at] == item.key
		}
		if item.exists == mutation.Delete {
			structural = true
		}
		found[i] = item
	}

	if structural {
		for _, item := range found {
			t.apply(item.is4, item.packed, item.key, item.mutation)
		}
		return t.rebuild()
	}

	// value-only: the index and the route ids are unchanged
	current := t.current.Load()
	values := make([]V, len(current.values))
	copy(values, current.values)
	for _, item := range found {
		if !item.exists {
			continue
		}
		if item.is4 {
			t.vals4[item.at] = item.mutation.Value
			// ids are 1-based and IPv4 comes first
			values[item.at+1] = item.mutation.Value
			continue
		}
		t.vals6[item.at] = item.mutation.Value
		values[len(t.keys4)+item.at+1] = item.mutation.Value
	}
	t.current.Store(&snapshot[V]{index: current.index, values: values})
	return nil
}

// apply performs one structural change - the caller holds mu
// We re-search because earlier mutations in the same batch may have shifted
// the insertion point
func (t *Table[V]) apply(is4 bool, packed uint64, wanted key6, mutation Mutation[V]) {
	if is4 {
		at := sort.Search(len(t.keys4), func(i int) bool { return t.keys4[i] >= packed })
		exists := at < len(t.keys4) && t.keys4[at] == packed
		switch {
		case mutation.Delete && exists:
			t.keys4 = append(t.keys4[:at], t.keys4[at+1:]...)
			t.vals4 = append(t.vals4[:at], t.vals4[at+1:]...)
		case !mutation.Delete && exists:
			t.vals4[at] = mutation.Value
		case !mutation.Delete:
			t.keys4 = insertSlice(t.keys4, at, packed)
			t.vals4 = insertSlice(t.vals4, at, mutation.Value)
		}
		return
	}
	at := sort.Search(len(t.keys6), func(i int) bool { return !less6(t.keys6[i], wanted) })
	exists := at < len(t.keys6) && t.keys6[at] == wanted
	switch {
	case mutation.Delete && exists:
		t.keys6 = append(t.keys6[:at], t.keys6[at+1:]...)
		t.vals6 = append(t.vals6[:at], t.vals6[at+1:]...)
	case !mutation.Delete && exists:
		t.vals6[at] = mutation.Value
	case !mutation.Delete:
		t.keys6 = insertSlice(t.keys6, at, wanted)
		t.vals6 = insertSlice(t.vals6, at, mutation.Value)
	}
}

// insertSlice splices value into items at at, shifting the tail up
func insertSlice[T any](items []T, at int, value T) []T {
	var zero T
	items = append(items, zero)
	copy(items[at+1:], items[at:])
	items[at] = value
	return items
}

// All calls fn for every stored prefix, IPv4 first, each family ascending
// We copy under the lock then iterate unlocked so fn can take its time
func (t *Table[V]) All(fn func(netip.Prefix, V) bool) {
	t.mu.Lock()
	keys4 := append([]uint64(nil), t.keys4...)
	vals4 := append([]V(nil), t.vals4...)
	keys6 := append([]key6(nil), t.keys6...)
	vals6 := append([]V(nil), t.vals6...)
	t.mu.Unlock()
	for i, packed := range keys4 {
		key, bits := uint32(packed>>8), uint8(packed&0xff)
		addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
		if !fn(netip.PrefixFrom(addr, int(bits)), vals4[i]) {
			return
		}
	}
	for i, k := range keys6 {
		var b [16]byte
		for j := 0; j < 8; j++ {
			b[j] = byte(k.high >> (56 - j*8))
			b[8+j] = byte(k.low >> (56 - j*8))
		}
		if !fn(netip.PrefixFrom(netip.AddrFrom16(b), int(k.bits)), vals6[i]) {
			return
		}
	}
}

// rebuild recompiles the index - route ids follow the packed order, IPv4 first,
// so no prefix-to-id map is needed - the caller holds mu
func (t *Table[V]) rebuild() error {
	builder := NewBuilder()
	for _, packed := range t.keys4 {
		builder.AddKey4(uint32(packed>>8), uint8(packed&0xff))
	}
	for _, k := range t.keys6 {
		builder.AddKey6(k.high, k.low, k.bits)
	}
	values := make([]V, 1+len(t.vals4)+len(t.vals6))
	copy(values[1:], t.vals4)
	copy(values[1+len(t.vals4):], t.vals6)
	t.current.Store(&snapshot[V]{index: builder.Build(), values: values})
	return nil
}

// decompose validates a prefix and returns its masked key
func decompose(prefix netip.Prefix) (key uint32, high, low uint64, bits uint8, is4, ok bool) {
	if !prefix.IsValid() {
		return 0, 0, 0, 0, false, false
	}
	addr := prefix.Addr()
	length := prefix.Bits()
	if addr.Is4In6() {
		if length < 96 {
			return 0, 0, 0, 0, false, false
		}
		addr = addr.Unmap()
		length -= 96
	}
	if addr.Zone() != "" {
		return 0, 0, 0, 0, false, false
	}
	if addr.Is4() {
		if length > 32 {
			return 0, 0, 0, 0, false, false
		}
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		return be32(addr.As4()) & mask, 0, 0, uint8(length), true, true
	}
	if length > 128 {
		return 0, 0, 0, 0, false, false
	}
	high, low = words16(addr.As16())
	maskHigh, maskLow := masks128(length)
	return 0, high & maskHigh, low & maskLow, uint8(length), false, true
}
