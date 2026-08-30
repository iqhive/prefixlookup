// Package bitlpm is the obvious immutable binary trie: one node per bit,
// arena indexes so GC doesn't scan the structure. We used it as a correctness
// baseline; it's slow on IPv6 (128 hops) and we moved on to stride-8 ART
package bitlpm

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type node struct {
	child [2]uint32
	value uint32
}

// Table is an immutable, arena-backed binary trie. Index links keep each node
// compact and keep the GC off the trie. Fine as a building block, not a FIB
type Table[V any] struct {
	v4     []node
	v6     []node
	values []V
}

// New builds an immutable longest-prefix-match table. We normalise each
// entry, stash the payload, then bit-insert into the matching family arena
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	t := &Table[V]{v4: make([]node, 1, 1+len(entries)*4), v6: make([]node, 1, 1+len(entries)*4)}
	t.values = make([]V, 1, len(entries)+1)
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		t.values = append(t.values, entry.Value)
		value := uint32(len(t.values) - 1)
		if prefix.Addr().Is4() {
			t.insert4(prefixentry.Addr4(prefix.Addr()), prefix.Bits(), value)
		} else {
			hi, lo := prefixentry.Addr6(prefix.Addr())
			t.insert6(hi, lo, prefix.Bits(), value)
		}
	}
	return t, nil
}

// insert4 walks the IPv4 key bit-by-bit, allocating missing children as we
// go, then parks the value at the terminal node. Last insert wins on a clash
func (t *Table[V]) insert4(key uint32, bits int, value uint32) {
	n := uint32(0)
	for depth := 0; depth < bits; depth++ {
		direction := (key >> (31 - depth)) & 1
		next := t.v4[n].child[direction]
		if next == 0 {
			t.v4 = append(t.v4, node{})
			next = uint32(len(t.v4) - 1)
			t.v4[n].child[direction] = next
		}
		n = next
	}
	t.v4[n].value = value
}

// insert6 is insert4 for 128 bits. We pull each bit via Bit6 because the
// key is split across hi/lo. Same last-wins behaviour
func (t *Table[V]) insert6(hi, lo uint64, bits int, value uint32) {
	n := uint32(0)
	for depth := 0; depth < bits; depth++ {
		direction := uint32(0)
		if prefixentry.Bit6(hi, lo, depth) != 0 {
			direction = 1
		}
		next := t.v6[n].child[direction]
		if next == 0 {
			t.v6 = append(t.v6, node{})
			next = uint32(len(t.v6) - 1)
			t.v6[n].child[direction] = next
		}
		n = next
	}
	t.v6[n].value = value
}

// Lookup performs longest-prefix matching without locks or allocations
// Zones and invalid addrs are a miss; then we dispatch on family
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		var zero V
		return zero, false
	}
	if addr.Is4() {
		return t.lookup4(prefixentry.Addr4(addr))
	}
	hi, lo := prefixentry.Addr6(addr)
	return t.lookup6(hi, lo)
}

// lookup4 walks all 32 bits, remembering the last node that had a value
// Child 0 means the path ended; we return that remembered payload
func (t *Table[V]) lookup4(key uint32) (V, bool) {
	n, found := uint32(0), t.v4[0].value
	for depth := 0; depth < 32; depth++ {
		n = t.v4[n].child[(key>>(31-depth))&1]
		if n == 0 {
			break
		}
		if value := t.v4[n].value; value != 0 {
			found = value
		}
	}
	if found != 0 {
		return t.values[found], true
	}
	var zero V
	return zero, false
}

// lookup6 is lookup4 for 128 bits. This is why we don't ship a bit trie:
// sixteen times the hops of IPv4, every query
func (t *Table[V]) lookup6(hi, lo uint64) (V, bool) {
	n, found := uint32(0), t.v6[0].value
	for depth := 0; depth < 128; depth++ {
		direction := uint32(0)
		if prefixentry.Bit6(hi, lo, depth) != 0 {
			direction = 1
		}
		n = t.v6[n].child[direction]
		if n == 0 {
			break
		}
		if value := t.v6[n].value; value != 0 {
			found = value
		}
	}
	if found != 0 {
		return t.values[found], true
	}
	var zero V
	return zero, false
}

// Nodes returns the number of arena nodes retained by the table. Handy when
// we're arguing about memory vs stride tries
func (t *Table[V]) Nodes() int { return len(t.v4) + len(t.v6) }
