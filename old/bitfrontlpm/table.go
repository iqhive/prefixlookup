// Package bitfrontlpm is bitlpm plus a cache-sized IPv4 /16 front table
// most v4 lookups are one indexed load then a 16-bit resume, v6 still
// walks 128 bits - we outgrew the v6 path and the front table is basically
// what compiledfib does better, so this stayed as a hybrid experiment
package bitfrontlpm

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type node struct {
	child [2]uint32
	value uint32
}

type slot struct{ node, value uint32 }

// Table combines a cache-sized IPv4 /16 forwarding table with private compact
// arena tries. Most IPv4 lookups need one indexed load; longer prefixes resume
// at depth 16. IPv6 uses the compact arena because a v6 FIB of this shape
// would be huge
type Table[V any] struct {
	v4     []node
	v6     []node
	values []V
	front  [1 << 16]slot
}

// New builds an immutable hybrid FIB/RIB lookup table. Insert everything
// into the bit tries first, then pre-walk the first 16 v4 bits into front
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	t := &Table[V]{
		v4:     make([]node, 1, 1+len(entries)*4),
		v6:     make([]node, 1, 1+len(entries)*4),
		values: make([]V, 1, len(entries)+1),
	}
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
	// precompute each /16: best match so far plus the node to resume from
	for key := 0; key < 1<<16; key++ {
		n, found := uint32(0), t.v4[0].value
		for depth := 0; depth < 16; depth++ {
			n = t.v4[n].child[(uint32(key)>>(15-depth))&1]
			if n == 0 {
				break
			}
			if value := t.v4[n].value; value != 0 {
				found = value
			}
		}
		t.front[key] = slot{n, found}
	}
	return t, nil
}

// insert4 walks the IPv4 key bit-by-bit, allocating missing children, then
// parks the value at the terminal. Last insert wins. Same as bitlpm
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

// insert6 is insert4 for 128 bits. No front table here; v6 stays a full walk
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

// Lookup performs lock-free longest-prefix matching. v6 is a full 128-bit
// walk; v4 consults front then resumes from depth 16 if that slot has a node
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		var zero V
		return zero, false
	}
	if !addr.Is4() {
		hi, lo := prefixentry.Addr6(addr)
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
	key := prefixentry.Addr4(addr)
	front := t.front[key>>16]
	found, n := front.value, front.node
	if n != 0 {
		// resume the remaining 16 bits; front already captured /16-or-shorter
		for depth := 16; depth < 32; depth++ {
			n = t.v4[n].child[(key>>(31-depth))&1]
			if n == 0 {
				break
			}
			if value := t.v4[n].value; value != 0 {
				found = value
			}
		}
	}
	if found != 0 {
		return t.values[found], true
	}
	var zero V
	return zero, false
}

// Nodes returns the compact backing trie node count. Front table is extra
func (t *Table[V]) Nodes() int { return len(t.v4) + len(t.v6) }
