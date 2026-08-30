// Package bitwalk is bitlpm plus parent links and recursive descendant
// walks. Topology for free if you're already paying for a bit trie, which
// we weren't willing to - 128 hops on v6 is still the deal-breaker. Kept
// as the walk backend behind fibbitwalk
package bitwalk

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type node struct {
	child  [2]uint32
	parent uint32
	value  uint32
}

// Table is an immutable topology-preserving arena trie. LPM, ancestor walks,
// and recursive descendant walks without per-result storage. Honest: we
// still walk one bit at a time
type Table[V any] struct {
	v4     []node
	v6     []node
	values []V
}

// New builds an immutable hierarchy index. Same insert loop as bitlpm;
// parent is stamped when we allocate a child
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

// insert4 walks the IPv4 key bit-by-bit, allocating missing children with
// parent back-links, then parks the value at the terminal. Last insert wins
func (t *Table[V]) insert4(key uint32, bits int, value uint32) {
	n := uint32(0)
	for depth := 0; depth < bits; depth++ {
		direction := (key >> (31 - depth)) & 1
		next := t.v4[n].child[direction]
		if next == 0 {
			t.v4 = append(t.v4, node{parent: n})
			next = uint32(len(t.v4) - 1)
			t.v4[n].child[direction] = next
		}
		n = next
	}
	t.v4[n].value = value
}

// insert6 is insert4 for 128 bits. Parent links are the only extra vs bitlpm
func (t *Table[V]) insert6(hi, lo uint64, bits int, value uint32) {
	n := uint32(0)
	for depth := 0; depth < bits; depth++ {
		direction := uint32(0)
		if prefixentry.Bit6(hi, lo, depth) != 0 {
			direction = 1
		}
		next := t.v6[n].child[direction]
		if next == 0 {
			t.v6 = append(t.v6, node{parent: n})
			next = uint32(len(t.v6) - 1)
			t.v6[n].child[direction] = next
		}
		n = next
	}
	t.v6[n].value = value
}

// Lookup performs longest-prefix matching. We throw away the node id that
// lookupNode found; WalkParents reconstructs the path itself
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	_, value, ok := t.lookupNode(addr)
	return value, ok
}

// lookupNode walks the matching family trie, remembering the last node that
// held a value. Returns that node so a caller could chase parents - we
// don't actually use the parent links on the hot path, they're leftover
func (t *Table[V]) lookupNode(addr netip.Addr) (uint32, V, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		var zero V
		return 0, zero, false
	}
	if addr.Is4() {
		key, n, found := prefixentry.Addr4(addr), uint32(0), t.v4[0].value
		foundNode := uint32(0)
		for depth := 0; depth < 32; depth++ {
			n = t.v4[n].child[(key>>(31-depth))&1]
			if n == 0 {
				break
			}
			if value := t.v4[n].value; value != 0 {
				found, foundNode = value, n
			}
		}
		if found != 0 {
			return foundNode, t.values[found], true
		}
	} else {
		hi, lo := prefixentry.Addr6(addr)
		n, found, foundNode := uint32(0), t.v6[0].value, uint32(0)
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
				found, foundNode = value, n
			}
		}
		if found != 0 {
			return foundNode, t.values[found], true
		}
	}
	var zero V
	return 0, zero, false
}

// WalkParents visits matching prefixes from most-specific to least-specific
// We record the descent path then walk it backwards, skipping empty nodes
// Prefix is reconstructed from the query addr plus depth - cheaper than
// chasing parent links, which is a bit embarrassing given we stored them
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(netip.Prefix, V) bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		return
	}
	if addr.Is4() {
		key, n := prefixentry.Addr4(addr), uint32(0)
		var path [33]uint32
		depth := 0
		for ; depth < 32; depth++ {
			n = t.v4[n].child[(key>>(31-depth))&1]
			if n == 0 {
				break
			}
			path[depth+1] = n
		}
		for i := depth; i >= 0; i-- {
			if value := t.v4[path[i]].value; value != 0 && !yield(netip.PrefixFrom(addr, i).Masked(), t.values[value]) {
				return
			}
		}
		return
	}
	hi, lo := prefixentry.Addr6(addr)
	n := uint32(0)
	var path [129]uint32
	depth := 0
	for ; depth < 128; depth++ {
		direction := uint32(0)
		if prefixentry.Bit6(hi, lo, depth) != 0 {
			direction = 1
		}
		n = t.v6[n].child[direction]
		if n == 0 {
			break
		}
		path[depth+1] = n
	}
	for i := depth; i >= 0; i-- {
		if value := t.v6[path[i]].value; value != 0 && !yield(netip.PrefixFrom(addr, i).Masked(), t.values[value]) {
			return
		}
	}
}

// WalkDescendants visits an exact prefix and all stored descendants in prefix
// order. We first walk the exact path (fail if any hop is missing or the
// terminal has no value), then recurse left-then-right, flipping the bit
// that distinguishes the right child
func (t *Table[V]) WalkDescendants(input netip.Prefix, yield func(netip.Prefix, V) bool) bool {
	prefix, ok := prefixentry.NormalizePrefix(input)
	if !ok {
		return false
	}
	if prefix.Addr().Is4() {
		key, n := prefixentry.Addr4(prefix.Addr()), uint32(0)
		for depth := 0; depth < prefix.Bits(); depth++ {
			n = t.v4[n].child[(key>>(31-depth))&1]
			if n == 0 {
				return false
			}
		}
		if t.v4[n].value == 0 {
			return false
		}
		t.walk4(n, key, prefix.Bits(), yield)
		return true
	}
	hi, lo := prefixentry.Addr6(prefix.Addr())
	n := uint32(0)
	for depth := 0; depth < prefix.Bits(); depth++ {
		direction := uint32(0)
		if prefixentry.Bit6(hi, lo, depth) != 0 {
			direction = 1
		}
		n = t.v6[n].child[direction]
		if n == 0 {
			return false
		}
	}
	if t.v6[n].value == 0 {
		return false
	}
	t.walk6(n, hi, lo, prefix.Bits(), yield)
	return true
}

// walk4 DFS-emits this node then left then right. We rebuild the prefix
// from the accumulated key so we don't have to store it on every node
func (t *Table[V]) walk4(n uint32, key uint32, depth int, yield func(netip.Prefix, V) bool) bool {
	if value := t.v4[n].value; value != 0 {
		addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
		if !yield(netip.PrefixFrom(addr, depth), t.values[value]) {
			return false
		}
	}
	if left := t.v4[n].child[0]; left != 0 && !t.walk4(left, key, depth+1, yield) {
		return false
	}
	if right := t.v4[n].child[1]; right != 0 {
		return t.walk4(right, key|uint32(1)<<(31-depth), depth+1, yield)
	}
	return true
}

// walk6 is walk4 for 128 bits. Right-child bit is flipped in hi or lo
// depending on depth, because of course it is
func (t *Table[V]) walk6(n uint32, hi, lo uint64, depth int, yield func(netip.Prefix, V) bool) bool {
	if value := t.v6[n].value; value != 0 {
		var a [16]byte
		for i := range 8 {
			a[i], a[8+i] = byte(hi>>(56-8*i)), byte(lo>>(56-8*i))
		}
		if !yield(netip.PrefixFrom(netip.AddrFrom16(a), depth), t.values[value]) {
			return false
		}
	}
	if left := t.v6[n].child[0]; left != 0 && !t.walk6(left, hi, lo, depth+1, yield) {
		return false
	}
	if right := t.v6[n].child[1]; right != 0 {
		if depth < 64 {
			hi |= uint64(1) << (63 - depth)
		} else {
			lo |= uint64(1) << (127 - depth)
		}
		return t.walk6(right, hi, lo, depth+1, yield)
	}
	return true
}

// Nodes returns the number of arena nodes retained by the table
func (t *Table[V]) Nodes() int { return len(t.v4) + len(t.v6) }
