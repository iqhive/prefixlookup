// Package artwalk is the ART that actually retains the covering relation
// parent pointers, supernets, subnets, Parent() - fast LPM tables throw
// that hierarchy away on purpose, this is the trade
// we kept it as the walk analogue - lookup isn't terrible, but the extra
// 16 bytes/node and the reconstruct-prefix walk aren't what we want on the
// hot path
package artwalk

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

// Table supports tree walking in both directions - upward to every covering
// prefix (supernets) and downward to every covered prefix (subnets). That's
// the opposite of a fast FIB: we keep every ancestor and can name it. Not
// safe for concurrent mutation
type Table[V any] struct {
	root4 ribNode[V]
	root6 ribNode[V]
	size4 int
	size6 int
}

// ribNode is one stride, with the upward links a fast table omits
type ribNode[V any] struct {
	childBits art.Bitset256
	children  []*ribNode[V]
	pfxBits   art.Bitset512
	values    []V
	pfxCount  uint16

	// upward links and self-location, which make walking possible
	parent *ribNode[V]
	octet  uint8 // the octet within parent that reaches this node
	depth  uint8 // stride depth from the root
	is4    bool
}

// New returns an empty Table. We stamp is4 on the v4 root so prefixAt can
// reconstruct without a table pointer
func New[V any]() *Table[V] {
	r := &Table[V]{}
	r.root4.is4 = true
	return r
}

// Size returns the number of stored prefixes
func (r *Table[V]) Size() int { return r.size4 + r.size6 }

// rootFor picks the family root
func (r *Table[V]) rootFor(is4 bool) *ribNode[V] {
	if is4 {
		return &r.root4
	}
	return &r.root6
}

// Insert stores val for pfx, reporting whether the prefix was newly added
// Descend creating children with parent/octet/depth stamped, then splice
// the value into the ART-ranked slice
func (r *Table[V]) Insert(pfx netip.Prefix, val V) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	n := r.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		rank := n.childBits.Rank0(octet)
		if !n.childBits.Test(octet) {
			child := &ribNode[V]{
				parent: n,
				octet:  uint8(octet),
				depth:  uint8(d + 1),
				is4:    pk.Is4,
			}
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			n = child
			continue
		}
		n = n.children[rank]
	}
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	rank := n.pfxBits.Rank0(idx)
	if n.pfxBits.Test(idx) {
		n.values[rank] = val
		return false
	}
	n.pfxBits.Set(idx)
	n.pfxCount++
	n.values = insertAt(n.values, rank, val)
	if pk.Is4 {
		r.size4++
	} else {
		r.size6++
	}
	return true
}

// Delete removes pfx, reporting whether it was present. After clearing the
// ART index we prune empty nodes via parent links rather than a path stack -
// that's the one place the extra pointer actually pays for itself
func (r *Table[V]) Delete(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	n := r.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		if !n.childBits.Test(octet) {
			return false
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if !n.pfxBits.Test(idx) {
		return false
	}
	rank := n.pfxBits.Rank0(idx)
	n.pfxBits.Clear(idx)
	n.pfxCount--
	n.values = deleteAt(n.values, rank)
	if pk.Is4 {
		r.size4--
	} else {
		r.size6--
	}
	// prune empty nodes using the parent links rather than a path stack
	for n.parent != nil && n.pfxCount == 0 && n.childBits.IsEmpty() {
		p := n.parent
		o := uint(n.octet)
		rank := p.childBits.Rank0(o)
		p.childBits.Clear(o)
		p.children = deleteAt(p.children, rank)
		n = p
	}
	return true
}

// Lookup performs a longest-prefix match, returning the value only. Same
// register-resident v4 descent as the fast tables - the extra per-node
// fields cost memory but don't have to cost lookup time
func (r *Table[V]) Lookup(addr netip.Addr) (val V, ok bool) {
	if addr.Is4() || addr.Is4In6() {
		key := be32(addr.As4())
		n := &r.root4
		for shift := 24; ; shift -= 8 {
			octet := uint(key>>shift) & 0xff
			if n.pfxCount != 0 {
				if idx, hit := n.pfxBits.LpmTop(uint8(octet)); hit {
					val, ok = n.values[n.pfxBits.Rank0(idx)], true
				}
			}
			if shift == 0 || !n.childBits.Test(octet) {
				return val, ok
			}
			n = n.children[n.childBits.Rank0(octet)]
		}
	}
	k, valid := addrkey.FromAddr(addr)
	if !valid {
		return val, false
	}
	n := r.rootFor(k.Is4)
	last := int(k.Len) - 1
	for depth := 0; ; depth++ {
		if n.pfxCount != 0 {
			if idx, hit := n.pfxBits.LpmTop(k.Octets[depth]); hit {
				val, ok = n.values[n.pfxBits.Rank0(idx)], true
			}
		}
		if depth == last {
			return val, ok
		}
		octet := uint(k.Octets[depth])
		if !n.childBits.Test(octet) {
			return val, ok
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// -----------------------------------------------------------------------------
// Upward walking: covering prefixes
// -----------------------------------------------------------------------------

// Supernets calls fn for every stored prefix that covers addr, from the
// longest match to the shortest. One descent: we collect (node, idx) hits
// shortest-first within each stride then emit the array in reverse so later
// (longer) strides come out first. Stack-sized so nothing hits the heap
func (r *Table[V]) Supernets(addr netip.Addr, fn func(netip.Prefix, V) bool) {
	k, valid := addrkey.FromAddr(addr)
	if !valid {
		return
	}
	n := r.rootFor(k.Is4)
	last := int(k.Len) - 1

	// collect (node, idx) pairs on the way down. Max is 16 strides × 9
	// prefix lengths; in practice only a handful match
	type hit struct {
		n   *ribNode[V]
		idx uint
	}
	var hits [16 * 9]hit
	count := 0

	for depth := 0; ; depth++ {
		if n.pfxCount != 0 {
			// collect this node's matches shortest-first, because the whole
			// array is emitted in reverse below
			base := count
			for i := art.HostIdx(k.Octets[depth]); i > 0; i >>= 1 {
				if n.pfxBits.Test(i) {
					hits[count] = hit{n, i}
					count++
				}
			}
			// reverse the run just appended
			for l, r := base, count-1; l < r; l, r = l+1, r-1 {
				hits[l], hits[r] = hits[r], hits[l]
			}
		}
		if depth == last {
			break
		}
		octet := uint(k.Octets[depth])
		if !n.childBits.Test(octet) {
			break
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
	// emit longest-first
	for i := count - 1; i >= 0; i-- {
		h := hits[i]
		if !fn(h.n.prefixAt(h.idx), h.n.values[h.n.pfxBits.Rank0(h.idx)]) {
			return
		}
	}
}

// Parent returns the longest stored prefix strictly shorter than pfx that
// covers it - pfx's immediate parent in the prefix hierarchy. Same descent
// as Supernets but we keep only the best hit, and at the terminal stride
// we start one ART level up so we don't return pfx itself
func (r *Table[V]) Parent(pfx netip.Prefix) (netip.Prefix, V, bool) {
	var zero V
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return netip.Prefix{}, zero, false
	}
	n := r.rootFor(pk.Is4)
	lastDepth, remain := decompose(pk.Bits)

	var bestN *ribNode[V]
	var bestIdx uint
	for depth := 0; ; depth++ {
		if n.pfxCount != 0 {
			start := art.HostIdx(pk.Octets[depth])
			if depth == lastDepth {
				// strictly shorter than the query, so begin one level up
				start = art.PfxToIdx(pk.Octets[depth], remain) >> 1
			}
			for i := start; i > 0; i >>= 1 {
				if n.pfxBits.Test(i) {
					bestN, bestIdx = n, i
					break
				}
			}
		}
		if depth == lastDepth {
			break
		}
		octet := uint(pk.Octets[depth])
		if !n.childBits.Test(octet) {
			break
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
	if bestN == nil {
		return netip.Prefix{}, zero, false
	}
	return bestN.prefixAt(bestIdx), bestN.values[bestN.pfxBits.Rank0(bestIdx)], true
}

// -----------------------------------------------------------------------------
// Downward walking: covered prefixes
// -----------------------------------------------------------------------------

// Subnets calls fn for every stored prefix covered by pfx, including pfx
// itself if it's stored. Output-sensitive: a short prefix on a large table
// can enumerate most of the table, so don't put this on a request path
// without a bound. Descend to the terminal stride, emit the ART-heap
// subtree of the query index, then walk child subtrees whose octet falls
// inside pfx
func (r *Table[V]) Subnets(pfx netip.Prefix, fn func(netip.Prefix, V) bool) {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return
	}
	n := r.rootFor(pk.Is4)
	lastDepth, remain := decompose(pk.Bits)

	// descend to the node holding pfx. A prefix at a shallower depth covers
	// pfx rather than being covered by it
	for depth := 0; depth < lastDepth; depth++ {
		octet := uint(pk.Octets[depth])
		if !n.childBits.Test(octet) {
			return
		}
		n = n.children[n.childBits.Rank0(octet)]
	}

	qIdx := art.PfxToIdx(pk.Octets[lastDepth], remain)
	if !n.emitIdxSubtree(qIdx, fn) {
		return
	}
	first, lastOct := art.IdxRange(qIdx)
	var cbuf [256]uint8
	for _, oct := range n.childBits.All(cbuf[:0]) {
		if oct < first || oct > lastOct {
			continue
		}
		child := n.children[n.childBits.Rank0(uint(oct))]
		if !child.walkAll(fn) {
			return
		}
	}
}

// emitIdxSubtree emits stored prefixes at idx and at every descendant of
// idx within the same stride, shortest first. ART heap numbering: kids of
// idx are idx<<1 and idx<<1|1
func (n *ribNode[V]) emitIdxSubtree(idx uint, fn func(netip.Prefix, V) bool) bool {
	if idx >= art.MaxPrefixes {
		return true
	}
	if n.pfxCount != 0 && n.pfxBits.Test(idx) {
		if !fn(n.prefixAt(idx), n.values[n.pfxBits.Rank0(idx)]) {
			return false
		}
	}
	if !n.emitIdxSubtree(idx<<1, fn) {
		return false
	}
	return n.emitIdxSubtree(idx<<1|1, fn)
}

// walkAll emits every stored prefix in this node and all its descendants
func (n *ribNode[V]) walkAll(fn func(netip.Prefix, V) bool) bool {
	if n.pfxCount != 0 {
		var buf [16]uint
		for _, idx := range n.pfxBits.All(buf[:0]) {
			if !fn(n.prefixAt(idx), n.values[n.pfxBits.Rank0(idx)]) {
				return false
			}
		}
	}
	var cbuf [256]uint8
	for _, oct := range n.childBits.All(cbuf[:0]) {
		if !n.children[n.childBits.Rank0(uint(oct))].walkAll(fn) {
			return false
		}
	}
	return true
}

// All calls fn for every stored prefix. v4 then v6 via walkAll
func (r *Table[V]) All(fn func(netip.Prefix, V) bool) {
	if !r.root4.walkAll(fn) {
		return
	}
	r.root6.walkAll(fn)
}

// prefixAt reconstructs the prefix stored at index idx of this node by
// walking the parent chain. At most 16 steps for v6 and 4 for v4, against
// up to 128 for a bit-trie GetPrefix, because each step recovers a whole
// octet. That's the actual reason we stored parent/octet/depth
func (n *ribNode[V]) prefixAt(idx uint) netip.Prefix {
	octet, pfxLen := art.IdxToPfx(idx)
	var k addrkey.Key
	k.Is4 = n.is4
	if n.is4 {
		k.Len = 4
	} else {
		k.Len = 16
	}
	k.Octets[n.depth] = octet
	for cur := n; cur.parent != nil; cur = cur.parent {
		k.Octets[cur.depth-1] = cur.octet
	}
	pk := addrkey.PrefixKey{Key: k, Bits: n.depth*8 + pfxLen}
	return pk.Prefix()
}

// decompose splits a prefix length into stride depth and remaining bits
func decompose(bits uint8) (depth int, pfxLen uint8) {
	if bits == 0 {
		return 0, 0
	}
	depth = int(bits-1) >> 3
	return depth, bits - uint8(depth<<3)
}

// be32 packs four bytes as a big-endian uint32
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// insertAt splices v into s at i
func insertAt[T any](s []T, i int, v T) []T {
	var zero T
	s = append(s, zero)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

// deleteAt removes index i and zeros the leftover slot
func deleteAt[T any](s []T, i int) []T {
	var zero T
	copy(s[i:], s[i+1:])
	s[len(s)-1] = zero
	return s[:len(s)-1]
}
