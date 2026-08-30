// Package coverartset is the artset variant that answers pure membership
// with a precomputed 256-bit coverage summary per node. artset's eight-word
// lattice intersect becomes one bit test. We kept it as the coverBits
// experiment; arenaartset is the version that also ditched the 512-bit
// prefix bitset on the lookup path
package coverartset

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

// Set is the performance-optimised membership structure. Not safe for
// concurrent mutation; see versioned.Table for that. coverBits is the
// whole pitch: bit i set iff some prefix at this node covers octet i
type Set struct {
	root4 setNode
	root6 setNode
	size4 int
	size6 int

	// front is the direct-indexed IPv4 /16 acceleration table, two bits per
	// /16, packed into 64-bit words: 65536 entries * 2 bits = 16 KiB
	front [65536 * 2 / 64]uint64
	hasV4 bool // whether any IPv4 prefix is stored at all
}

// Front table codes, two bits per /16 slot
const (
	frontNone   = 0 // no stored prefix covers or intersects this /16
	frontAll    = 1 // a prefix at /16 or shorter covers this entire /16
	frontDeeper = 2 // must descend the trie to decide
)

// setNode is one stride of the membership trie. No values, so descent
// (childBits, children) and match (pfxBits) are all that remain. coverBits
// is a materialised summary of pfxBits. Field order groups the hot-path
// fields ahead of the cold ones so a descent touches fewer cache lines
type setNode struct {
	coverBits art.Bitset256
	pfxCount  uint16
	leafBits  art.Bitset256
	childBits art.Bitset256
	children  []*setNode
	pfxBits   art.Bitset512
	leaves    []setLeaf
}

// setLeaf is a path-compressed terminal prefix with no value
type setLeaf struct {
	key  addrkey.Key
	bits uint8
}

// covers reports whether the leaf's prefix covers the given key. Byte-wise
// compare of the full octets then a masked last byte. We later switched
// this to word-wise XOR in arenaartset because this loop is embarrassing
func (lf *setLeaf) covers(octets *[16]byte) bool {
	full := int(lf.bits) >> 3
	for i := 0; i < full; i++ {
		if lf.key.Octets[i] != octets[i] {
			return false
		}
	}
	if rem := lf.bits & 7; rem != 0 {
		m := byte(0xff) << (8 - rem)
		if lf.key.Octets[full]&m != octets[full]&m {
			return false
		}
	}
	return true
}

// New returns an empty Set. Zero value would work too; this is just tidy
func New() *Set { return &Set{} }

// Size returns the number of stored prefixes. Both families
func (s *Set) Size() int { return s.size4 + s.size6 }

// rootFor picks the family root. Tiny helper, called a lot on writes
func (s *Set) rootFor(is4 bool) *setNode {
	if is4 {
		return &s.root4
	}
	return &s.root6
}

// getFront reads the two-bit code for a /16 slot. Packed 32 slots per word
func (s *Set) getFront(slot uint32) uint64 {
	return (s.front[slot>>5] >> ((slot & 31) * 2)) & 3
}

// setFront writes the two-bit code for a /16 slot. Mask-then-OR so we can
// overwrite an existing code
func (s *Set) setFront(slot uint32, code uint64) {
	sh := (slot & 31) * 2
	s.front[slot>>5] = (s.front[slot>>5] &^ (3 << sh)) | (code << sh)
}

// Contains reports whether any stored prefix covers addr. v4 goes through
// contains4 (front table); v6 descends, returning on the first coverBits
// hit or a covering leaf
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() || addr.Is4In6() {
		return s.contains4(be32(addr.As4()))
	}
	k, ok := addrkey.FromAddr(addr)
	if !ok {
		return false
	}
	n := &s.root6
	last := int(k.Len) - 1
	for depth := 0; ; depth++ {
		if n.pfxCount != 0 && n.coverBits.Test(uint(k.Octets[depth])) {
			return true
		}
		octet := uint(k.Octets[depth])
		if n.leafBits.Test(octet) {
			return n.leaves[n.leafBits.Rank0(octet)].covers(&k.Octets)
		}
		if depth == last || !n.childBits.Test(octet) {
			return false
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// contains4 answers IPv4 membership, consulting the front table first
// frontNone/frontAll return immediately; frontDeeper walks the trie with
// coverBits instead of the eight-word lattice intersect
func (s *Set) contains4(key uint32) bool {
	if !s.hasV4 {
		return false
	}
	// one array access decides the overwhelming majority of queries
	switch s.getFront(key >> 16) {
	case frontNone:
		return false
	case frontAll:
		return true
	}
	// frontDeeper: the /16 is partially covered, so descend. Path-compressed
	// leaves may sit at any depth, so every level is checked
	var ob [16]byte
	ob[0], ob[1], ob[2], ob[3] = byte(key>>24), byte(key>>16), byte(key>>8), byte(key)
	n := &s.root4
	for d := 0; ; d++ {
		octet := uint(ob[d])
		if n.pfxCount != 0 && n.coverBits.Test(octet) {
			return true
		}
		if n.leafBits.Test(octet) {
			return n.leaves[n.leafBits.Rank0(octet)].covers(&ob)
		}
		if d == 3 || !n.childBits.Test(octet) {
			return false
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// Insert adds a prefix. Reports whether it was newly added. We descend
// creating path-compressed leaves until we collide, then explode the leaf
// into a child and keep going. coverBits is updated incrementally
func (s *Set) Insert(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	n := s.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		rank := n.childBits.Rank0(octet)
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			if lf.bits == pk.Bits && lf.key.Octets == pk.Octets {
				return false
			}
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			child := &setNode{}
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			n = child
			s.insertAtDepth(child, lf.key, lf.bits, d+1)
			continue
		}
		if !n.childBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, setLeaf{key: pk.Key, bits: pk.Bits})
			if pk.Is4 {
				s.size4++
				s.hasV4 = true
				s.updateFront(pk)
			} else {
				s.size6++
			}
			return true
		}
		n = n.children[rank]
	}
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if n.pfxBits.Test(idx) {
		return false
	}
	n.pfxBits.Set(idx)
	n.pfxCount++
	n.setCover(idx)
	if pk.Is4 {
		s.size4++
		s.hasV4 = true
		s.updateFront(pk)
	} else {
		s.size6++
	}
	return true
}

// insertAtDepth reinserts a displaced leaf starting at trie depth from
// Same shape as Insert minus size/front bookkeeping - the leaf was already
// counted
func (s *Set) insertAtDepth(n *setNode, key addrkey.Key, bits uint8, from int) {
	depth, remain := decompose(bits)
	for d := from; d < depth; d++ {
		octet := uint(key.Octets[d])
		rank := n.childBits.Rank0(octet)
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			if lf.bits == bits && lf.key.Octets == key.Octets {
				return
			}
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			child := &setNode{}
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			n = child
			s.insertAtDepth(child, lf.key, lf.bits, d+1)
			continue
		}
		if !n.childBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, setLeaf{key: key, bits: bits})
			return
		}
		n = n.children[rank]
	}
	idx := art.PfxToIdx(key.Octets[depth], remain)
	if !n.pfxBits.Test(idx) {
		n.pfxBits.Set(idx)
		n.pfxCount++
		n.setCover(idx)
	}
}

// setCover marks every octet covered by the prefix at index idx in coverBits
// IdxRange gives the contiguous octet span; we just set the bits
func (n *setNode) setCover(idx uint) {
	first, last := art.IdxRange(idx)
	for o := uint(first); o <= uint(last); o++ {
		n.coverBits.Set(o)
	}
}

// rebuildCover recomputes coverBits from pfxBits. Used after deletion, which
// is rare, so we don't bother with per-octet refcounts
func (n *setNode) rebuildCover() {
	n.coverBits = art.Bitset256{}
	var buf [16]uint
	for _, idx := range n.pfxBits.All(buf[:0]) {
		first, last := art.IdxRange(idx)
		for o := uint(first); o <= uint(last); o++ {
			n.coverBits.Set(o)
		}
	}
}

// updateFront refreshes the front-table codes affected by an IPv4 prefix
// /16 or shorter can only promote toward frontAll; longer than /16 can
// only promote toward frontDeeper if the slot isn't already All
func (s *Set) updateFront(pk addrkey.PrefixKey) {
	base := uint32(pk.Octets[0])<<8 | uint32(pk.Octets[1])
	if pk.Bits == 16 {
		// exactly the front stride: this /16 is wholly covered
		if s.getFront(base) != frontAll {
			s.setFront(base, frontAll)
		}
		return
	}
	if pk.Bits > 16 {
		// longer than the front stride: this /16 needs a trie descent unless
		// it's already wholly covered by a prefix of /16 or shorter
		if s.getFront(base) != frontAll {
			s.setFront(base, frontDeeper)
		}
		return
	}
	// shorter than the front stride: every /16 it spans is wholly covered
	// A /8 writes 256 sequential slots
	span := uint32(1) << (16 - pk.Bits)
	for i := uint32(0); i < span; i++ {
		s.setFront(base+i, frontAll)
	}
}

// Delete removes a prefix and reports whether it was present. We walk with
// a path stack so we can prune empty nodes on the way back, then rebuild
// coverBits and (for v4) the whole front table. Delete is assumed rare
func (s *Set) Delete(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	root := s.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	var stack [16]*setNode
	n := root
	for d := 0; d < depth; d++ {
		stack[d] = n
		octet := uint(pk.Octets[d])
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := &n.leaves[lrank]
			if lf.bits != pk.Bits || lf.key.Octets != pk.Octets {
				return false
			}
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			if pk.Is4 {
				s.size4--
				s.rebuildFront()
			} else {
				s.size6--
			}
			return true
		}
		if !n.childBits.Test(octet) {
			return false
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
	stack[depth] = n
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if !n.pfxBits.Test(idx) {
		return false
	}
	n.pfxBits.Clear(idx)
	n.pfxCount--
	n.rebuildCover()
	if pk.Is4 {
		s.size4--
	} else {
		s.size6--
	}
	for d := depth; d > 0; d-- {
		cur := stack[d]
		if cur.pfxCount != 0 || !cur.childBits.IsEmpty() || !cur.leafBits.IsEmpty() {
			break
		}
		parent := stack[d-1]
		octet := uint(pk.Octets[d-1])
		r := parent.childBits.Rank0(octet)
		parent.childBits.Clear(octet)
		parent.children = deleteAt(parent.children, r)
	}
	if pk.Is4 {
		// deletion can only reduce coverage, and recomputing an individual
		// slot from the trie is more code than it's worth for a rare
		// operation, so rebuild the front table from the surviving prefixes
		s.rebuildFront()
	}
	return true
}

// rebuildFront recomputes the whole front table. Delete is assumed rare;
// this keeps Insert and Contains simple
func (s *Set) rebuildFront() {
	s.front = [65536 * 2 / 64]uint64{}
	s.hasV4 = s.size4 > 0
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	s.root4.walkSet(&key, 0, func(p netip.Prefix) bool {
		pk, _ := addrkey.FromPrefix(p)
		s.updateFront(pk)
		return true
	})
}

// All calls fn for every stored prefix; iteration stops early if fn returns
// false. v4 then v6
func (s *Set) All(fn func(netip.Prefix) bool) {
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	if !s.root4.walkSet(&key, 0, fn) {
		return
	}
	key = addrkey.Key{Len: 16}
	s.root6.walkSet(&key, 0, fn)
}

// walkSet enumerates this node's prefixes, then leaves, then children
// Octets are stashed/restored on the shared key so we don't allocate
func (n *setNode) walkSet(key *addrkey.Key, depth int, fn func(netip.Prefix) bool) bool {
	if n.pfxCount != 0 {
		var buf [16]uint
		for _, idx := range n.pfxBits.All(buf[:0]) {
			octet, pfxLen := art.IdxToPfx(idx)
			saved := key.Octets[depth]
			key.Octets[depth] = octet
			pk := addrkey.PrefixKey{Key: *key, Bits: uint8(depth*8) + pfxLen}
			ok := fn(pk.Prefix())
			key.Octets[depth] = saved
			if !ok {
				return false
			}
		}
	}
	if !n.leafBits.IsEmpty() {
		var lbuf [16]uint8
		for _, octet := range n.leafBits.All(lbuf[:0]) {
			lf := &n.leaves[n.leafBits.Rank0(uint(octet))]
			pk := addrkey.PrefixKey{Key: lf.key, Bits: lf.bits}
			if !fn(pk.Prefix()) {
				return false
			}
		}
	}
	if n.childBits.IsEmpty() {
		return true
	}
	var cbuf [16]uint8
	for _, octet := range n.childBits.All(cbuf[:0]) {
		saved := key.Octets[depth]
		key.Octets[depth] = octet
		child := n.children[n.childBits.Rank0(uint(octet))]
		ok := child.walkSet(key, depth+1, fn)
		key.Octets[depth] = saved
		if !ok {
			return false
		}
	}
	return true
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

// insertAt splices v into s at i, growing by one. Generic because we use
// it for both children and leaves
func insertAt[T any](s []T, i int, v T) []T {
	var zero T
	s = append(s, zero)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

// deleteAt removes index i and zeros the leftover slot so we don't leak a
// pointer into the truncated tail
func deleteAt[T any](s []T, i int) []T {
	var zero T
	copy(s[i:], s[i+1:])
	s[len(s)-1] = zero
	return s[:len(s)-1]
}
