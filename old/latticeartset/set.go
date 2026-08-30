// Package latticeartset is the first-gen ART membership set: no values,
// first-cover-wins, /16 front table, path-compressed leaves. Lookup still
// pays the eight-word lattice intersect per stride. We kept it as the
// equivalence reference the later sets (coverartset, arenaartset) get
// tested against - it's the slow-but-obvious one
package latticeartset

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

// Set answers pure membership - does any stored prefix cover this address
// Dropping the value buys three things: no rank-into-values on a hit, return
// at the first covering prefix, and a smaller node. The /16 front table is
// 16 KiB and L1-resident; a /8 insert writes 256 slots, which we accepted
// because short prefixes almost never churn
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
// (childBits, children) and match (pfxBits) are all that remain. Leaves
// matter most for IPv6, where an uncompressed trie spends up to thirteen
// single-child levels reaching a /128
type setNode struct {
	childBits art.Bitset256
	children  []*setNode
	pfxBits   art.Bitset512
	pfxCount  uint16

	leafBits art.Bitset256
	leaves   []setLeaf
}

// setLeaf is a path-compressed terminal prefix with no value
type setLeaf struct {
	key  addrkey.Key
	bits uint8
}

// covers reports whether the leaf's prefix covers the given key. Byte-wise
// compare; we later replaced this with word-wise XOR in arenaartset
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

// New returns an empty Set
func New() *Set { return &Set{} }

// Size returns the number of stored prefixes
func (s *Set) Size() int { return s.size4 + s.size6 }

// rootFor picks the family root
func (s *Set) rootFor(is4 bool) *setNode {
	if is4 {
		return &s.root4
	}
	return &s.root6
}

// getFront reads the two-bit code for a /16 slot
func (s *Set) getFront(slot uint32) uint64 {
	return (s.front[slot>>5] >> ((slot & 31) * 2)) & 3
}

// setFront writes the two-bit code for a /16 slot. Mask-then-OR
func (s *Set) setFront(slot uint32, code uint64) {
	sh := (slot & 31) * 2
	s.front[slot>>5] = (s.front[slot>>5] &^ (3 << sh)) | (code << sh)
}

// Contains reports whether any stored prefix covers addr. v4 uses the
// front table; v6 descends and returns on the first lattice intersect or
// covering leaf. This is the eight-word path we later replaced
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
		if n.pfxCount != 0 && n.pfxBits.IntersectsOctet(k.Octets[depth]) {
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
// frontDeeper starts at depth 0 even though the first two strides can't
// have a covering prefix (that'd be frontAll) - we still have to check
// leaves at every depth
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
	// frontDeeper: the /16 is partially covered, so descend
	var ob [16]byte
	ob[0], ob[1], ob[2], ob[3] = byte(key>>24), byte(key>>16), byte(key>>8), byte(key)
	n := &s.root4
	for d := 0; ; d++ {
		octet := uint(ob[d])
		if n.pfxCount != 0 && n.pfxBits.IntersectsOctet(uint8(octet)) {
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

// Insert adds a prefix. Reports whether it was newly added. Descend,
// exploding path-compressed leaves into children when we collide, then
// set the ART index at the terminal stride
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
// No size/front bookkeeping - the leaf was already counted
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
	}
}

// updateFront refreshes the front-table codes affected by an IPv4 prefix
// Same promote-only rules as coverartset
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

// Delete removes a prefix and reports whether it was present. Path stack
// for pruning empty nodes; v4 rebuilds the whole front table because
// shrinking an individual slot isn't worth the code
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
		// deletion can only reduce coverage, so rebuild the front table from
		// the surviving prefixes rather than trying to shrink one slot
		s.rebuildFront()
	}
	return true
}

// rebuildFront recomputes the whole front table. Delete is assumed rare
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

// All calls fn for every stored prefix; stops early if fn returns false
func (s *Set) All(fn func(netip.Prefix) bool) {
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	if !s.root4.walkSet(&key, 0, fn) {
		return
	}
	key = addrkey.Key{Len: 16}
	s.root6.walkSet(&key, 0, fn)
}

// walkSet enumerates prefixes, then leaves, then children. Shared key,
// stash/restore the octet
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

// insertAt splices v into s at i
func insertAt[T any](s []T, i int, v T) []T {
	var zero T
	s = append(s, zero)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

// deleteAt removes index i and zeros the leftover so we don't leak a
// pointer into the truncated tail
func deleteAt[T any](s []T, i int) []T {
	var zero T
	copy(s[i:], s[i+1:])
	s[len(s)-1] = zero
	return s[:len(s)-1]
}
