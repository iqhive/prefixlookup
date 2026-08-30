// Package arenaartset is the third-gen mutable boolean prefix set: coverBits
// on the hot path, sorted []uint16 lattice instead of a 512-bit bitset,
// pooled arena nodes, deferred v4 classifier rebuild. We kept it as the
// last membership experiment before we specialised further. Still not
// safe for concurrent mutation
package arenaartset

import (
	"cmp"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

const (
	// Arena indices of the two family roots. Index 0 is a sentinel that is
	// never a valid node, so a zero child index is recognisable as such
	root4 = 1
	root6 = 2
)

// Front-table codes, two bits per /16 slot
const (
	frontNone   = 0 // no stored prefix covers or intersects this /16
	frontAll    = 1 // a prefix at /16 or shorter covers this entire /16
	frontDeeper = 2 // must descend the trie to decide
)

// Set answers one question: does any stored prefix cover this address. The
// zero value is not usable; construct with New
type Set struct {
	arena        []node
	free         []int32
	size4, size6 int

	// front is the direct-indexed IPv4 /16 classifier, two bits per /16,
	// packed into 64-bit words: 65536 entries * 2 bits = 16 KiB
	front [65536 * 2 / 64]uint64
	hasV4 bool

	// frontDirty defers the O(table) classifier rebuild after an IPv4
	// delete. Any read or insert refreshes it first, so a burst of deletes
	// pays for one rebuild, not one per delete
	frontDirty bool
}

// node is one stride of the membership trie. Fields are ordered for the
// descent: the three bitsets the hot path tests occupy the first 96 bytes,
// the slice headers follow, and the lazily allocated prefix lattice is last
//
// cov is the coverage bitmap: cov[o] is set when some prefix ending within
// this stride covers octet value o. A hit is this single bit test
//
// pfx retains the node's prefixes as sorted lattice indices. Required to
// enumerate and delete; nil on nodes that store none. Never read on lookup
type node struct {
	cov       art.Bitset256
	childBits art.Bitset256
	leafBits  art.Bitset256
	children  []int32 // arena indices, rank-indexed by childBits
	leaves    []leaf
	pfx       []uint16 // sorted art.PfxToIdx lattice indices
}

// leaf is a path-compressed terminal prefix
type leaf struct {
	key  addrkey.Key
	bits uint8
}

// covers reports whether the leaf's prefix covers the given key octets
// Word-wise: at most two 64-bit XORs regardless of length, where the
// earlier sets walked the compared bytes one at a time
func (lf *leaf) covers(oct *[16]byte) bool {
	b := uint(lf.bits)
	hi := binary.BigEndian.Uint64(lf.key.Octets[0:8]) ^ binary.BigEndian.Uint64(oct[0:8])
	if b < 64 {
		if b == 0 {
			return true
		}
		return hi&(^uint64(0)<<(64-b)) == 0
	}
	if hi != 0 {
		return false
	}
	if b == 64 {
		return true
	}
	lo := binary.BigEndian.Uint64(lf.key.Octets[8:16]) ^ binary.BigEndian.Uint64(oct[8:16])
	if b == 128 {
		return lo == 0
	}
	return lo&(^uint64(0)<<(128-b)) == 0
}

// setCover marks the octet values covered by a prefix whose significant
// octet within the stride is octet and whose length within the stride is
// remain bits. remain 0 is the default route, which covers every octet
// Covered values are one contiguous bit range, so the write is word-wise
func setCover(cov *art.Bitset256, octet uint8, remain uint8) {
	if remain == 0 {
		*cov = art.Bitset256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
		return
	}
	base := uint(octet) >> (8 - remain) << (8 - remain)
	setCoverRange(cov, base, base+1<<(8-remain))
}

// setCoverRange sets the contiguous bit range [base, end). At most five
// word writes regardless of range length
func setCoverRange(cov *art.Bitset256, base, end uint) {
	first, last := base>>6, (end-1)>>6
	if first == last {
		cov[first] |= (^uint64(0) << (base & 63)) & (^uint64(0) >> (63 - ((end - 1) & 63)))
		return
	}
	cov[first] |= ^uint64(0) << (base & 63)
	for w := first + 1; w < last; w++ {
		cov[w] = ^uint64(0)
	}
	cov[last] |= ^uint64(0) >> (63 - ((end - 1) & 63))
}

// recomputeCover rebuilds the coverage bitmap from the node's prefix lattice
// Runs on delete, where the cleared entry may have been the only cover for
// some octet values. No refcounts; we just replay
func recomputeCover(n *node) {
	var cov art.Bitset256
	for _, idx := range n.pfx {
		octet, remain := art.IdxToPfx(uint(idx))
		setCover(&cov, octet, remain)
	}
	n.cov = cov
}

// New returns an empty Set. Arena is pre-sized so both family roots exist
// (indexes 1 and 2); 0 stays a sentinel
func New() *Set {
	return &Set{arena: make([]node, root6+1)}
}

// Size returns the number of stored prefixes
func (s *Set) Size() int { return s.size4 + s.size6 }

// rootFor picks the family root arena index
func (s *Set) rootFor(is4 bool) int32 {
	if is4 {
		return root4
	}
	return root6
}

// alloc returns the index of a fresh node, recycling released indices first
// Callers must re-derive node pointers after calling it: growing the arena
// moves it. Growth is doubling so a bulk load copies O(final) bytes in total
func (s *Set) alloc() int32 {
	if n := len(s.free); n > 0 {
		idx := s.free[n-1]
		s.free = s.free[:n-1]
		s.arena[idx] = node{}
		return idx
	}
	if len(s.arena) == cap(s.arena) {
		next := cap(s.arena) * 2
		if next == 0 {
			next = 4
		}
		grown := make([]node, len(s.arena), next)
		copy(grown, s.arena)
		s.arena = grown
	}
	s.arena = append(s.arena, node{})
	return int32(len(s.arena) - 1)
}

// release returns an empty node to the pool. We don't shrink the arena
func (s *Set) release(idx int32) {
	s.free = append(s.free, idx)
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

// Contains reports whether any stored prefix covers addr. v4 goes through
// contains4; v6 descends testing cov then leaves. That's the whole hot path
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() || addr.Is4In6() {
		return s.contains4(be32(addr.As4()))
	}
	k, ok := addrkey.FromAddr(addr)
	if !ok {
		return false
	}
	var ob *[16]byte = &k.Octets
	idx := int32(root6)
	last := int(k.Len) - 1
	for depth := 0; ; depth++ {
		n := &s.arena[idx]
		octet := uint(ob[depth])
		if n.cov.Test(octet) {
			return true
		}
		if n.leafBits.Test(octet) {
			return n.leaves[n.leafBits.Rank0(octet)].covers(ob)
		}
		if depth == last || !n.childBits.Test(octet) {
			return false
		}
		idx = n.children[n.childBits.Rank0(octet)]
	}
}

// contains4 answers IPv4 membership, consulting the classifier first
// Refreshes a dirty front table, then frontNone/All return immediately
// frontDeeper skips cov on the first two strides (a /16-or-shorter would
// have been All) but still checks leaves at every depth
func (s *Set) contains4(key uint32) bool {
	if s.frontDirty {
		s.rebuildFront()
	}
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
	var ob [16]byte
	ob[0], ob[1], ob[2], ob[3] = byte(key>>24), byte(key>>16), byte(key>>8), byte(key)
	idx := int32(root4)
	for d := 0; d < 2; d++ {
		n := &s.arena[idx]
		octet := uint(ob[d])
		if n.leafBits.Test(octet) {
			return n.leaves[n.leafBits.Rank0(octet)].covers(&ob)
		}
		if !n.childBits.Test(octet) {
			return false
		}
		idx = n.children[n.childBits.Rank0(octet)]
	}
	for d := 2; ; d++ {
		n := &s.arena[idx]
		octet := uint(ob[d])
		if n.cov.Test(octet) {
			return true
		}
		if n.leafBits.Test(octet) {
			return n.leaves[n.leafBits.Rank0(octet)].covers(&ob)
		}
		if d == 3 || !n.childBits.Test(octet) {
			return false
		}
		idx = n.children[n.childBits.Rank0(octet)]
	}
}

// Insert adds a prefix. Reports whether it was newly added. Thin wrapper
// onto insertKey after we normalise
func (s *Set) Insert(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	return s.insertKey(pk)
}

// Load adds every valid prefix in one bulk operation. Sorted input makes
// every child/leaf slice append land at its tail and pools sibling nodes
// adjacently in the arena, so we sort first if needed. Invalid prefixes
// are skipped rather than failing the whole load. Then we maybe shrink
// the arena slack
func (s *Set) Load(prefixes []netip.Prefix) {
	keys := make([]addrkey.PrefixKey, 0, len(prefixes))
	sorted := true
	for _, p := range prefixes {
		pk, ok := addrkey.FromPrefix(p)
		if !ok {
			continue
		}
		if sorted && len(keys) != 0 && lessPrefix(keys[len(keys)-1], pk) > 0 {
			sorted = false
		}
		keys = append(keys, pk)
	}
	if !sorted {
		slices.SortFunc(keys, lessPrefix)
	}
	for _, pk := range keys {
		s.insertKey(pk)
	}
	// children reference the arena by index, so a final exact-size copy is
	// safe and drops the growth slack a bulk load leaves behind
	if cap(s.arena) > len(s.arena)+(len(s.arena)>>3) {
		exact := make([]node, len(s.arena))
		copy(exact, s.arena)
		s.arena = exact
	}
}

// lessPrefix orders PrefixKeys by octets then length, for Load's sort
func lessPrefix(a, b addrkey.PrefixKey) int {
	if c := slices.Compare(a.Octets[:], b.Octets[:]); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits, b.Bits)
}

// recordAdd performs size and classifier bookkeeping for a newly added
// prefix. v4 refreshes a dirty front first so updateFront sees a consistent
// table, then promotes the affected slots
func (s *Set) recordAdd(pk addrkey.PrefixKey) {
	if pk.Is4 {
		s.size4++
		s.hasV4 = true
		if s.frontDirty {
			s.rebuildFront()
		}
		s.updateFront(pk)
	} else {
		s.size6++
	}
}

// insertKey adds a normalised prefix and reports whether it was newly added
// Same leaf-explode descent as the pointer sets, but we re-fetch the node
// after alloc because the arena may have moved
func (s *Set) insertKey(pk addrkey.PrefixKey) bool {
	depth, remain := decompose(pk.Bits)
	idx := s.rootFor(pk.Is4)
	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		n := &s.arena[idx]
		rank := n.childBits.Rank0(octet)
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			if lf.bits == pk.Bits && lf.key.Octets == pk.Octets {
				return false
			}
			child := s.alloc()
			n = &s.arena[idx] // alloc may have grown the arena
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			s.insertAtDepth(child, lf.key, lf.bits, d+1)
			idx = child
			continue
		}
		if !n.childBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, leaf{key: pk.Key, bits: pk.Bits})
			s.recordAdd(pk)
			return true
		}
		idx = n.children[rank]
	}
	n := &s.arena[idx]
	pidx := uint16(art.PfxToIdx(pk.Octets[depth], remain))
	if !insertPfx(n, pidx) {
		return false
	}
	setCover(&n.cov, pk.Octets[depth], remain)
	s.recordAdd(pk)
	return true
}

// insertPfx adds lattice index v to n's sorted prefix list, reporting
// whether it was absent. The common bulk case appends past the current
// maximum, which skips both the search and the shifting copy
func insertPfx(n *node, v uint16) bool {
	if len(n.pfx) == 0 || v > n.pfx[len(n.pfx)-1] {
		n.pfx = append(n.pfx, v)
		return true
	}
	lo, hi := 0, len(n.pfx)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if n.pfx[m] < v {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if n.pfx[lo] == v {
		return false
	}
	n.pfx = insertAt(n.pfx, lo, v)
	return true
}

// insertAtDepth reinserts a displaced leaf starting at trie depth from. It
// performs no size or classifier bookkeeping: the leaf was already counted
func (s *Set) insertAtDepth(idx int32, key addrkey.Key, bits uint8, from int) {
	depth, remain := decompose(bits)
	for d := from; d < depth; d++ {
		octet := uint(key.Octets[d])
		n := &s.arena[idx]
		rank := n.childBits.Rank0(octet)
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			if lf.bits == bits && lf.key.Octets == key.Octets {
				return
			}
			child := s.alloc()
			n = &s.arena[idx] // alloc may have grown the arena
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			s.insertAtDepth(child, lf.key, lf.bits, d+1)
			idx = child
			continue
		}
		if !n.childBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, leaf{key: key, bits: bits})
			return
		}
		idx = n.children[rank]
	}
	n := &s.arena[idx]
	pidx := uint16(art.PfxToIdx(key.Octets[depth], remain))
	if insertPfx(n, pidx) {
		setCover(&n.cov, key.Octets[depth], remain)
	}
}

// updateFront refreshes the classifier codes affected by an IPv4 prefix
// Promote-only: /16-or-shorter toward All, longer toward Deeper
func (s *Set) updateFront(pk addrkey.PrefixKey) {
	base := uint32(pk.Octets[0])<<8 | uint32(pk.Octets[1])
	if pk.Bits == 16 {
		// exactly the classifier stride: this /16 is wholly covered
		if s.getFront(base) != frontAll {
			s.setFront(base, frontAll)
		}
		return
	}
	if pk.Bits > 16 {
		// longer than the classifier stride: this /16 needs a trie descent
		// unless it's already wholly covered by a prefix of /16 or shorter
		if s.getFront(base) != frontAll {
			s.setFront(base, frontDeeper)
		}
		return
	}
	// shorter than the classifier stride: every /16 it spans is wholly
	// covered. A /8 writes 256 sequential slots
	span := uint32(1) << (16 - pk.Bits)
	for i := uint32(0); i < span; i++ {
		s.setFront(base+i, frontAll)
	}
}

// Delete removes a prefix and reports whether it was present. Binary-search
// the sorted lattice, recompute cov, prune empty nodes back into the pool
// v4 just sets frontDirty rather than rebuilding immediately
func (s *Set) Delete(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	depth, remain := decompose(pk.Bits)
	var stack [16]int32
	idx := s.rootFor(pk.Is4)
	for d := 0; d < depth; d++ {
		stack[d] = idx
		n := &s.arena[idx]
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
				s.frontDirty = true
			} else {
				s.size6--
			}
			return true
		}
		if !n.childBits.Test(octet) {
			return false
		}
		idx = n.children[n.childBits.Rank0(octet)]
	}
	stack[depth] = idx
	n := &s.arena[idx]
	pidx := uint16(art.PfxToIdx(pk.Octets[depth], remain))
	lo, hi := 0, len(n.pfx)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if n.pfx[m] < pidx {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo == len(n.pfx) || n.pfx[lo] != pidx {
		return false
	}
	n.pfx = deleteAt(n.pfx, lo)
	if len(n.pfx) == 0 {
		n.pfx = nil
		n.cov = art.Bitset256{}
	} else {
		recomputeCover(n)
	}
	if pk.Is4 {
		s.size4--
		s.frontDirty = true
	} else {
		s.size6--
	}
	for d := depth; d > 0; d-- {
		cur := &s.arena[stack[d]]
		if cur.pfx != nil || !cur.childBits.IsEmpty() || !cur.leafBits.IsEmpty() {
			break
		}
		parent := &s.arena[stack[d-1]]
		octet := uint(pk.Octets[d-1])
		r := parent.childBits.Rank0(octet)
		parent.childBits.Clear(octet)
		parent.children = deleteAt(parent.children, r)
		s.release(stack[d])
	}
	return true
}

// rebuildFront recomputes the whole classifier from the trie. Called lazily
// from the next v4 read or insert after a dirty delete
func (s *Set) rebuildFront() {
	s.front = [65536 * 2 / 64]uint64{}
	s.hasV4 = s.size4 > 0
	s.frontDirty = false
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	s.walk(&s.arena[root4], &key, 0, func(p netip.Prefix) bool {
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
	if !s.walk(&s.arena[root4], &key, 0, fn) {
		return
	}
	key = addrkey.Key{Len: 16}
	s.walk(&s.arena[root6], &key, 0, fn)
}

// walk enumerates the subtree of n, which sits at trie depth and inherits
// the octets accumulated in key. Prefix bits first, then leaves, then
// children, matching the iteration order of the lattice form. Leaf/child
// iteration is word-wise TZCNT rather than All() - leftover micro-opt
func (s *Set) walk(n *node, key *addrkey.Key, depth int, fn func(netip.Prefix) bool) bool {
	for _, entry := range n.pfx {
		octet, pfxLen := art.IdxToPfx(uint(entry))
		saved := key.Octets[depth]
		key.Octets[depth] = octet
		pk := addrkey.PrefixKey{Key: *key, Bits: uint8(depth*8) + pfxLen}
		ok := fn(pk.Prefix())
		key.Octets[depth] = saved
		if !ok {
			return false
		}
	}
	if !n.leafBits.IsEmpty() {
		for w := uint(0); w < 4; w++ {
			word := n.leafBits[w]
			for word != 0 {
				octet := uint8(w<<6 + uint(bits.TrailingZeros64(word)))
				word &= word - 1
				lf := &n.leaves[n.leafBits.Rank0(uint(octet))]
				pk := addrkey.PrefixKey{Key: lf.key, Bits: lf.bits}
				if !fn(pk.Prefix()) {
					return false
				}
			}
		}
	}
	if n.childBits.IsEmpty() {
		return true
	}
	for w := uint(0); w < 4; w++ {
		word := n.childBits[w]
		for word != 0 {
			octet := uint8(w<<6 + uint(bits.TrailingZeros64(word)))
			word &= word - 1
			saved := key.Octets[depth]
			key.Octets[depth] = octet
			child := n.children[n.childBits.Rank0(uint(octet))]
			ok := s.walk(&s.arena[child], key, depth+1, fn)
			key.Octets[depth] = saved
			if !ok {
				return false
			}
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

// deleteAt removes index i and zeros the leftover slot so we don't leak a
// pointer into the truncated tail
func deleteAt[T any](s []T, i int) []T {
	var zero T
	copy(s[i:], s[i+1:])
	s[len(s)-1] = zero
	return s[:len(s)-1]
}
