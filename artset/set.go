// Package artset is the membership-only ART set: packed v4 classifier, per-node
// coverage summaries, path-compressed terminals
//
// no values, just "does any prefix cover this addr" - if you need a payload use
// artlpm.Table instead, not safe for concurrent mutation
package artset

import (
	"math/bits"
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

// Set is a mutable membership set over v4 and v6 prefixes
// front is 2 bits per /16 (16 KiB), hasV4 lets Contains bail before we even
// look at the classifier
type Set struct {
	root4 setNode
	root6 setNode
	size4 int
	size6 int
	front [65536 * 2 / 64]uint64
	hasV4 bool
}

// front-table codes, two bits per /16 slot
const (
	frontNone    = 0
	frontAll     = 1
	frontDeeper  = 2
	frontAllWord = uint64(0x5555555555555555) // 16 slots of frontAll packed in one word
)

// setNode is one stride: coverage + pfx bitmap + compressed kids/leaves
// coverBits is "this octet is covered by some prefix stored here" so Contains
// can return true without walking the ART heap
type setNode struct {
	coverBits art.Bitset256
	pfxCount  uint16
	leafBits  art.Bitset256
	childBits art.Bitset256
	children  []*setNode
	pfxBits   art.Bitset512
	leaves    []setLeaf
}

// setLeaf is a path-compressed terminal prefix, full key plus length
type setLeaf struct {
	key  addrkey.Key
	bits uint8
}

// covers reports whether this leaf's prefix covers octets from depth onward
// we skip the octets already matched by the descent and only compare the tail
func (lf *setLeaf) covers(octets *[16]byte, depth int) bool {
	full := int(lf.bits) >> 3
	for i := depth; i < full; i++ {
		if lf.key.Octets[i] != octets[i] {
			return false
		}
	}
	if rem := lf.bits & 7; rem != 0 {
		// partial last octet, mask off the host bits
		m := byte(0xff) << (8 - rem)
		if lf.key.Octets[full]&m != octets[full]&m {
			return false
		}
	}
	return true
}

// New returns an empty Set
// roots are embedded, front is a zero array, nothing to allocate
func New() *Set { return &Set{} }

// Size returns how many prefixes we've stored
// size4+size6, we keep families split so this is just an add
func (s *Set) Size() int { return s.size4 + s.size6 }

// rootFor picks the v4 or v6 root
// one branch, two embedded nodes
func (s *Set) rootFor(is4 bool) *setNode {
	if is4 {
		return &s.root4
	}
	return &s.root6
}

// getFront pulls the 2-bit code for a /16 slot out of the packed word array
// 32 slots per uint64, so slot>>5 is the word and (slot&31)*2 is the shift
func (s *Set) getFront(slot uint32) uint64 {
	return (s.front[slot>>5] >> ((slot & 31) * 2)) & 3
}

// setFront writes a 2-bit code into a /16 slot
// mask out the old bits then or in the new ones
func (s *Set) setFront(slot uint32, code uint64) {
	sh := (slot & 31) * 2
	s.front[slot>>5] = (s.front[slot>>5] &^ (3 << sh)) | (code << sh)
}

// Contains reports whether any stored prefix covers addr
// v4/4in6 goes through contains4 (front table), v6 walks the trie testing
// coverBits then leaves then kids
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() || addr.Is4In6() {
		return s.contains4(be32(addr.As4()))
	}
	k, ok := addrkey.FromAddr(addr)
	if !ok {
		return false
	}
	// v6 lookup: start at the root6 node, check prefixes and descend as needed
	n := &s.root6
	last := int(k.Len) - 1 // last octet index we'll check, keys are variable length
	for depth := 0; ; depth++ {
		// grab the current octet from the address key (k.Octets is a [16]byte)
		octet := uint(k.Octets[depth])
		// if this node actually has prefixes, see if any of them cover this slot
		if n.pfxCount != 0 && n.coverBits.Test(octet) {
			// some prefix stored at this level covers this octet, that's enough, stop
			return true
		}
		// if there's a leaf on this octet, compare its key tail to the addr
		if n.leafBits.Test(octet) {
			// need to binary search down the parallel leaves array
			return n.leaves[n.leafBits.Rank0(octet)].covers(&k.Octets, depth)
		}
		// if we've run out of address or there's no child here, the search failed
		if depth == last || !n.childBits.Test(octet) {
			return false
		}
		// descend: walk to child pointer for this octet (popcount-compressed)
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// contains4 answers IPv4 membership, consulting the front table first
// frontNone/frontAll resolve without touching the trie, otherwise we descend
// extracting octets from the uint32 by shift
func (s *Set) contains4(key uint32) bool {
	if !s.hasV4 {
		return false
	}
	switch s.getFront(key >> 16) {
	case frontNone:
		return false
	case frontAll:
		return true
	}
	// anchor at the v4 root node of the trie; this is where IPv4 lookups start
	n := &s.root4
	// preallocate a buffer for a full IPv6 address for later leaf comparison (using only the first 4 slots for IPv4)
	var octets [16]byte
	for depth := 0; ; depth++ {
		// for each level in the trie, pluck out the relevant byte of the IPv4 addr
		octet := uint(byte(key >> (24 - depth*8))) // top byte first, then the next, etc
		// see if this node has any prefixes that directly cover this address chunk
		// coverBits gives a flat check for "is any covering prefix at this stride for this octet"
		if n.pfxCount != 0 && n.coverBits.Test(octet) {
			// bang, direct hit, covered at this depth, can bail now
			return true
		}
		// terminal: if the bit is set, there's a path-compressed leaf node at this octet
		if n.leafBits.Test(octet) {
			// only bother unpacking the address as 4 separate bytes if we're going to do the leaf comparison
			octets[0], octets[1], octets[2], octets[3] = byte(key>>24), byte(key>>16), byte(key>>8), byte(key)
			// grab the correct leaf (the array is compressed to match which bits are set)
			// and see if this leaf actually covers us (full prefix/addr compare)
			return n.leaves[n.leafBits.Rank0(octet)].covers(&octets, depth)
		}
		// done if we're at the bottom of IPv4 (4 bytes, so depth==3), or there's no child to walk to
		if depth == 3 || !n.childBits.Test(octet) {
			return false
		}
		// not found at this stride, but there's more tree: jump down to the correct child node for this octet
		// children array is popcount-compressed: only has pointers for bits which are actually set
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// Insert adds a prefix, reports whether it was newly added
// walk to decompose depth, splitting leaves if we collide, else store as a
// leaf or set the ART index and cover bits - v4 also patches the front table
func (s *Set) Insert(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	n := s.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits) // chop the prefix len into trie depth + bits to use at this stride
	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])      // get the relevant byte at this depth
		rank := n.childBits.Rank0(octet) // where in the children array do we land if needed
		if n.leafBits.Test(octet) {      // leaf check: see if a compressed leaf lives in this node at this slot
			lrank := n.leafBits.Rank0(octet)                      // get the leaf's index in the compressed array
			lf := n.leaves[lrank]                                 // fetch that leaf
			if lf.bits == pk.Bits && lf.key.Octets == pk.Octets { // got a duplicate: same prefix, don't double up
				return false
			}
			// so we hit an existing leaf but it's a clash: old leaf needs to be pushed down
			n.leafBits.Clear(octet)                        // remove the leaf-bit so future lookups don't see it
			n.leaves = deleteAt(n.leaves, lrank)           // actually remove from slice
			child := &setNode{}                            // prep a new node for the old leaf to live under
			n.childBits.Set(octet)                         // flip on child-bit for this branch
			n.children = insertAt(n.children, rank, child) // slide in new child to compressed kid list
			n = child                                      // descend
			s.insertAtDepth(child, lf.key, lf.bits, d+1)   // drop the old leaf deeper from next stride
			continue                                       // keep walking trie with *our* prefix (the new one)
		}
		if !n.childBits.Test(octet) {
			// slot's free at this stride, shortcut: we path-compress the rest as a single leaf, no chain needed
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)                                                     // claim this spot for a leaf
			n.leaves = insertAt(n.leaves, lrank, setLeaf{key: pk.Key, bits: pk.Bits}) // stash the details
			if pk.Is4 {                                                               // if it's IPv4
				s.size4++         // bump our /32 count
				s.hasV4 = true    // flip the fast-path shortcut for v4
				s.updateFront(pk) // tweak the front-table for /16-and-above skips
			} else { // v6 gets counted but nothing else needed here
				s.size6++
			}
			return true // all done
		}
		n = n.children[rank] // not here, but there IS a child to walk into at this stride
	}
	idx := art.PfxToIdx(pk.Octets[depth], remain) // index for the prefix bits at this node
	if n.pfxBits.Test(idx) {                      // another duplicate: same stride, already present
		return false
	}
	n.pfxBits.Set(idx) // claim that
	n.pfxCount++       // bump counters used for fast match ("is there a prefix covering this chunk here")
	n.setCover(idx)    // update coverage bits, so we can shortcut lookups for anything under this bit
	if pk.Is4 {        // same as above, update v4 stats and summary
		s.size4++
		s.hasV4 = true
		s.updateFront(pk)
	} else {
		s.size6++
	}
	return true // inserted
}

// insertAtDepth reinserts a displaced leaf starting at trie depth from
// same walk as Insert but we don't bump size counters - the entry already counted
func (s *Set) insertAtDepth(n *setNode, key addrkey.Key, prefixBits uint8, from int) {
	depth, remain := decompose(prefixBits)
	for d := from; d < depth; d++ {
		octet := uint(key.Octets[d])
		rank := n.childBits.Rank0(octet)

		// if there's already a leaf at this position, check duplicate vs push-down
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			// duplicated (key and bits match), nothing to do
			if lf.bits == prefixBits && lf.key.Octets == key.Octets {
				return
			}
			// existing leaf isn't a duplicate, yank it and push it down
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			child := &setNode{}
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			n = child
			// reinsert the displaced leaf deeper
			s.insertAtDepth(child, lf.key, lf.bits, d+1)
			continue
		}
		// no child here, path-compress the rest as a leaf
		if !n.childBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, setLeaf{key: key, bits: prefixBits})
			return
		}
		// otherwise descend into the child at this stride
		n = n.children[rank]
	}
	// landed at the terminal stride, set the ART index if it's new
	idx := art.PfxToIdx(key.Octets[depth], remain)
	if !n.pfxBits.Test(idx) {
		n.pfxBits.Set(idx) // set the prefix bit
		n.pfxCount++       // increase prefix count for fast matching
		n.setCover(idx)    // update cover bits for this entry
	}
}

// setCover marks every octet covered by the prefix at ART index idx
// IdxRange gives the inclusive octet span, then we or 1s into coverBits,
// handling the single-word and multi-word cases separately
func (n *setNode) setCover(idx uint) {
	first, last := art.IdxRange(idx)
	start, end := uint(first), uint(last)
	firstWord, lastWord := start>>6, end>>6
	if firstWord == lastWord {
		n.coverBits[firstWord] |= ^uint64(0) << (start & 63) & (^uint64(0) >> (63 - (end & 63)))
		return
	}
	n.coverBits[firstWord] |= ^uint64(0) << (start & 63)
	for word := firstWord + 1; word < lastWord; word++ {
		n.coverBits[word] = ^uint64(0)
	}
	n.coverBits[lastWord] |= ^uint64(0) >> (63 - (end & 63))
}

// rebuildCover recomputes coverBits from pfxBits after a delete
// we don't keep per-octet refcounts, delete is rare enough that a full rebuild
// of one node's 256-bit summary is cheaper
func (n *setNode) rebuildCover() {
	n.coverBits = art.Bitset256{}
	for word, value := range n.pfxBits {
		for value != 0 {
			bit := uint(bits.TrailingZeros64(value))
			n.setCover(uint(word*64) + bit)
			value &= value - 1
		}
	}
}

// updateFront refreshes the front-table codes affected by an IPv4 prefix
// /16 sets one slot to frontAll, longer prefixes mark frontDeeper unless the
// slot is already fully covered, shorter prefixes stamp frontAll across the
// whole span they cover (word-at-a-time where we can)
func (s *Set) updateFront(pk addrkey.PrefixKey) {
	base := uint32(pk.Octets[0])<<8 | uint32(pk.Octets[1])
	if pk.Bits == 16 {
		s.setFront(base, frontAll)
		return
	}
	if pk.Bits > 16 {
		if s.getFront(base) != frontAll {
			s.setFront(base, frontDeeper)
		}
		return
	}
	span := uint32(1) << (16 - pk.Bits)
	end := base + span
	for base < end && base&31 != 0 {
		s.setFront(base, frontAll)
		base++
	}
	for base+32 <= end {
		s.front[base>>5] = frontAllWord
		base += 32
	}
	for base < end {
		s.setFront(base, frontAll)
		base++
	}
}

// Delete removes a prefix and reports whether it was present
// we record the path, yank the leaf or ART index, prune empty nodes, and if
// it was v4 we rebuild the whole front table (delete is assumed rare)
func (s *Set) Delete(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	root := s.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	var stack [16]*setNode // path for prune, we don't keep parent pointers
	n := root
	for d := 0; d < depth; d++ {
		stack[d] = n
		octet := uint(pk.Octets[d])
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := &n.leaves[lrank]
			if lf.bits != pk.Bits || lf.key.Octets != pk.Octets {
				// leaf at this octet but it's a different prefix
				return false
			}
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			if pk.Is4 {
				s.size4--
			} else {
				s.size6--
			}
			s.prune(stack[:d+1], pk.Octets[:], d)
			if pk.Is4 {
				s.rebuildFront()
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
	s.prune(stack[:depth+1], pk.Octets[:], depth)
	if pk.Is4 {
		s.rebuildFront()
	}
	return true
}

// prune removes empty nodes walking back up the recorded path
// a node is empty when it has no prefixes, no kids, no leaves - root stays
func (s *Set) prune(stack []*setNode, octets []byte, depth int) {
	for d := depth; d > 0; d-- {
		cur := stack[d]
		if cur.pfxCount != 0 || !cur.childBits.IsEmpty() || !cur.leafBits.IsEmpty() {
			return
		}
		parent := stack[d-1]
		octet := uint(octets[d-1])
		rank := parent.childBits.Rank0(octet)
		parent.childBits.Clear(octet)
		parent.children = deleteAt(parent.children, rank)
	}
}

// rebuildFront recomputes the whole front table from the v4 trie
// nuke it, then walk every stored prefix through updateFront. Insert patches
// incrementally, Delete just does this because it's rare
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

// All calls fn for every stored prefix, stops early if fn returns false
// v4 then v6, same scratch-key walk as artlpm
func (s *Set) All(fn func(netip.Prefix) bool) {
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	if !s.root4.walkSet(&key, 0, fn) {
		return
	}
	key = addrkey.Key{Len: 16}
	s.root6.walkSet(&key, 0, fn)
}

// walkSet enumerates pfxBits, then leaves, then children under n
// we iterate set bits with trailing-zeros rather than All() so we don't
// allocate a buffer
func (n *setNode) walkSet(key *addrkey.Key, depth int, fn func(netip.Prefix) bool) bool {
	// walk set bits in pfxBits (prefixes that live in this stride)
	for word, value := range n.pfxBits {
		for value != 0 {
			// next set bit
			bit := uint(bits.TrailingZeros64(value))
			idx := uint(word*64) + bit // absolute prefix bitmap index

			// ART index back to octet + residual length
			octet, pfxLen := art.IdxToPfx(idx)

			// temp overwrite current stride in key to construct prefix key
			saved := key.Octets[depth]
			key.Octets[depth] = octet

			// construct prefix and invoke callback
			ok := fn(addrkey.PrefixKey{Key: *key, Bits: uint8(depth*8) + pfxLen}.Prefix())

			// restore previous value in scratch key
			key.Octets[depth] = saved

			// fn said stop
			if !ok {
				return false
			}

			// clear the bit we just handled (trailing-zeros walk)
			value &= value - 1
		}
	}

	// path-compressed leaves at this node
	for word, value := range n.leafBits {
		for value != 0 {
			// next set leaf bit
			octet := uint(word*64 + bits.TrailingZeros64(value))
			// Rank0 finds the slot in the compressed leaves slice
			lf := &n.leaves[n.leafBits.Rank0(octet)]

			// exact leaf prefix
			if !fn(addrkey.PrefixKey{Key: lf.key, Bits: lf.bits}.Prefix()) {
				return false
			}
			value &= value - 1
		}
	}

	// children, recurse
	for word, value := range n.childBits {
		for value != 0 {
			// next set child bit
			octet := uint(word*64 + bits.TrailingZeros64(value))
			saved := key.Octets[depth]
			key.Octets[depth] = byte(octet)

			// walk the child
			ok := n.children[n.childBits.Rank0(octet)].walkSet(key, depth+1, fn)

			// restore key after the child returns
			key.Octets[depth] = saved

			// early abort if fn returned false in the subtree
			if !ok {
				return false
			}
			value &= value - 1
		}
	}
	// node and subtree done
	return true
}

// decompose splits a prefix length into trie depth and residual bits
// same canonical split as artlpm: length b at depth (b-1)/8, default route is 0,0
func decompose(prefixBits uint8) (depth int, pfxLen uint8) {
	if prefixBits == 0 {
		return 0, 0
	}
	depth = int(prefixBits-1) >> 3
	return depth, prefixBits - uint8(depth<<3)
}

// be32 packs four octets into a big-endian uint32
// octet 0 is the high byte
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// insertAt inserts value at index, growing slice by one
// append a zero then memmove the tail
func insertAt[T any](slice []T, index int, value T) []T {
	var zero T
	slice = append(slice, zero)
	copy(slice[index+1:], slice[index:])
	slice[index] = value
	return slice
}

// deleteAt removes index, shrinking slice by one
// we zero the vacated tail so a pointer payload doesn't keep an object alive
func deleteAt[T any](slice []T, index int) []T {
	var zero T
	copy(slice[index:], slice[index+1:])
	slice[len(slice)-1] = zero
	return slice[:len(slice)-1]
}
