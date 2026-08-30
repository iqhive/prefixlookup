// Package groupartset is the membership set we built after artset, same job,
// less work per level of descent
//
// it differs from artset in four ways, each of which removes work from the
// per-level inner loop rather than from the structure as a whole
//
//  1. interleaved bit groups. artset keeps three independent 256-bit sets
//     (coverBits, leafBits, childBits) plus their popcount ranks in separate
//     struct fields, so testing one octet at one level reads three addresses
//     spread across the node and, at typical node sizes, two cache lines. here
//     the three sets are sliced by 64-octet group and stored interleaved, so
//     the words for a given octet - together with the precomputed child and
//     leaf ranks for that group - live in a single naturally aligned 32-byte
//     bitGroup. one level of descent reads one group and nothing else
//
//  2. precomputed ranks. locating a child in the popcount-compressed child
//     slice needs the number of set bits below the octet. artset recomputes
//     that with up to three extra popcounts and their branches on every level
//     each group here carries the running count of the groups below it, so the
//     index is one addition plus a single masked popcount
//
//  3. no pfxCount guard. artset tests pfxCount != 0 before consulting the
//     coverage summary. the summary is already zero when a node holds no
//     prefixes, so the guard is a redundant load and branch on every level and
//     we just drop it
//
//  4. word-wise leaf comparison. a path-compressed leaf stored its full
//     16-byte key and was compared a byte at a time in a loop whose trip count
//     the branch predictor cannot know. leaves here hold the address as two
//     big-endian 64-bit words, so the comparison is a fixed pair of
//     mask-xor-test operations with no loop and no data-dependent branch
//
// the IPv4 front table is unchanged from artset: a direct-indexed /16
// classifier at two bits per slot, 16 KiB in total, which answers the
// overwhelming majority of queries from L1 with no pointer chasing. one extra
// property we exploit: reaching the trie at all means the slot read "descend",
// which can only happen when no prefix of /16 or shorter covers the address
// coverage tests at depths 0 and 1 are therefore known to fail, so those two
// levels skip them
//
// not safe for concurrent mutation, see versioned.Table for that
package groupartset

import (
	"math/bits"
	"net/netip"
)

// Set is a mutable membership set over IPv4 and IPv6 prefixes
// same shape as artset (two roots, front table, hasV4) but nodes are grouped
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
	frontNone    = 0 // no stored prefix covers or intersects this /16
	frontAll     = 1 // a prefix at /16 or shorter covers this entire /16
	frontDeeper  = 2 // must descend the trie to decide
	frontAllWord = uint64(0x5555555555555555)
)

// bitGroup holds one 64-octet slice of a node's three bitsets, plus the number
// of children and leaves belonging to the groups below it. every field a level
// of descent needs is here, and the type is exactly 32 bytes so a group never
// straddles a cache line
type bitGroup struct {
	cover     uint64 // octet o is covered by some prefix stored at this node
	leafMask  uint64 // octet o holds a path-compressed terminal prefix
	childMask uint64 // octet o holds a child node
	leafRank  uint16 // leaves in groups below this one
	childRank uint16 // children in groups below this one
	_         uint32 // pad to 32 bytes
}

// setNode is one stride of the membership trie. groups is the hot descent
// state, pfxIdx is cold and exists only to rebuild coverage after a delete and
// to enumerate
type setNode struct {
	groups   [4]bitGroup
	children []*setNode
	leaves   []setLeaf
	pfxIdx   []uint16 // sorted ART prefix indices stored at this node
}

// setLeaf is a path-compressed terminal prefix, held as the two big-endian
// words of its address plus its length
type setLeaf struct {
	hi, lo uint64
	bits   uint8
}

// masks returns the two address words masked to a prefix of the given length
// <=64 means the low word is unused, >64 means the high word is all ones
func masks(prefixBits uint8) (uint64, uint64) {
	if prefixBits <= 64 {
		return ^uint64(0) << (64 - prefixBits), 0
	}
	return ^uint64(0), ^uint64(0) << (128 - prefixBits)
}

// covers reports whether the leaf's prefix covers the address (hi, lo)
// mask-xor-test on both words, no loop
func (lf *setLeaf) covers(hi, lo uint64) bool {
	maskHi, maskLo := masks(lf.bits)
	return (hi^lf.hi)&maskHi == 0 && (lo^lf.lo)&maskLo == 0
}

// New returns an empty Set
// embedded roots, zero front, nothing to allocate
func New() *Set { return &Set{} }

// Size returns how many prefixes we've stored
// size4+size6
func (s *Set) Size() int { return s.size4 + s.size6 }

// rootFor picks the v4 or v6 root
func (s *Set) rootFor(is4 bool) *setNode {
	if is4 {
		return &s.root4
	}
	return &s.root6
}

// getFront pulls the 2-bit code for a /16 slot out of the packed word array
// 32 slots per uint64
func (s *Set) getFront(slot uint32) uint64 {
	return (s.front[slot>>5] >> ((slot & 31) * 2)) & 3
}

// setFront writes a 2-bit code into a /16 slot
// mask then or
func (s *Set) setFront(slot uint32, code uint64) {
	shift := (slot & 31) * 2
	s.front[slot>>5] = s.front[slot>>5]&^(3<<shift) | code<<shift
}

// hasChild reports whether octet has a child pointer
// one bit test in the right group
func (n *setNode) hasChild(octet uint) bool {
	return n.groups[octet>>6].childMask&(uint64(1)<<(octet&63)) != 0
}

// hasLeaf reports whether octet holds a path-compressed leaf
func (n *setNode) hasLeaf(octet uint) bool {
	return n.groups[octet>>6].leafMask&(uint64(1)<<(octet&63)) != 0
}

// childIndex is the popcount-compressed index of octet in children
// group.childRank plus ones below the bit in this group's mask
func (n *setNode) childIndex(octet uint) int {
	g := &n.groups[octet>>6]
	return int(g.childRank) + bits.OnesCount64(g.childMask&(uint64(1)<<(octet&63)-1))
}

// leafIndex is the same idea as childIndex, for the leaves slice
func (n *setNode) leafIndex(octet uint) int {
	g := &n.groups[octet>>6]
	return int(g.leafRank) + bits.OnesCount64(g.leafMask&(uint64(1)<<(octet&63)-1))
}

// addChild inserts a child at octet and bumps childRank on later groups
// we have to keep the running ranks consistent or childIndex goes wrong
func (n *setNode) addChild(octet uint, child *setNode) {
	index := n.childIndex(octet)
	word := octet >> 6
	n.groups[word].childMask |= uint64(1) << (octet & 63)
	for w := word + 1; w < 4; w++ {
		n.groups[w].childRank++
	}
	n.children = insertAt(n.children, index, child)
}

// removeChild drops the child at octet and decrements later ranks
func (n *setNode) removeChild(octet uint) {
	index := n.childIndex(octet)
	word := octet >> 6
	n.groups[word].childMask &^= uint64(1) << (octet & 63)
	for w := word + 1; w < 4; w++ {
		n.groups[w].childRank--
	}
	n.children = deleteAt(n.children, index)
}

// addLeaf inserts a leaf at octet and bumps leafRank on later groups
func (n *setNode) addLeaf(octet uint, leaf setLeaf) {
	index := n.leafIndex(octet)
	word := octet >> 6
	n.groups[word].leafMask |= uint64(1) << (octet & 63)
	for w := word + 1; w < 4; w++ {
		n.groups[w].leafRank++
	}
	n.leaves = insertAt(n.leaves, index, leaf)
}

// removeLeaf drops the leaf at octet and decrements later ranks
func (n *setNode) removeLeaf(octet uint) {
	index := n.leafIndex(octet)
	word := octet >> 6
	n.groups[word].leafMask &^= uint64(1) << (octet & 63)
	for w := word + 1; w < 4; w++ {
		n.groups[w].leafRank--
	}
	n.leaves = deleteAt(n.leaves, index)
}

// isEmpty reports whether n has no prefixes, no kids, no leaves
// used by Delete when pruning upward
func (n *setNode) isEmpty() bool {
	return len(n.pfxIdx) == 0 && len(n.children) == 0 && len(n.leaves) == 0
}

// Contains reports whether any stored prefix covers addr
// v4/4in6 through contains4, v6 walks groups testing cover then leaf then child
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() || addr.Is4In6() {
		return s.contains4(be32(addr.As4()))
	}
	if !addr.IsValid() {
		return false
	}
	hi, lo := words16(addr.As16())
	n := &s.root6
	key := hi
	for depth := 0; ; depth++ {
		if depth == 8 {
			key = lo
		}
		octet := uint(byte(key >> (56 - (depth&7)*8)))
		g := &n.groups[octet>>6]
		bit := uint64(1) << (octet & 63)
		if g.cover&bit != 0 {
			return true
		}
		if g.leafMask&bit != 0 {
			return n.leaves[int(g.leafRank)+bits.OnesCount64(g.leafMask&(bit-1))].covers(hi, lo)
		}
		if depth == 15 || g.childMask&bit == 0 {
			return false
		}
		n = n.children[int(g.childRank)+bits.OnesCount64(g.childMask&(bit-1))]
	}
}

// contains4 answers IPv4 membership, consulting the front table first
// if the slot says descend, no prefix of /16 or shorter covers this address,
// so we skip coverage tests at depths 0 and 1
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
	// slot read "descend", so no prefix of /16 or shorter covers this
	// address and the coverage tests at depths 0 and 1 cannot succeed
	hi := uint64(key) << 32
	n := &s.root4
	for depth := 0; depth < 2; depth++ {
		octet := uint(byte(key >> (24 - depth*8)))
		g := &n.groups[octet>>6]
		bit := uint64(1) << (octet & 63)
		if g.leafMask&bit != 0 {
			return n.leaves[int(g.leafRank)+bits.OnesCount64(g.leafMask&(bit-1))].covers(hi, 0)
		}
		if g.childMask&bit == 0 {
			return false
		}
		n = n.children[int(g.childRank)+bits.OnesCount64(g.childMask&(bit-1))]
	}
	for depth := 2; ; depth++ {
		octet := uint(byte(key >> (24 - depth*8)))
		g := &n.groups[octet>>6]
		bit := uint64(1) << (octet & 63)
		if g.cover&bit != 0 {
			return true
		}
		if g.leafMask&bit != 0 {
			return n.leaves[int(g.leafRank)+bits.OnesCount64(g.leafMask&(bit-1))].covers(hi, 0)
		}
		if depth == 3 || g.childMask&bit == 0 {
			return false
		}
		n = n.children[int(g.childRank)+bits.OnesCount64(g.childMask&(bit-1))]
	}
}

// Insert adds a prefix, reports whether it was newly added
// we normalise into words, insertKey into the right trie, then bump size and
// (for v4) patch the front table
func (s *Set) Insert(prefix netip.Prefix) bool {
	hi, lo, prefixBits, is4, ok := normalize(prefix)
	if !ok {
		return false
	}
	if !s.insertKey(s.rootFor(is4), hi, lo, prefixBits, 0) {
		return false
	}
	if is4 {
		s.size4++
		s.hasV4 = true
		s.updateFront(hi, prefixBits)
	} else {
		s.size6++
	}
	return true
}

// insertKey places a prefix into the trie rooted at n, starting at trie depth from
// reports whether it was newly added. leaf collisions get pushed down, empty
// slots become leaves, the terminal stride stores an ART index
func (s *Set) insertKey(n *setNode, hi, lo uint64, prefixBits uint8, from int) bool {
	depth, remain := decompose(prefixBits)
	for d := from; d < depth; d++ {
		octet := octetAt(hi, lo, d)
		if n.hasLeaf(octet) {
			existing := n.leaves[n.leafIndex(octet)]
			if existing.bits == prefixBits && existing.hi == hi && existing.lo == lo {
				return false
			}
			n.removeLeaf(octet)
			child := &setNode{}
			n.addChild(octet, child)
			s.insertKey(child, existing.hi, existing.lo, existing.bits, d+1)
			n = child
			continue
		}
		if !n.hasChild(octet) {
			n.addLeaf(octet, setLeaf{hi: hi, lo: lo, bits: prefixBits})
			return true
		}
		n = n.children[n.childIndex(octet)]
	}
	idx := pfxToIdx(octetAt(hi, lo, depth), remain)
	if !n.addPrefix(idx) {
		return false
	}
	n.setCover(idx)
	return true
}

// addPrefix records an ART prefix index, keeping pfxIdx sorted
// linear scan is fine, nodes hold a handful of prefixes
func (n *setNode) addPrefix(idx uint16) bool {
	at := len(n.pfxIdx)
	for i, have := range n.pfxIdx {
		if have == idx {
			return false
		}
		if have > idx {
			at = i
			break
		}
	}
	n.pfxIdx = insertAt(n.pfxIdx, at, idx)
	return true
}

// removePrefix drops an ART prefix index, reports whether it was present
// same linear scan, stop early once we've gone past idx
func (n *setNode) removePrefix(idx uint16) bool {
	for i, have := range n.pfxIdx {
		if have == idx {
			n.pfxIdx = deleteAt(n.pfxIdx, i)
			return true
		}
		if have > idx {
			break
		}
	}
	return false
}

// setCover marks every octet covered by the prefix at index idx
// idxRange gives the inclusive span, then we or 1s into each group's cover word
func (n *setNode) setCover(idx uint16) {
	first, last := idxRange(idx)
	firstWord, lastWord := first>>6, last>>6
	for w := firstWord; w <= lastWord; w++ {
		low := uint(0)
		if w == firstWord {
			low = first & 63
		}
		high := uint(63)
		if w == lastWord {
			high = last & 63
		}
		n.groups[w].cover |= ^uint64(0) << low & (^uint64(0) >> (63 - high))
	}
}

// rebuildCover recomputes the coverage summary from the stored prefix indices
// deletion is rare, so this avoids maintaining per-octet reference counts
func (n *setNode) rebuildCover() {
	for w := range n.groups {
		n.groups[w].cover = 0
	}
	for _, idx := range n.pfxIdx {
		n.setCover(idx)
	}
}

// updateFront refreshes the front-table codes affected by an IPv4 prefix
// /16 -> frontAll, longer -> frontDeeper unless already covered, shorter ->
// stamp frontAll across the span, word-at-a-time where aligned
func (s *Set) updateFront(hi uint64, prefixBits uint8) {
	base := uint32(hi >> 48)
	if prefixBits == 16 {
		s.setFront(base, frontAll)
		return
	}
	if prefixBits > 16 {
		if s.getFront(base) != frontAll {
			s.setFront(base, frontDeeper)
		}
		return
	}
	end := base + uint32(1)<<(16-prefixBits)
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
// walk recording the path, yank leaf or ART index, prune empty nodes upward,
// v4 rebuilds the whole front table
func (s *Set) Delete(prefix netip.Prefix) bool {
	hi, lo, prefixBits, is4, ok := normalize(prefix)
	if !ok {
		return false
	}
	depth, remain := decompose(prefixBits)
	var stack [17]*setNode
	n := s.rootFor(is4)
	removed := false
	for d := 0; d < depth; d++ {
		stack[d] = n
		octet := octetAt(hi, lo, d)
		if n.hasLeaf(octet) {
			existing := &n.leaves[n.leafIndex(octet)]
			if existing.bits != prefixBits || existing.hi != hi || existing.lo != lo {
				return false
			}
			n.removeLeaf(octet)
			removed = true
			depth = d
			break
		}
		if !n.hasChild(octet) {
			return false
		}
		n = n.children[n.childIndex(octet)]
	}
	if !removed {
		stack[depth] = n
		if !n.removePrefix(pfxToIdx(octetAt(hi, lo, depth), remain)) {
			return false
		}
		n.rebuildCover()
	}
	for d := depth; d > 0; d-- {
		if !stack[d].isEmpty() {
			break
		}
		stack[d-1].removeChild(octetAt(hi, lo, d-1))
	}
	if is4 {
		s.size4--
		s.rebuildFront()
	} else {
		s.size6--
	}
	return true
}

// rebuildFront recomputes the whole front table
// Delete is assumed rare, this keeps the far more frequent Insert and Contains
// paths simple
func (s *Set) rebuildFront() {
	s.front = [65536 * 2 / 64]uint64{}
	s.hasV4 = s.size4 > 0
	s.root4.walk(0, 0, 0, true, func(_ netip.Prefix, hi uint64, prefixBits uint8) bool {
		s.updateFront(hi, prefixBits)
		return true
	})
}

// All calls fn for every stored prefix, stops early if fn returns false
// we wrap walk so callers don't have to care about the hi/bits extras
func (s *Set) All(fn func(netip.Prefix) bool) {
	visit := func(prefix netip.Prefix, _ uint64, _ uint8) bool { return fn(prefix) }
	if !s.root4.walk(0, 0, 0, true, visit) {
		return
	}
	s.root6.walk(0, 0, 0, false, visit)
}

// walk enumerates every prefix under n. hi and lo carry the octets already
// fixed by the path from the root. pfxIdx, then leaves, then children
func (n *setNode) walk(hi, lo uint64, depth int, is4 bool, fn func(netip.Prefix, uint64, uint8) bool) bool {
	for _, idx := range n.pfxIdx {
		octet, pfxLen := idxToPfx(idx)
		keyHi, keyLo := withOctet(hi, lo, depth, byte(octet))
		prefixBits := uint8(depth*8) + pfxLen
		if !fn(rebuild(keyHi, keyLo, prefixBits, is4), keyHi, prefixBits) {
			return false
		}
	}
	for word := range n.groups {
		value := n.groups[word].leafMask
		for value != 0 {
			octet := uint(word*64 + bits.TrailingZeros64(value))
			leaf := &n.leaves[n.leafIndex(octet)]
			if !fn(rebuild(leaf.hi, leaf.lo, leaf.bits, is4), leaf.hi, leaf.bits) {
				return false
			}
			value &= value - 1
		}
	}
	for word := range n.groups {
		value := n.groups[word].childMask
		for value != 0 {
			octet := uint(word*64 + bits.TrailingZeros64(value))
			keyHi, keyLo := withOctet(hi, lo, depth, byte(octet))
			if !n.children[n.childIndex(octet)].walk(keyHi, keyLo, depth+1, is4, fn) {
				return false
			}
			value &= value - 1
		}
	}
	return true
}

// normalize converts a prefix into masked address words plus its length
// rejects invalids, zones, and 4in6 prefixes shorter than /96 (those aren't
// real v4). 4in6 gets unmapped and we subtract 96 from the length
func normalize(prefix netip.Prefix) (hi, lo uint64, prefixBits uint8, is4, ok bool) {
	if !prefix.IsValid() {
		return 0, 0, 0, false, false
	}
	addr := prefix.Addr()
	prefixBits = uint8(prefix.Bits())
	if addr.Is4In6() {
		if prefix.Bits() < 96 {
			return 0, 0, 0, false, false
		}
		addr = addr.Unmap()
		prefixBits -= 96
	}
	if addr.Zone() != "" {
		return 0, 0, 0, false, false
	}
	if addr.Is4() {
		hi = uint64(be32(addr.As4())) << 32
		is4 = true
		if prefixBits > 32 {
			return 0, 0, 0, false, false
		}
	} else {
		hi, lo = words16(addr.As16())
	}
	maskHi, maskLo := masks(prefixBits)
	return hi & maskHi, lo & maskLo, prefixBits, is4, true
}

// rebuild turns address words and a length back into a netip.Prefix
// v4 pulls the top 32 bits of hi, v6 unpacks both words into 16 bytes
func rebuild(hi, lo uint64, prefixBits uint8, is4 bool) netip.Prefix {
	if is4 {
		key := uint32(hi >> 32)
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)}), int(prefixBits))
	}
	var octets [16]byte
	for i := 0; i < 8; i++ {
		octets[i] = byte(hi >> (56 - i*8))
		octets[8+i] = byte(lo >> (56 - i*8))
	}
	return netip.PrefixFrom(netip.AddrFrom16(octets), int(prefixBits))
}

// octetAt returns the octet at trie depth d
// d<8 from hi, else from lo
func octetAt(hi, lo uint64, d int) uint {
	if d < 8 {
		return uint(byte(hi >> (56 - d*8)))
	}
	return uint(byte(lo >> (56 - (d-8)*8)))
}

// withOctet returns the address words with the octet at depth d replaced
// used while enumerating to stitch the path back into a key
func withOctet(hi, lo uint64, d int, octet byte) (uint64, uint64) {
	shift := uint(56 - (d&7)*8)
	if d < 8 {
		return hi&^(uint64(0xff)<<shift) | uint64(octet)<<shift, lo
	}
	return hi, lo&^(uint64(0xff)<<shift) | uint64(octet)<<shift
}

// words16 packs 16 bytes into two big-endian uint64s
func words16(octets [16]byte) (uint64, uint64) {
	hi := uint64(octets[0])<<56 | uint64(octets[1])<<48 | uint64(octets[2])<<40 | uint64(octets[3])<<32 |
		uint64(octets[4])<<24 | uint64(octets[5])<<16 | uint64(octets[6])<<8 | uint64(octets[7])
	lo := uint64(octets[8])<<56 | uint64(octets[9])<<48 | uint64(octets[10])<<40 | uint64(octets[11])<<32 |
		uint64(octets[12])<<24 | uint64(octets[13])<<16 | uint64(octets[14])<<8 | uint64(octets[15])
	return hi, lo
}

// be32 packs four octets into a big-endian uint32
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// decompose splits a prefix length into its trie depth and residual bits
// same canonical split as artlpm: length b at depth (b-1)/8
func decompose(prefixBits uint8) (depth int, pfxLen uint8) {
	if prefixBits == 0 {
		return 0, 0
	}
	depth = int(prefixBits-1) >> 3
	return depth, prefixBits - uint8(depth<<3)
}

// pfxToIdx maps an octet and a residual length to its ART index
// it's the heap numbering: 1<<pfxLen | the top pfxLen bits of the octet
func pfxToIdx(octet uint, pfxLen uint8) uint16 {
	return uint16(octet>>(8-pfxLen)) | 1<<pfxLen
}

// idxToPfx is the inverse of pfxToIdx
// length is bits.Len-1, then we shift the payload back to the top of the octet
func idxToPfx(idx uint16) (octet uint, pfxLen uint8) {
	pfxLen = uint8(bits.Len16(idx)) - 1
	return uint(idx&(1<<pfxLen-1)) << (8 - pfxLen), pfxLen
}

// idxRange returns the inclusive octet range an ART index covers
// that's [octet, octet | the don't-care bits]
func idxRange(idx uint16) (first, last uint) {
	octet, pfxLen := idxToPfx(idx)
	return octet, octet | uint(0xff>>pfxLen)
}

// insertAt inserts value at index, growing slice by one
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
