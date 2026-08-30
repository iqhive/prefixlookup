// Package soaart is the compiled stride-8 ART we keep as struct-of-arrays
//
// steplpm leaf-pushes into a step function so beaten prefixes disappear - we
// can't walk supernets off that. here every prefix stays at its own level, so
// one trie answers LPM, exact, supernets and subnets without an auxiliary index
//
// LPM: one descent, test the node's own prefixes at each level, keep the last
// match - one test per level, no BART-style unwind of a stack
// exact: same descent, stop at the prefix's own level, test one bit. no hashing,
// which is why we beat BART and fiborderwalk on subnet walks (they pay a map
// lookup on a 32-byte netip.Prefix to find the start)
// supernets: ancestors are exactly the prefixes the descent already passed, so
// we don't store parent pointers. fiborderwalk chases a parent chain through a
// 48-byte-per-route catalogue, mean 123 positions apart, every hop a miss
// subnets: enumerate the subtree, rebuild each prefix from the path we walked
//
// nodes live in parallel flat slices, uint32 indices not pointer - GC never
// scans the hot structure, links are four bytes, the whole index is a handful
// of allocations instead of one per node (Go rounds every alloc to a size class
// and a node-per-object layout pays that tens of thousands of times)
//
// Index is immutable, unsynchronised concurrent reads are fine
package soaart

import (
	"errors"
	"math/bits"
	"net/netip"
)

// ErrBadPrefix reports an invalid or zoned prefix
var ErrBadPrefix = errors.New("soaart: bad prefix")

// ErrTooManyRoutes reports a table larger than the index space
var ErrTooManyRoutes = errors.New("soaart: too many routes")

const (
	// a child slot holds a tagged reference: two tag bits and a 30-bit payload
	tagShift    = 30
	tagMask     = uint32(3) << tagShift
	payloadMask = ^tagMask

	refNode   = uint32(0) << tagShift // payload is a node index
	refLeaf   = uint32(1) << tagShift // payload is a leaf index
	refFringe = uint32(2) << tagShift // payload is a route id

	maxPayload = payloadMask
)

// lpmTable[octet] has a bit set at every ART prefix index that covers octet,
// for prefix lengths 0 through 7 within the stride. a node's matching prefixes
// are therefore the intersection of its prefix bitset with this mask, and the
// longest match is the highest set bit of that intersection, because the ART
// base index is monotone in prefix length
var lpmTable [256][4]uint64

// init fills lpmTable once - 256 octets times 8 lengths, cheap enough to do at
// start rather than compute per lookup. for each (octet, length) we set the
// ART index that that within-stride prefix occupies: the high `length` bits of
// the octet, with the 1<<length sentinel that makes the index unique
func init() {
	for octet := 0; octet < 256; octet++ {
		for length := uint(0); length < 8; length++ {
			idx := uint(octet)>>(8-length) | 1<<length
			lpmTable[octet][idx>>6] |= 1 << (idx & 63)
		}
	}
}

// pfxIndex maps an octet and a within-stride prefix length (0..7) to its ART
// base index
// high `length` bits of the octet, or'd with 1<<length so /0 is 1, /1 is 2|bit,
// and so on - that's the standard ART numbering
func pfxIndex(octet uint8, length uint8) uint {
	return uint(octet)>>(8-length) | 1<<length
}

// pfxLength recovers the within-stride length from an ART base index
// bits.Len(idx)-1 because of the 1<<length sentinel - index 1 is /0, 2..3 are /1
func pfxLength(idx uint) uint8 { return uint8(bits.Len(idx)) - 1 }

// pfxOctet recovers the octet from an ART base index
// strip the sentinel, then shift the remaining prefix bits back up to the top
// of the byte so a /4 of 0b1010 comes out as 0xA0
func pfxOctet(idx uint) uint8 {
	length := pfxLength(idx)
	return uint8(idx&(1<<length-1)) << (8 - length)
}

// leaf is a path-compressed prefix: its full key, its length, and its route id
type leaf struct {
	high, low uint64
	bits      uint8
	id        uint32
}

// covers reports whether the leaf's prefix contains the address
// XOR the keys, mask to the leaf's length, both halves must be zero - same
// test as "the address agrees with the prefix on the first bits bits"
func (lf *leaf) covers(high, low uint64) bool {
	maskHigh, maskLow := masks128(int(lf.bits))
	return (high^lf.high)&maskHigh == 0 && (low^lf.low)&maskLow == 0
}

// tree is a pointer-free stride-8 ART over one address family
//
// node n owns pfx[4n:4n+4] and kids[4n:4n+4] as bitsets, and its items are the
// popcount-compressed runs beginning at pfxBase[n] and kidBase[n]. that's why
// we're SoA: lookup touches four slices per level, which aosart then packs
// back into one struct to cut the cache-line count
type tree struct {
	pfx      []uint64
	kids     []uint64
	pfxBase  []uint32
	kidBase  []uint32
	pfxItems []uint32 // route ids, ascending by prefix index
	kidItems []uint32 // tagged references, ascending by octet
	leaves   []leaf
	depth    int // 4 for IPv4, 16 for IPv6
	empty    bool
}

// rank returns the number of set bits in words strictly below index i
// that's how we turn a bitset index into an offset into the compressed item
// run: count whole words, then the bits below i in the current word
func rank(words []uint64, i uint) int {
	word := i >> 6
	total := 0
	for k := uint(0); k < word; k++ {
		total += bits.OnesCount64(words[k])
	}
	return total + bits.OnesCount64(words[word]&(1<<(i&63)-1))
}

// testBit reports whether bit i is set in the 256-bit word array
// one shift-and-mask, no range check - callers already know i is in 0..255
func testBit(words []uint64, i uint) bool { return words[i>>6]&(1<<(i&63)) != 0 }

// nodePfx slices the four prefix-bitset words belonging to node
// three-index slice so the cap is 4 and a mistaken append can't clobber the
// next node's bitset
func (t *tree) nodePfx(node uint32) []uint64  { return t.pfx[node*4 : node*4+4 : node*4+4] }

// nodeKids slices the four child-bitset words belonging to node
// same three-index trick as nodePfx
func (t *tree) nodeKids(node uint32) []uint64 { return t.kids[node*4 : node*4+4 : node*4+4] }

// bestPfx returns the route id of the longest prefix stored at this node that
// covers octet
//
// intersect the node's prefix bitset with lpmTable[octet], then walk words
// high-to-low so the first hit is the highest ART index, which is the longest
// match. rank that index to find the compressed slot
func (t *tree) bestPfx(node uint32, octet uint8) (uint32, bool) {
	words := t.nodePfx(node)
	mask := &lpmTable[octet]
	for word := 3; word >= 0; word-- {
		if hit := words[word] & mask[word]; hit != 0 {
			idx := uint(word)*64 + uint(63-bits.LeadingZeros64(hit))
			return t.pfxItems[t.pfxBase[node]+uint32(rank(words, idx))], true
		}
	}
	return 0, false
}

// childRef returns the tagged reference stored at octet, if any
// test the kid bitset, then rank to the compressed slot - same shape as
// bestPfx but one bit not an LPM intersection
func (t *tree) childRef(node uint32, octet uint8) (uint32, bool) {
	words := t.nodeKids(node)
	if !testBit(words, uint(octet)) {
		return 0, false
	}
	return t.kidItems[t.kidBase[node]+uint32(rank(words, uint(octet)))], true
}

// octetAt pulls the depth'th octet out of a 128-bit key
// depths 0..7 live in high, 8..15 in low; we shift from the top of the word
// so depth 0 is the most significant octet - IPv4 keys sit in the top 32 of
// high, so depths 0..3 still work
func octetAt(high, low uint64, depth int) uint8 {
	if depth < 8 {
		return uint8(high >> (56 - depth*8))
	}
	return uint8(low >> (56 - (depth-8)*8))
}

// masks128 returns the 128-bit mask for a prefix length, split across two words
// /0 is both zeros, /1../64 live entirely in high, longer lengths fill high
// and take the top of low
func masks128(length int) (high, low uint64) {
	if length == 0 {
		return 0, 0
	}
	if length <= 64 {
		return ^uint64(0) << (64 - length), 0
	}
	return ^uint64(0), ^uint64(0) << (128 - length)
}

// lookup performs the longest-prefix match, testing each level's own prefixes
// on the way down and keeping the last match found
//
// empty tree misses immediately. otherwise we walk from the root: at each
// depth, bestPfx may update `best`, then we follow the child. a missing child
// means we're done. a fringe fills the whole subtree and is only left in place
// when nothing longer was inserted under it, so it's the winner outright. a
// leaf is a path-compressed tail - covers() decides whether it matches, else
// we keep whatever we already had
func (t *tree) lookup(high, low uint64) (uint32, bool) {
	if t.empty {
		return 0, false
	}
	node := uint32(0)
	best, found := uint32(0), false
	for depth := 0; depth < t.depth; depth++ {
		octet := octetAt(high, low, depth)
		if id, ok := t.bestPfx(node, octet); ok {
			best, found = id, true
		}
		ref, ok := t.childRef(node, octet)
		if !ok {
			return best, found
		}
		switch ref & tagMask {
		case refNode:
			node = ref & payloadMask
		case refFringe:
			// a fringe fills the whole subtree below this octet and is only ever
			// left in place when nothing longer was inserted under it, so it is
			// the winner outright
			return ref & payloadMask, true
		default: // refLeaf
			lf := &t.leaves[ref&payloadMask]
			if lf.covers(high, low) {
				return lf.id, true
			}
			return best, found
		}
	}
	return best, found
}

// exact returns the route id stored for exactly this prefix
//
// we descend `length/8` full strides following children. a missing child or a
// fringe/leaf that isn't this prefix is a miss. a fringe matches only when the
// query is exactly the stride-aligned prefix that fringe represents
//
// remainder 0 after the loop means the prefix ends on a stride boundary and
// the parent held a node rather than a fringe - the fringe was split when
// something longer was inserted - so the prefix is now that node's own
// zero-length entry (ART index 1). this holds at every depth, including the
// root. otherwise we test the within-stride ART index for (octet, remainder)
func (t *tree) exact(high, low uint64, length uint8) (uint32, bool) {
	if t.empty {
		return 0, false
	}
	node := uint32(0)
	depth := int(length) / 8
	remainder := length % 8
	for level := 0; level < depth; level++ {
		octet := octetAt(high, low, level)
		ref, ok := t.childRef(node, octet)
		if !ok {
			return 0, false
		}
		switch ref & tagMask {
		case refNode:
			node = ref & payloadMask
		case refFringe:
			// a fringe is the prefix of length (level+1)*8 at this octet
			if remainder == 0 && level == depth-1 {
				return ref & payloadMask, true
			}
			return 0, false
		default:
			lf := &t.leaves[ref&payloadMask]
			if lf.bits == length && lf.high == high && lf.low == low {
				return lf.id, true
			}
			return 0, false
		}
	}
	if remainder == 0 {
		// the prefix ends on a stride boundary. reaching here means the parent
		// held a node rather than a fringe - the fringe was split when
		// something longer was inserted - so the prefix is now that node's own
		// zero-length entry. this holds at every depth, including the root
		words := t.nodePfx(node)
		if testBit(words, 1) {
			return t.pfxItems[t.pfxBase[node]+uint32(rank(words, 1))], true
		}
		return 0, false
	}
	octet := octetAt(high, low, depth)
	idx := pfxIndex(octet, remainder)
	words := t.nodePfx(node)
	if !testBit(words, idx) {
		return 0, false
	}
	return t.pfxItems[t.pfxBase[node]+uint32(rank(words, idx))], true
}

// match is one prefix yielded by a traversal
type match struct {
	high, low uint64
	bits      uint8
	id        uint32
}

// walkSupernets visits every stored prefix covering the address, longest first
//
// prefixes are collected during a single descent and yielded in reverse, so no
// ancestor link is stored anywhere in the index. what we buffer is deliberately
// tiny: two bytes per match plus one node index per level, rather than the
// reconstructed prefixes themselves. a buffer of 129 full matches would be
// three kilobytes of stack that Go zeroes on every call, which measured at
// over a hundred nanoseconds - far more than the walk itself
//
// hits[i] packs depth<<8 | ART index. we collect node prefixes in ascending
// index order (that's ascending length) then yield them last-to-first after
// whatever leaf/fringe terminated the descent, so overall order is longest
// first
func (t *tree) walkSupernets(high, low uint64, yield func(match) bool) {
	if t.empty {
		return
	}
	var hits [136]uint16 // depth<<8 | ART prefix index
	var nodes [17]uint32
	count := 0

	node := uint32(0)
	fringeID, fringeDepth := uint32(0), -1
	var pathLeaf *leaf
	for depth := 0; depth < t.depth; depth++ {
		nodes[depth] = node
		octet := octetAt(high, low, depth)
		words := t.nodePfx(node)
		mask := &lpmTable[octet]
		// ascending index order is ascending prefix length, so collecting in
		// index order and yielding in reverse gives longest-first overall
		for word := 0; word < 4; word++ {
			hit := words[word] & mask[word]
			for hit != 0 {
				idx := uint(word)*64 + uint(bits.TrailingZeros64(hit))
				hit &= hit - 1
				hits[count] = uint16(depth)<<8 | uint16(idx)
				count++
			}
		}
		ref, ok := t.childRef(node, octet)
		if !ok {
			break
		}
		if ref&tagMask == refNode {
			node = ref & payloadMask
			continue
		}
		if ref&tagMask == refFringe {
			fringeID, fringeDepth = ref&payloadMask, depth
			break
		}
		lf := &t.leaves[ref&payloadMask]
		if lf.covers(high, low) {
			pathLeaf = lf
		}
		break
	}

	// the deepest match, if any, is whatever terminated the descent
	if pathLeaf != nil {
		if !yield(match{high: pathLeaf.high, low: pathLeaf.low, bits: pathLeaf.bits, id: pathLeaf.id}) {
			return
		}
	} else if fringeDepth >= 0 {
		length := (fringeDepth + 1) * 8
		keyHigh, keyLow := withOctet(high, low, fringeDepth, octetAt(high, low, fringeDepth))
		keyHigh, keyLow = maskKey(keyHigh, keyLow, length)
		if !yield(match{high: keyHigh, low: keyLow, bits: uint8(length), id: fringeID}) {
			return
		}
	}

	for i := count - 1; i >= 0; i-- {
		depth := int(hits[i] >> 8)
		idx := uint(hits[i] & 0xff)
		node := nodes[depth]
		words := t.nodePfx(node)
		length := pfxLength(idx)
		keyHigh, keyLow := withOctet(high, low, depth, pfxOctet(idx))
		total := depth*8 + int(length)
		keyHigh, keyLow = maskKey(keyHigh, keyLow, total)
		id := t.pfxItems[t.pfxBase[node]+uint32(rank(words, idx))]
		if !yield(match{high: keyHigh, low: keyLow, bits: uint8(total), id: id}) {
			return
		}
	}
}

// walkSubnets visits the prefix itself and every stored prefix contained in it
//
// we descend to the node that owns the query's own level, same shape as exact
// a fringe that's exactly the query yields just itself (nothing can sit under
// a fringe). a path-compressed leaf is contained when the query is a prefix of
// it - then the leaf is the only thing in that subtree
//
// remainder != 0: the query lives as a within-stride prefix on this node. we
// yield it, then walkWithin for everything longer that's still inside it
// remainder == 0: the query spans exactly this node, so walkNode yields the
// node's own zero-length entry (the query) before anything below it
func (t *tree) walkSubnets(high, low uint64, length uint8, yield func(match) bool) bool {
	if t.empty {
		return false
	}
	node := uint32(0)
	depth := int(length) / 8
	remainder := length % 8

	// descend to the node that owns the prefix's own level
	for level := 0; level < depth; level++ {
		octet := octetAt(high, low, level)
		ref, ok := t.childRef(node, octet)
		if !ok {
			return false
		}
		switch ref & tagMask {
		case refNode:
			node = ref & payloadMask
		case refFringe:
			if remainder == 0 && level == depth-1 {
				yield(match{high: high, low: low, bits: length, id: ref & payloadMask})
				return true
			}
			return false
		default:
			lf := &t.leaves[ref&payloadMask]
			// a path-compressed leaf is contained in the query when the query is
			// a prefix of it
			if lf.bits >= length && sameKey(lf.high, lf.low, high, low, int(length)) {
				yield(match{high: lf.high, low: lf.low, bits: lf.bits, id: lf.id})
				return true
			}
			return false
		}
	}

	if remainder != 0 {
		octet := octetAt(high, low, depth)
		idx := pfxIndex(octet, remainder)
		words := t.nodePfx(node)
		if !testBit(words, idx) {
			return false
		}
		if !yield(match{high: high, low: low, bits: length,
			id: t.pfxItems[t.pfxBase[node]+uint32(rank(words, idx))]}) {
			return true
		}
		// every longer prefix inside the query lives either deeper in this node
		// or under one of the octets the query covers
		t.walkWithin(node, depth, high, low, length, yield)
		return true
	}

	// the query ends on a stride boundary and the parent held a node, so the
	// query spans exactly this node. walkNode yields the node's own
	// zero-length entry - the query itself - before anything below it
	t.walkNode(node, depth, high, low, yield)
	return true
}

// walkWithin yields the prefixes of node that are longer than the query and
// contained in it, then everything under the child octets the query covers
//
// `within` is the query's leftover length inside this stride (1..7). the
// covered octet range is [octet, octet | 0xff>>within] - that's the ART
// covering-range trick. we scan all 256 prefix indices (sparse but cheap at
// this size) and skip anything not longer / not in range, then walk the kid
// bitset the same way
func (t *tree) walkWithin(node uint32, depth int, high, low uint64, length uint8, yield func(match) bool) {
	within := uint8(length) - uint8(depth*8) // 1..7
	octet := octetAt(high, low, depth)
	first := octet
	last := octet | uint8(0xff>>within)

	words := t.nodePfx(node)
	base := t.pfxBase[node]
	for idx := uint(1); idx < 256; idx++ {
		if !testBit(words, idx) {
			continue
		}
		if pfxLength(idx) <= within {
			continue
		}
		o := pfxOctet(idx)
		if o < first || o > last {
			continue
		}
		keyHigh, keyLow := withOctet(high, low, depth, o)
		total := depth*8 + int(pfxLength(idx))
		keyHigh, keyLow = maskKey(keyHigh, keyLow, total)
		if !yield(match{high: keyHigh, low: keyLow, bits: uint8(total),
			id: t.pfxItems[base+uint32(rank(words, idx))]}) {
			return
		}
	}

	kidWords := t.nodeKids(node)
	kidBase := t.kidBase[node]
	for o := int(first); o <= int(last); o++ {
		if !testBit(kidWords, uint(o)) {
			continue
		}
		ref := t.kidItems[kidBase+uint32(rank(kidWords, uint(o)))]
		keyHigh, keyLow := withOctet(high, low, depth, uint8(o))
		if !t.walkRef(ref, depth+1, keyHigh, keyLow, yield) {
			return
		}
	}
}

// walkNode yields every prefix stored at or below node. high and low carry the
// octets already fixed by the path to node
//
// we iterate set bits with trailing-zeros so we don't walk empty slots. prefix
// items and kid items are stored in the same order as the bitset, so we can
// just bump `position` rather than re-rank. walkRef handles the three child
// kinds. false from yield aborts the whole walk
func (t *tree) walkNode(node uint32, depth int, high, low uint64, yield func(match) bool) bool {
	words := t.nodePfx(node)
	position := t.pfxBase[node]
	for word := 0; word < 4; word++ {
		remaining := words[word]
		for remaining != 0 {
			idx := uint(word)*64 + uint(bits.TrailingZeros64(remaining))
			remaining &= remaining - 1
			id := t.pfxItems[position]
			position++
			keyHigh, keyLow := withOctet(high, low, depth, pfxOctet(idx))
			total := depth*8 + int(pfxLength(idx))
			keyHigh, keyLow = maskKey(keyHigh, keyLow, total)
			if !yield(match{high: keyHigh, low: keyLow, bits: uint8(total), id: id}) {
				return false
			}
		}
	}
	kidWords := t.nodeKids(node)
	position = t.kidBase[node]
	for word := 0; word < 4; word++ {
		remaining := kidWords[word]
		for remaining != 0 {
			octet := uint8(uint(word)*64 + uint(bits.TrailingZeros64(remaining)))
			remaining &= remaining - 1
			ref := t.kidItems[position]
			position++
			keyHigh, keyLow := withOctet(high, low, depth, octet)
			if !t.walkRef(ref, depth+1, keyHigh, keyLow, yield) {
				return false
			}
		}
	}
	return true
}

// walkRef dispatches a tagged child reference onto the right walker
// node: recurse. fringe: it's a stride-aligned prefix of length depth*8 (the
// octets already in high/low, masked). leaf: yield the compressed prefix as-is
func (t *tree) walkRef(ref uint32, depth int, high, low uint64, yield func(match) bool) bool {
	switch ref & tagMask {
	case refNode:
		return t.walkNode(ref&payloadMask, depth, high, low, yield)
	case refFringe:
		keyHigh, keyLow := maskKey(high, low, depth*8)
		return yield(match{high: keyHigh, low: keyLow, bits: uint8(depth * 8), id: ref & payloadMask})
	default:
		lf := &t.leaves[ref&payloadMask]
		return yield(match{high: lf.high, low: lf.low, bits: lf.bits, id: lf.id})
	}
}

// withOctet returns the key with the octet at the given depth replaced
// clear the 8-bit window then or the new value in. depth < 8 writes high,
// otherwise low - same split as octetAt
func withOctet(high, low uint64, depth int, octet uint8) (uint64, uint64) {
	if depth < 8 {
		shift := uint(56 - depth*8)
		return high&^(uint64(0xff)<<shift) | uint64(octet)<<shift, low
	}
	shift := uint(56 - (depth-8)*8)
	return high, low&^(uint64(0xff)<<shift) | uint64(octet)<<shift
}

// maskKey zeros bits below length
// AND with masks128 so a reconstructed prefix has a canonical host part
func maskKey(high, low uint64, length int) (uint64, uint64) {
	maskHigh, maskLow := masks128(length)
	return high & maskHigh, low & maskLow
}

// sameKey reports whether two keys agree on the first length bits
// XOR-and-mask, both halves - same test as leaf.covers
func sameKey(aHigh, aLow, bHigh, bLow uint64, length int) bool {
	maskHigh, maskLow := masks128(length)
	return (aHigh^bHigh)&maskHigh == 0 && (aLow^bLow)&maskLow == 0
}

// be32 packs 4 big-endian bytes into a uint32
// octet 0 is the high byte, same as you'd write the address
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// words16 splits a 16-byte IPv6 address into two uint64s
// high is bytes 0..7, low is 8..15, both big-endian so octetAt shifts work
func words16(b [16]byte) (high, low uint64) {
	high = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	low = uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	return high, low
}

// addrOf rebuilds a netip.Addr from a key
// v4: the address lives in the top 32 of high (that's how we packed it). v6:
// peel octets off both words into a [16]byte. used when a traversal match has
// to become a netip.Prefix for the caller
func addrOf(high, low uint64, is4 bool) netip.Addr {
	if is4 {
		key := uint32(high >> 32)
		return netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
	}
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(high >> (56 - i*8))
		b[8+i] = byte(low >> (56 - i*8))
	}
	return netip.AddrFrom16(b)
}
