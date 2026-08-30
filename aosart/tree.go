// Package aosart is soaart tuned for speed, accepting a modest increase in
// retained memory - same stride-8 ART, stored as array-of-structs
//
// three things changed, each aimed at a cost we measured rather than guessed
//
// # one node, one struct
//
// soaart keeps a node's prefix bitset, child bitset, prefix base and child
// base in four separate parallel slices, so a single level of descent reads
// four unrelated addresses and pays four cache lines. here a node is one
// struct with its fields grouped by which half of the descent uses them: the
// prefix bitset, its ranks and its base share the first cache line, and the
// child bitset, its ranks and its base share the second. a level of descent
// touches two lines instead of four
//
// # ranks are precomputed
//
// locating an item in a popcount-compressed array needs the number of set bits
// below its index, which soaart recomputes by looping over the preceding
// words. each node here carries the running count for each word, so the index
// is one load, one add and one masked popcount, with no loop and no
// data-dependent branch
//
// # supernets buffer the path, not the prefixes
//
// ancestors must be yielded most-specific first, but a descent discovers them
// least-specific first, so something has to be buffered. soaart buffered the
// matches; that was measured at 166 ns, most of it Go zeroing the buffer on
// entry. this version buffers only the node index per level - sixty-eight
// bytes - and re-derives the matches on the way back up, walking each node's
// bitset from its highest set bit downwards so the yield order falls out for
// free
//
// Index is immutable, unsynchronised concurrent reads are fine
package aosart

import (
	"errors"
	"math/bits"
	"net/netip"
)

// ErrBadPrefix reports an invalid or zoned prefix
var ErrBadPrefix = errors.New("aosart: bad prefix")

// ErrTooManyRoutes reports a table larger than the index space
var ErrTooManyRoutes = errors.New("aosart: too many routes")

const (
	tagShift    = 30
	tagMask     = uint32(3) << tagShift
	payloadMask = ^tagMask

	refNode   = uint32(0) << tagShift // payload is a node index
	refLeaf   = uint32(1) << tagShift // payload is a leaf index
	refFringe = uint32(2) << tagShift // payload is a route id

	maxPayload = payloadMask
)

// lpmTable[octet] has a bit set at every ART prefix index covering octet, for
// prefix lengths 0 through 7 within the stride. the longest match in a node is
// the highest set bit of its prefix bitset intersected with this mask, because
// the ART base index is monotone in prefix length
var lpmTable [256][4]uint64

// init fills lpmTable once - 256 octets times 8 lengths, cheap enough to do at
// start rather than compute per lookup. for each (octet, length) we set the
// ART index that that within-stride prefix occupies
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
// high `length` bits of the octet, or'd with 1<<length so /0 is 1, /1 is 2|bit
func pfxIndex(octet uint8, length uint8) uint { return uint(octet)>>(8-length) | 1<<length }

// pfxLength recovers the within-stride length from an ART base index
// bits.Len(idx)-1 because of the 1<<length sentinel
func pfxLength(idx uint) uint8 { return uint8(bits.Len(idx)) - 1 }

// pfxOctet recovers the octet from an ART base index
// strip the sentinel, then shift the remaining prefix bits back up to the top
// of the byte
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
// XOR the keys, mask to the leaf's length, both halves must be zero
func (lf *leaf) covers(high, low uint64) bool {
	maskHigh, maskLow := masks128(int(lf.bits))
	return (high^lf.high)&maskHigh == 0 && (low^lf.low)&maskLow == 0
}

// node is one stride of the trie. the field order is deliberate: everything
// the prefix half of a descent reads precedes everything the child half reads,
// so each half is one cache line
type node struct {
	pfx     [4]uint64
	pfxRank [4]uint16 // set bits in pfx words below this one
	pfxBase uint32
	_       uint32 // pad, keeping the child half on its own line

	kids    [4]uint64
	kidRank [4]uint16
	kidBase uint32
	_       uint32
}

// pfxIndexOf turns an ART prefix index into an offset in the compressed
// pfxItems run
// precomputed rank of the word plus popcount of the bits below idx in that
// word - no loop over preceding words, that's the whole point of pfxRank
func (n *node) pfxIndexOf(idx uint) uint32 {
	return uint32(n.pfxRank[idx>>6]) + uint32(bits.OnesCount64(n.pfx[idx>>6]&(1<<(idx&63)-1)))
}

// kidIndexOf turns an octet into an offset in the compressed kidItems run
// same as pfxIndexOf, against the child bitset
func (n *node) kidIndexOf(octet uint) uint32 {
	return uint32(n.kidRank[octet>>6]) + uint32(bits.OnesCount64(n.kids[octet>>6]&(1<<(octet&63)-1)))
}

// tree is a pointer-free stride-8 ART over one address family
// nodes is the AoS array; pfxItems/kidItems are still popcount-compressed
// runs, indexed via node.pfxBase/kidBase. empty tree is nodes == nil
type tree struct {
	nodes    []node
	pfxItems []uint32 // route ids, ascending by prefix index
	kidItems []uint32 // tagged references, ascending by octet
	leaves   []leaf
	depth    int // 4 for IPv4, 16 for IPv6
}

// testBit reports whether bit i is set in a 256-bit [4]uint64
// pointer so we can pass &node.pfx without copying
func testBit(words *[4]uint64, i uint) bool { return words[i>>6]&(1<<(i&63)) != 0 }

// octetAt pulls the depth'th octet out of a 128-bit key
// depths 0..7 live in high, 8..15 in low. IPv4 keys sit in the top 32 of high
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

// bestPfx returns the route id of the longest prefix at this node covering
// octet
//
// intersect with lpmTable[octet], walk words high-to-low so the first hit is
// the highest ART index. pfxIndexOf finds the compressed slot without a rank
// loop
func (t *tree) bestPfx(n *node, octet uint8) (uint32, bool) {
	mask := &lpmTable[octet]
	for word := 3; word >= 0; word-- {
		if hit := n.pfx[word] & mask[word]; hit != 0 {
			idx := uint(word)*64 + uint(63-bits.LeadingZeros64(hit))
			return t.pfxItems[n.pfxBase+n.pfxIndexOf(idx)], true
		}
	}
	return 0, false
}

// childRef returns the tagged reference stored at octet, if any
// test the kid bitset, kidIndexOf to the compressed slot
func (t *tree) childRef(n *node, octet uint8) (uint32, bool) {
	if !testBit(&n.kids, uint(octet)) {
		return 0, false
	}
	return t.kidItems[n.kidBase+n.kidIndexOf(uint(octet))], true
}

// lookup performs the longest-prefix match, testing each level's own prefixes
// on the way down and keeping the last match
//
// empty (nodes nil) misses immediately. otherwise we walk from nodes[0]: at
// each depth bestPfx may update `best`, then we follow the child. a missing
// child means we're done. a fringe fills the whole subtree and is only left in
// place when nothing longer was inserted under it, so it wins outright. a leaf
// is a path-compressed tail - covers() decides whether it matches
func (t *tree) lookup(high, low uint64) (uint32, bool) {
	if len(t.nodes) == 0 {
		return 0, false
	}
	n := &t.nodes[0]
	best, found := uint32(0), false
	for depth := 0; depth < t.depth; depth++ {
		octet := octetAt(high, low, depth)
		if id, ok := t.bestPfx(n, octet); ok {
			best, found = id, true
		}
		ref, ok := t.childRef(n, octet)
		if !ok {
			return best, found
		}
		switch ref & tagMask {
		case refNode:
			n = &t.nodes[ref&payloadMask]
		case refFringe:
			// a fringe is only left in place when nothing longer was inserted
			// beneath it, so it wins outright
			return ref & payloadMask, true
		default:
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
// we descend length/8 full strides following children. a missing child or a
// fringe/leaf that isn't this prefix is a miss. a fringe matches only when the
// query is exactly the stride-aligned prefix that fringe represents
//
// after the loop, remainder 0 means ART index 1 (the node's zero-length
// entry, which is what a split fringe becomes). otherwise we test the
// within-stride index. unlike soaart we don't special-case remainder==0 into
// its own branch - idx starts at 1 and we overwrite it when remainder != 0
func (t *tree) exact(high, low uint64, length uint8) (uint32, bool) {
	if len(t.nodes) == 0 {
		return 0, false
	}
	n := &t.nodes[0]
	depth := int(length) / 8
	remainder := length % 8
	for level := 0; level < depth; level++ {
		octet := octetAt(high, low, level)
		ref, ok := t.childRef(n, octet)
		if !ok {
			return 0, false
		}
		switch ref & tagMask {
		case refNode:
			n = &t.nodes[ref&payloadMask]
		case refFringe:
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
	idx := uint(1)
	if remainder != 0 {
		idx = pfxIndex(octetAt(high, low, depth), remainder)
	}
	if !testBit(&n.pfx, idx) {
		return 0, false
	}
	return t.pfxItems[n.pfxBase+n.pfxIndexOf(idx)], true
}

// match is one prefix yielded by a traversal
type match struct {
	high, low uint64
	bits      uint8
	id        uint32
}

// walkSupernets visits every stored prefix covering the address, longest first
//
// only the node path is buffered; the matches are re-derived on the way back
// up. that's the measured win over soaart: 17 uint32s instead of a 136-entry
// hits array that Go zeroes on every call
//
// first we descend, recording the node at each level, until a missing child
// or a fringe/leaf. the terminator (if it covers) is longer than anything
// above it, so we yield it first. then we walk the path backwards, and inside
// each node walk the covering prefix bits high-to-low so longest-first falls
// out without a reverse pass
func (t *tree) walkSupernets(high, low uint64, yield func(match) bool) {
	if len(t.nodes) == 0 {
		return
	}
	var path [17]uint32
	levels := 0
	current := uint32(0)
	terminal := -1
	var terminalRef uint32
	for depth := 0; depth < t.depth; depth++ {
		path[depth] = current
		levels = depth + 1
		octet := octetAt(high, low, depth)
		ref, ok := t.childRef(&t.nodes[current], octet)
		if !ok {
			break
		}
		if ref&tagMask == refNode {
			current = ref & payloadMask
			continue
		}
		terminal, terminalRef = depth, ref
		break
	}

	// whatever terminated the descent is longer than any node prefix above it
	if terminal >= 0 {
		if terminalRef&tagMask == refFringe {
			length := (terminal + 1) * 8
			keyHigh, keyLow := maskKey(high, low, length)
			if !yield(match{high: keyHigh, low: keyLow, bits: uint8(length), id: terminalRef & payloadMask}) {
				return
			}
		} else {
			lf := &t.leaves[terminalRef&payloadMask]
			if lf.covers(high, low) {
				if !yield(match{high: lf.high, low: lf.low, bits: lf.bits, id: lf.id}) {
					return
				}
			}
		}
	}

	for depth := levels - 1; depth >= 0; depth-- {
		n := &t.nodes[path[depth]]
		octet := octetAt(high, low, depth)
		mask := &lpmTable[octet]
		// highest index first is longest first within the node
		for word := 3; word >= 0; word-- {
			hit := n.pfx[word] & mask[word]
			for hit != 0 {
				bit := 63 - bits.LeadingZeros64(hit)
				hit &^= uint64(1) << bit
				idx := uint(word)*64 + uint(bit)
				length := pfxLength(idx)
				keyHigh, keyLow := withOctet(high, low, depth, pfxOctet(idx))
				total := depth*8 + int(length)
				keyHigh, keyLow = maskKey(keyHigh, keyLow, total)
				if !yield(match{high: keyHigh, low: keyLow, bits: uint8(total),
					id: t.pfxItems[n.pfxBase+n.pfxIndexOf(idx)]}) {
					return
				}
			}
		}
	}
}

// walkSubnets visits the prefix itself and every stored prefix contained in it
//
// we descend to the node that owns the query's own level, same shape as exact
// a fringe that's exactly the query yields just itself. a path-compressed leaf
// is contained when the query is a prefix of it
//
// remainder != 0: the query lives as a within-stride prefix on this node - we
// yield it, then walkWithin for everything longer that's still inside it
// remainder == 0: the query spans exactly this node, so walkNode yields the
// node's own zero-length entry (the query) before anything below it
func (t *tree) walkSubnets(high, low uint64, length uint8, yield func(match) bool) bool {
	if len(t.nodes) == 0 {
		return false
	}
	index := uint32(0)
	depth := int(length) / 8
	remainder := length % 8

	for level := 0; level < depth; level++ {
		octet := octetAt(high, low, level)
		ref, ok := t.childRef(&t.nodes[index], octet)
		if !ok {
			return false
		}
		switch ref & tagMask {
		case refNode:
			index = ref & payloadMask
		case refFringe:
			if remainder == 0 && level == depth-1 {
				yield(match{high: high, low: low, bits: length, id: ref & payloadMask})
				return true
			}
			return false
		default:
			lf := &t.leaves[ref&payloadMask]
			if lf.bits >= length && sameKey(lf.high, lf.low, high, low, int(length)) {
				yield(match{high: lf.high, low: lf.low, bits: lf.bits, id: lf.id})
				return true
			}
			return false
		}
	}

	n := &t.nodes[index]
	if remainder != 0 {
		idx := pfxIndex(octetAt(high, low, depth), remainder)
		if !testBit(&n.pfx, idx) {
			return false
		}
		if !yield(match{high: high, low: low, bits: length,
			id: t.pfxItems[n.pfxBase+n.pfxIndexOf(idx)]}) {
			return true
		}
		t.walkWithin(n, depth, high, low, length, yield)
		return true
	}
	t.walkNode(n, depth, high, low, yield)
	return true
}

// walkWithin yields the prefixes of n longer than the query and contained in
// it, then everything under the child octets the query covers
//
// `within` is the query's leftover length inside this stride (1..7). the
// covered octet range is [octet, octet | 0xff>>within]. unlike soaart we walk
// set bits with trailing-zeros and bump `position` rather than re-rank, then
// skip anything not longer / not in range - same order as the compressed run
func (t *tree) walkWithin(n *node, depth int, high, low uint64, length uint8, yield func(match) bool) {
	within := length - uint8(depth*8) // 1..7
	octet := octetAt(high, low, depth)
	first := octet
	last := octet | uint8(0xff>>within)

	position := n.pfxBase
	for word := 0; word < 4; word++ {
		remaining := n.pfx[word]
		for remaining != 0 {
			idx := uint(word)*64 + uint(bits.TrailingZeros64(remaining))
			remaining &= remaining - 1
			id := t.pfxItems[position]
			position++
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
			if !yield(match{high: keyHigh, low: keyLow, bits: uint8(total), id: id}) {
				return
			}
		}
	}

	position = n.kidBase
	for word := 0; word < 4; word++ {
		remaining := n.kids[word]
		for remaining != 0 {
			o := uint8(uint(word)*64 + uint(bits.TrailingZeros64(remaining)))
			remaining &= remaining - 1
			ref := t.kidItems[position]
			position++
			if o < first || o > last {
				continue
			}
			keyHigh, keyLow := withOctet(high, low, depth, o)
			if !t.walkRef(ref, depth+1, keyHigh, keyLow, yield) {
				return
			}
		}
	}
}

// walkNode yields every prefix stored at or below n
// high/low carry the octets already fixed by the path to n. we iterate set
// bits with trailing-zeros so we don't walk empty slots, bumping position
// through the compressed runs. walkRef handles the three child kinds
func (t *tree) walkNode(n *node, depth int, high, low uint64, yield func(match) bool) bool {
	position := n.pfxBase
	for word := 0; word < 4; word++ {
		remaining := n.pfx[word]
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
	position = n.kidBase
	for word := 0; word < 4; word++ {
		remaining := n.kids[word]
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
// node: recurse. fringe: stride-aligned prefix of length depth*8. leaf: yield
// the compressed prefix as-is
func (t *tree) walkRef(ref uint32, depth int, high, low uint64, yield func(match) bool) bool {
	switch ref & tagMask {
	case refNode:
		return t.walkNode(&t.nodes[ref&payloadMask], depth, high, low, yield)
	case refFringe:
		keyHigh, keyLow := maskKey(high, low, depth*8)
		return yield(match{high: keyHigh, low: keyLow, bits: uint8(depth * 8), id: ref & payloadMask})
	default:
		lf := &t.leaves[ref&payloadMask]
		return yield(match{high: lf.high, low: lf.low, bits: lf.bits, id: lf.id})
	}
}

// withOctet returns the key with the octet at the given depth replaced
// clear the 8-bit window then or the new value in. depth < 8 writes high
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
// v4: the address lives in the top 32 of high. v6: peel octets off both words
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
