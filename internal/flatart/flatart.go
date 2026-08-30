// Package flatart is the immutable arena core shared by flatset, flatlpm
// and flatwalk
//
// stride-8 ART fronted by a direct-indexed root, held in pointer-free
// arenas addressed by uint32 slots - five properties make the descent
// cheaper than the alternatives we've measured here
//
//  1) inherited node defaults instead of per-level backtracking - every
//     node records, at ART index 1, the shortest-prefix match covering
//     the whole node - a prefix stored at stride depth d always has a
//     length in (root+8d, root+8d+8], so it's strictly longer than
//     anything storable above it - combined with the inherited default
//     this means the deepest node the descent reaches already knows the
//     answer - we carry no "best so far", test no coverage summary per
//     level, and never walk back up - bart descends onto a 16-deep stack
//     and then backtracks, groupartset tests a coverage bitmask at every
//     level
//
//  2) a separate node kind for the childless case - in the generated
//     distributions used here, well over nine tenths of stride nodes have
//     no children at all: they're the bottom of the trie, holding a
//     handful of prefixes that end on the stride boundary - those become a
//     stop, which drops the 64-byte child block entirely - a lookup that
//     lands on a stop performs no child test and reads one cache line
//     before the value
//
//  3) prefixes split by shape - host covers the ART indices whose length
//     ends exactly on the stride boundary - /16, /24, /32, /48 and so on,
//     which dominate both real tables and the generated distributions
//     short covers the partial-stride prefixes and the inherited default
//     the common resolution therefore tests one bit of a 32-byte set
//
//  4) ranks resolved from a packed prefix sum rather than recounted - each
//     set carries the running population of its preceding words in one
//     word, so a rank is a shift, a mask, one popcount and an add
//
//  5) a 16-bit root stride stored in two 8-bit levels - a flat 16-bit root
//     is a 256 KiB array per family, which is mostly empty for IPv6 and
//     for any table concentrated in a few /8s - splitting it into a 1 KiB
//     /8 index over 1 KiB blocks makes the cost proportional to occupancy,
//     and blocks whose 256 slots are uniform - every /8 holding nothing
//     but a covering route - are shared - the extra load is from an array
//     small enough to stay in L1, and the stride depth is unchanged, so a
//     /24 is still two loads from its value
//
// values are opaque non-zero uint32 indices, zero means no match
// the 30-bit reference width caps a table at 2^30 entries
package flatart

import (
	"errors"
	"math/bits"
	"net/netip"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// ErrTooLarge means we blew the 30-bit arena reference width
var ErrTooLarge = errors.New("flatart: table exceeds 2^30 entries")

// tags occupy the top two bits of every arena reference
// tag zero is a terminal value, which makes an empty slot and a miss the
// same thing and lets the hot path return the payload without masking
// the childless stride is placed last so the single most common shape is
// reached by one unsigned compare
//
// two bits, not three: adding a fourth arena kind and the compare that
// selects it cost 5.7 ns of a 15 ns IPv4 lookup when we measured it,
// because every extra compare sits between the root load and the stride
// load on the dependent chain - whatever a new stride shape might save
// has to beat that first
const (
	refMask = 0x3fff_ffff
	tagNode = 0x4000_0000 // index into Index.nodes
	tagLeaf = 0x8000_0000 // index into Index.leaf4 or Index.leaf6
	tagStop = 0xc000_0000 // index into Index.stops
)

// MaxEntries is the largest number of prefixes an index can hold
const MaxEntries = refMask

// rootBits is the width of the root stride
// realised as two 8-bit levels, see the package comment
const (
	rootBits  = 16
	rootBlock = 1 << 8 // slots per second-level root block
)

// group holds the child bitmask for 64 octets beside the absolute arena
// index of the group's first child
// keeping the index absolute rather than node-relative is what lets a
// level of descent read one 16-byte group and nothing else
type group struct {
	mask uint64
	slot uint32
	aux  uint32
}

// node is a stride that has children: one cache line of descent state
// followed by one of resolution state
//
//	groups[0].aux = value index of the first host prefix
//	groups[1].aux = value index of the first short prefix
//	groups[2].aux = packed word prefix sums for host
//	groups[3].aux = packed word prefix sums for short
type node struct {
	groups [4]group
	host   [4]uint64
	short  [4]uint64
}

// stop is a stride with no children
// dropping the child block makes it 80 bytes instead of 128 and removes
// the child test from the lookup that lands on it
type stop struct {
	hostBase  uint32
	shortBase uint32
	hostPre   uint32
	shortPre  uint32
	host      [4]uint64
	short     [4]uint64
}

type leaf4 struct {
	key     uint32
	value   uint32
	inherit uint32
	bits    uint8
	_       [3]byte
}

type leaf6 struct {
	hi, lo  uint64
	value   uint32
	inherit uint32
	bits    uint8
	_       [7]byte
}

// covers is the IPv6 leaf match - mask-compare on hi, then lo if we're past /64
func (lf *leaf6) covers(hi, lo uint64) bool {
	if lf.bits <= 64 {
		return (hi^lf.hi)>>(64-lf.bits) == 0
	}
	return hi == lf.hi && (lo^lf.lo)>>(128-lf.bits) == 0
}

// Options selects the optional parts of the index
type Options struct {
	// Exact builds the side table that answers exact-prefix queries for
	// prefixes no longer than the root stride - those prefixes are pushed
	// into the root and so are otherwise indistinguishable from a covering
	// match - it's also what lets All enumerate them
	Exact bool
}

// Index is an immutable prefix index
// lookups are allocation-free and safe for unsynchronised concurrent use
type Index struct {
	// the root stride is a /8 index into second-level blocks of 256 slots
	// the index is a fixed-size array pointer so addressing it by an octet
	// needs no bounds check
	rootHi4 *[rootBlock]uint32
	rootLo4 []uint32
	rootHi6 *[rootBlock]uint32
	rootLo6 []uint32

	nodes []node
	stops []stop
	refs  []uint32

	leaf4 []leaf4
	leaf6 []leaf6

	exact4 exactTable
	exact6 exactTable

	values int
}

// Values is the number of value indices the index assigns, so a caller can
// size its value slice - index zero is reserved for "no match"
func (ix *Index) Values() int { return ix.values }

// Lookup returns the value index of the longest prefix covering addr, or zero
// 4-in-6 is treated as v4 after Unmap, zoned addrs are a miss
func (ix *Index) Lookup(addr netip.Addr) uint32 {
	if addr.Is4() {
		return ix.Lookup4(prefixentry.Addr4(addr))
	}
	if !addr.IsValid() || addr.Zone() != "" {
		return 0
	}
	if addr.Is4In6() {
		// mapped v4 uses the v4 root, same as native
		return ix.Lookup4(prefixentry.Addr4(addr.Unmap()))
	}
	hi, lo := prefixentry.Addr6(addr)
	return ix.Lookup6(hi, lo)
}

// Lookup4 is the decoded IPv4 path
// with a 16-bit root IPv4 needs at most two strides, so it's written out
// rather than looped - don't turn this into a for-loop, we measured it
func (ix *Index) Lookup4(key uint32) uint32 {
	// two array indexes through the split root, /8 then /16
	slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
	if slot >= tagStop {
		// childless stride, no child test, one cache line then the value
		return resolveStop(&ix.stops[slot&refMask], uint8(key>>8))
	}
	if slot < tagNode {
		// terminal value already, including miss=0
		return slot
	}
	if slot < tagLeaf {
		n := &ix.nodes[slot&refMask]
		octet := uint(uint8(key >> 8))
		g := &n.groups[(octet>>6)&3]
		bit := uint64(1) << (octet & 63)
		if g.mask&bit == 0 {
			// no child at this octet, resolve here - inherited default is in short
			return resolveNode(n, uint8(octet))
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
		if slot >= tagStop {
			return resolveStop(&ix.stops[slot&refMask], uint8(key))
		}
		if slot < tagLeaf {
			return resolveNode(&ix.nodes[slot&refMask], uint8(key))
		}
	}
	return ix.result4(slot, key)
}

// Lookup6 is the decoded IPv6 path
// same tag tests as Lookup4, but we loop because v6 can be four or five strides
func (ix *Index) Lookup6(hi, lo uint64) uint32 {
	slot := ix.rootLo6[ix.rootHi6[hi>>56]+uint32(hi>>48&0xff)]
	word := hi
	for byteIndex := rootBits / 8; byteIndex < 16; byteIndex++ {
		if byteIndex == 8 {
			word = lo
		}
		octet := uint(uint8(word >> (56 - 8*(byteIndex&7))))
		if slot >= tagStop {
			return resolveStop(&ix.stops[slot&refMask], uint8(octet))
		}
		if slot < tagNode {
			return slot
		}
		if slot >= tagLeaf {
			lf := &ix.leaf6[slot&refMask]
			if lf.covers(hi, lo) {
				return lf.value
			}
			return lf.inherit
		}
		n := &ix.nodes[slot&refMask]
		g := &n.groups[(octet>>6)&3]
		bit := uint64(1) << (octet & 63)
		if g.mask&bit == 0 {
			return resolveNode(n, uint8(octet))
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
	}
	return 0
}

// Contains reports whether any stored prefix covers addr
// it skips every rank that Lookup performs - membership doesn't care who won
func (ix *Index) Contains(addr netip.Addr) bool {
	if addr.Is4() {
		return ix.Contains4(prefixentry.Addr4(addr))
	}
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	if addr.Is4In6() {
		return ix.Contains4(prefixentry.Addr4(addr.Unmap()))
	}
	hi, lo := prefixentry.Addr6(addr)
	return ix.Contains6(hi, lo)
}

// Contains4 is the decoded IPv4 membership path
// same descent as Lookup4, but coversSet instead of hostValue/shortValue
func (ix *Index) Contains4(key uint32) bool {
	slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
	if slot >= tagStop {
		s := &ix.stops[slot&refMask]
		return coversSet(&s.host, &s.short, uint(uint8(key>>8)))
	}
	if slot < tagNode {
		return slot != 0
	}
	if slot < tagLeaf {
		n := &ix.nodes[slot&refMask]
		octet := uint(uint8(key >> 8))
		g := &n.groups[(octet>>6)&3]
		bit := uint64(1) << (octet & 63)
		if g.mask&bit == 0 {
			return coversSet(&n.host, &n.short, octet)
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
		if slot >= tagStop {
			s := &ix.stops[slot&refMask]
			return coversSet(&s.host, &s.short, uint(uint8(key)))
		}
		if slot < tagLeaf {
			n = &ix.nodes[slot&refMask]
			return coversSet(&n.host, &n.short, uint(uint8(key)))
		}
	}
	return ix.covers4(slot, key)
}

// Contains6 is the decoded IPv6 membership path
func (ix *Index) Contains6(hi, lo uint64) bool {
	slot := ix.rootLo6[ix.rootHi6[hi>>56]+uint32(hi>>48&0xff)]
	word := hi
	for byteIndex := rootBits / 8; byteIndex < 16; byteIndex++ {
		if byteIndex == 8 {
			word = lo
		}
		octet := uint(uint8(word >> (56 - 8*(byteIndex&7))))
		if slot >= tagStop {
			s := &ix.stops[slot&refMask]
			return coversSet(&s.host, &s.short, octet)
		}
		if slot < tagNode {
			return slot != 0
		}
		if slot >= tagLeaf {
			lf := &ix.leaf6[slot&refMask]
			return lf.covers(hi, lo) || lf.inherit != 0
		}
		n := &ix.nodes[slot&refMask]
		g := &n.groups[(octet>>6)&3]
		bit := uint64(1) << (octet & 63)
		if g.mask&bit == 0 {
			return coversSet(&n.host, &n.short, octet)
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
	}
	return false
}

// result4 is the IPv4 leaf match - cover-test the stored prefix, else inherit
func (ix *Index) result4(slot, key uint32) uint32 {
	lf := &ix.leaf4[slot&refMask]
	if (key^lf.key)>>(32-lf.bits) == 0 {
		return lf.value
	}
	return lf.inherit
}

// covers4 is the membership analogue of result4
func (ix *Index) covers4(slot, key uint32) bool {
	lf := &ix.leaf4[slot&refMask]
	return (key^lf.key)>>(32-lf.bits) == 0 || lf.inherit != 0
}

// resolveNode returns the value index of the longest prefix stored at a
// stride covering octet, or zero
// inherited defaults mean this single test at the deepest reached stride
// is conclusive, so it runs once per lookup rather than once per level
func resolveNode(n *node, octet uint8) uint32 {
	if value := hostValue(&n.host, n.groups[0].aux, n.groups[2].aux, uint(octet)); value != 0 {
		return value
	}
	return shortValue(&n.short, n.groups[1].aux, n.groups[3].aux, uint(octet))
}

// resolveStop is the childless analogue of resolveNode
func resolveStop(s *stop, octet uint8) uint32 {
	if value := hostValue(&s.host, s.hostBase, s.hostPre, uint(octet)); value != 0 {
		return value
	}
	return shortValue(&s.short, s.shortBase, s.shortPre, uint(octet))
}

// hostValue resolves the shape whose length ends on the stride boundary -
// /16, /24, /32, /48 and so on
// deliberately small enough to inline, so the shape that answers most
// lookups costs no call
func hostValue(set *[4]uint64, base, pre uint32, o uint) uint32 {
	word := (o >> 6) & 3
	w := set[word]
	bit := uint64(1) << (o & 63)
	if w&bit == 0 {
		return 0
	}
	return base + (pre>>(8*word))&0xff + uint32(bits.OnesCount64(w&(bit-1)))
}

// coverShort[octet] holds the ART indices in 1..255 that cover octet, that
// is the eight proper ancestors of the host index in the complete binary
// tree - four words rather than eight, because the full-octet indices
// 256..511 are held in a set of their own and tested directly
var coverShort [256][4]uint64

// init fills coverShort so shortValue can AND instead of walking ancestors
func init() {
	for octet := range coverShort {
		for idx := (octet | 256) >> 1; idx > 0; idx >>= 1 {
			coverShort[octet][idx>>6] |= uint64(1) << (idx & 63)
		}
	}
}

// shortValue resolves the partial-stride shapes and the inherited default
// by intersecting the short set with the precomputed cover mask for this
// octet, highest word first, so the longest match falls out of the first
// non-empty word
//
// testing the eight short candidates with a fixed sequence of shifts
// instead needs no table and fewer instructions, but measured slower: it
// keeps too many values live at once and the register spills cost more
// than the table load - a branch-free form that resolves both shapes and
// selects with masks is slower again, for the same reason
func shortValue(short *[4]uint64, shortBase, shortPre uint32, o uint) uint32 {
	m := &coverShort[o&0xff]
	if x := short[3] & m[3]; x != 0 {
		return shortResult(short[3], shortBase, shortPre, 3, x)
	}
	if x := short[2] & m[2]; x != 0 {
		return shortResult(short[2], shortBase, shortPre, 2, x)
	}
	if x := short[1] & m[1]; x != 0 {
		return shortResult(short[1], shortBase, shortPre, 1, x)
	}
	if x := short[0] & m[0]; x != 0 {
		return shortResult(short[0], shortBase, shortPre, 0, x)
	}
	return 0
}

// shortResult ranks the highest set bit of the intersection within its word
func shortResult(w uint64, base, pre uint32, word uint, x uint64) uint32 {
	top := uint64(1) << (63 - uint(bits.LeadingZeros64(x)))
	return base + (pre>>(8*word))&0xff + uint32(bits.OnesCount64(w&(top-1)))
}

// coversSet reports whether any prefix in either set covers o, which is
// all a membership query needs - it performs no rank
func coversSet(host, short *[4]uint64, o uint) bool {
	if host[(o>>6)&3]>>(o&63)&1 != 0 {
		return true
	}
	m := &coverShort[o&0xff]
	return short[0]&m[0]|short[1]&m[1]|short[2]&m[2]|short[3]&m[3] != 0
}

// rankAt counts the set bits below a position in a four-word set
// the population of the preceding words is precomputed into pre at build
// time, one byte per word, so no word is recounted at lookup time
func rankAt(set *[4]uint64, pre uint32, word, bit uint) uint32 {
	word &= 3
	return (pre>>(8*word))&0xff + uint32(bits.OnesCount64(set[word]&(uint64(1)<<bit-1)))
}

// packPrefixSums precomputes the running population of a four-word set
// a word holds at most 64 bits and the total at most 192, so a byte per
// word suffices and word zero's sum is always zero
func packPrefixSums(set *[4]uint64) uint32 {
	c1 := bits.OnesCount64(set[0])
	c2 := c1 + bits.OnesCount64(set[1])
	c3 := c2 + bits.OnesCount64(set[2])
	return uint32(c1)<<8 | uint32(c2)<<16 | uint32(c3)<<24
}

// Bytes reports the retained size of the index, excluding caller value storage
func (ix *Index) Bytes() int {
	return 4*(len(ix.rootHi4)+len(ix.rootLo4)+len(ix.rootHi6)+len(ix.rootLo6)) +
		128*len(ix.nodes) + 80*len(ix.stops) + 4*len(ix.refs) +
		16*len(ix.leaf4) + 32*len(ix.leaf6) +
		ix.exact4.bytes() + ix.exact6.bytes()
}

// Nodes reports the arena stride count, counting both kinds
func (ix *Index) Nodes() int { return len(ix.nodes) + len(ix.stops) }
