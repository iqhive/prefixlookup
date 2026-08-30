package flatart

import (
	"math/bits"
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/art"
)

// exactTable answers exact-prefix queries for prefixes no longer than the
// root stride
// those prefixes are pushed into the root, where a stored prefix and a
// covering prefix are indistinguishable, so they need a side table
//
// it's a sorted array searched by bisection rather than a hash table: the
// path is cold, and an array costs exactly eight bytes per prefix where an
// open-addressing table would cost sixteen after load-factor headroom
type exactTable struct {
	// entries pack the root key and prefix length into the high 32 bits and
	// the value index into the low 32, so ordering by key falls out of
	// ordering the words
	entries []uint64
}

// packExact combines a root key with a prefix length
func packExact(key uint32, prefixBits uint8) uint32 { return key<<8 | uint32(prefixBits) }

// lookup is a bisection on the packed key - written out so we don't pay
// sort.Search's closure on a cold path that's still not free
func (t *exactTable) lookup(packed uint32) uint32 {
	entries := t.entries
	target := uint64(packed) << 32
	low, high := 0, len(entries)
	for low < high {
		mid := int(uint(low+high) >> 1)
		if entries[mid] < target {
			low = mid + 1
		} else {
			high = mid
		}
	}
	if low < len(entries) && entries[low]>>32 == uint64(packed) {
		return uint32(entries[low])
	}
	return 0
}

// bytes is eight per exact-root prefix, nothing else
func (t *exactTable) bytes() int { return 8 * len(t.entries) }

// Exact returns the value index stored for exactly this prefix, or zero
// requires Options.Exact
//
// for prefixes longer than the root stride this is a plain trie descent,
// so it costs the same handful of loads as a lookup - the comparable
// operation on the existing implementations hashes a netip.Prefix, which
// is a 24-byte address plus a length, and that hash dominates their
// traversal cost
func (ix *Index) Exact(prefix netip.Prefix) uint32 {
	hi, lo, prefixBits, is4, ok := decompose(prefix)
	if !ok {
		return 0
	}

	rootHi, rootLo, exact := ix.rootHi6, ix.rootLo6, &ix.exact6
	if is4 {
		rootHi, rootLo, exact = ix.rootHi4, ix.rootLo4, &ix.exact4
	}
	rootKey := uint32(hi >> (64 - rootBits))
	if prefixBits <= rootBits {
		return exact.lookup(packExact(rootKey, prefixBits))
	}

	slot := rootLo[rootHi[rootKey>>8]+(rootKey&0xff)]
	if slot < tagNode {
		return 0
	}

	depth := int(prefixBits-rootBits-1) / 8
	remain := prefixBits - rootBits - uint8(8*depth)
	firstByte := rootBits / 8

	for d := 0; d <= depth; d++ {
		octet := octetAt(hi, lo, firstByte+d)
		if slot >= tagStop {
			if d != depth {
				return 0
			}
			s := &ix.stops[slot&refMask]
			return exactAt(&s.host, &s.short, s.hostBase, s.shortBase, s.hostPre, s.shortPre, octet, remain)
		}
		if slot >= tagLeaf {
			if is4 {
				lf := &ix.leaf4[slot&refMask]
				if lf.bits == prefixBits && lf.key == uint32(hi>>32) {
					return lf.value
				}
				return 0
			}
			lf := &ix.leaf6[slot&refMask]
			if lf.bits == prefixBits && lf.hi == hi && lf.lo == lo {
				return lf.value
			}
			return 0
		}
		n := &ix.nodes[slot&refMask]
		if d == depth {
			return exactAt(&n.host, &n.short, n.groups[0].aux, n.groups[1].aux,
				n.groups[2].aux, n.groups[3].aux, octet, remain)
		}
		g := &n.groups[uint(octet)>>6]
		bit := uint64(1) << (uint(octet) & 63)
		if g.mask&bit == 0 {
			return 0
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
	}
	return 0
}

// exactAt tests one ART index of a stride's prefix sets
// remain==8 is the host set, anything shorter is short
func exactAt(host, short *[4]uint64, hostBase, shortBase, hostPre, shortPre uint32, octet, remain uint8) uint32 {
	if remain == 8 {
		o := uint(octet)
		if host[o>>6]>>(o&63)&1 == 0 {
			return 0
		}
		return hostBase + rankAt(host, hostPre, o>>6, o&63)
	}
	idx := art.PfxToIdx(octet, remain)
	if short[(idx>>6)&3]>>(idx&63)&1 == 0 {
		return 0
	}
	return shortBase + rankAt(short, shortPre, (idx>>6)&3, idx&63)
}
