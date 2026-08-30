package flatart

import (
	"math/bits"
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/art"
)

// All visits every stored prefix with its value index
// iteration stops early if yield returns false - order is unspecified
//
// enumeration exists so a managed table can reconstruct its catalogue from
// the index when a structural change forces a rebuild, rather than retaining
// a parallel map[netip.Prefix]V - that map is the single largest component
// of the existing managed tables' footprint
//
// prefixes no longer than the root stride live in the exact-match side
// table, so All requires Options.Exact to report them
func (ix *Index) All(yield func(netip.Prefix, uint32) bool) {
	if !ix.allFamily(ix.rootHi4, ix.rootLo4, &ix.exact4, true, yield) {
		return
	}
	ix.allFamily(ix.rootHi6, ix.rootLo6, &ix.exact6, false, yield)
}

// allFamily walks one family's exact table then its root /8s
func (ix *Index) allFamily(rootHi *[rootBlock]uint32, rootLo []uint32, exact *exactTable, is4 bool, yield func(netip.Prefix, uint32) bool) bool {
	for _, entry := range exact.entries {
		packed, value := uint32(entry>>32), uint32(entry)
		key, prefixBits := packed>>8, uint8(packed)
		if !yield(rebuild(uint64(key)<<(64-rootBits), 0, prefixBits, is4), value) {
			return false
		}
	}
	// blocks are shared between /8s that hold nothing but a covering route, so
	// enumeration walks the /8 index rather than the blocks - a shared block
	// never contains a subtree reference
	for top, base := range rootHi {
		for offset := uint32(0); offset < rootBlock; offset++ {
			slot := rootLo[base+offset]
			if slot < tagNode {
				continue
			}
			key := uint64(top)<<8 | uint64(offset)
			if !ix.allRef(slot, rootBits/8, key<<(64-rootBits), 0, is4, yield) {
				return false
			}
		}
	}
	return true
}

// allRef dispatches on the arena tag and walks children if it's a node
func (ix *Index) allRef(slot uint32, byteIndex int, hi, lo uint64, is4 bool, yield func(netip.Prefix, uint32) bool) bool {
	if slot >= tagStop {
		s := &ix.stops[slot&refMask]
		return allSets(&s.host, &s.short, s.hostBase, s.shortBase, byteIndex, hi, lo, is4, yield)
	}
	if slot >= tagLeaf {
		if is4 {
			lf := &ix.leaf4[slot&refMask]
			return yield(rebuild(uint64(lf.key)<<32, 0, lf.bits, true), lf.value)
		}
		lf := &ix.leaf6[slot&refMask]
		return yield(rebuild(lf.hi, lf.lo, lf.bits, false), lf.value)
	}

	n := &ix.nodes[slot&refMask]
	if !allSets(&n.host, &n.short, n.groups[0].aux, n.groups[1].aux, byteIndex, hi, lo, is4, yield) {
		return false
	}
	for g := 0; g < 4; g++ {
		mask := n.groups[g].mask
		for mask != 0 {
			offset := bits.TrailingZeros64(mask)
			octet := uint8(g*64 + offset)
			ref := ix.refs[n.groups[g].slot+uint32(bits.OnesCount64(n.groups[g].mask&(uint64(1)<<offset-1)))]
			childHi, childLo := withOctet(hi, lo, byteIndex, octet)
			if !ix.allRef(ref, byteIndex+1, childHi, childLo, is4, yield) {
				return false
			}
			mask &= mask - 1
		}
	}
	return true
}

// allSets yields the prefixes of one stride
// each set holds consecutive value indices in ascending index order, so
// the rank of the i-th set bit is i
func allSets(host, short *[4]uint64, hostBase, shortBase uint32, byteIndex int, hi, lo uint64, is4 bool, yield func(netip.Prefix, uint32) bool) bool {
	position := uint32(0)
	for word := 0; word < 4; word++ {
		mask := host[word]
		for mask != 0 {
			octet := uint8(word*64 + bits.TrailingZeros64(mask))
			keyHi, keyLo := withOctet(hi, lo, byteIndex, octet)
			if !yield(rebuild(keyHi, keyLo, uint8(8*byteIndex+8), is4), hostBase+position) {
				return false
			}
			position++
			mask &= mask - 1
		}
	}
	position = 0
	for word := 0; word < 4; word++ {
		mask := short[word]
		for mask != 0 {
			idx := uint(word*64 + bits.TrailingZeros64(mask))
			mask &= mask - 1
			// index 1 is the inherited default, not a stored prefix, but it
			// still occupies a value index
			if idx == 1 {
				position++
				continue
			}
			octet, pfxLen := art.IdxToPfx(idx)
			keyHi, keyLo := withOctet(hi, lo, byteIndex, octet)
			if !yield(rebuild(keyHi, keyLo, uint8(8*byteIndex)+pfxLen, is4), shortBase+position) {
				return false
			}
			position++
		}
	}
	return true
}

// rebuild turns address words and a length back into a netip.Prefix
func rebuild(hi, lo uint64, prefixBits uint8, is4 bool) netip.Prefix {
	if is4 {
		key := uint32(hi >> 32)
		addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
		return netip.PrefixFrom(addr, int(prefixBits))
	}
	var octets [16]byte
	for i := 0; i < 8; i++ {
		octets[i] = byte(hi >> (56 - 8*i))
		octets[8+i] = byte(lo >> (56 - 8*i))
	}
	return netip.PrefixFrom(netip.AddrFrom16(octets), int(prefixBits))
}
