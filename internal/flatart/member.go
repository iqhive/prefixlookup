package flatart

import (
	"math/bits"
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// MemberIndex is the membership-only form of Index
// answering "does anything cover this address" is a strictly weaker
// question than longest-prefix match, and this layout spends nothing on
// the difference
//
// a value index has to identify which prefix won, so Index keeps two
// prefix sets per stride plus four words of rank metadata, and resolves
// by intersecting against a cover table - membership only has to know that
// something won, so a stride here keeps one 256-bit mask in which every
// octet covered by any prefix stored at or above it is already set
// resolution is one word load and one bit test, and a childless stride is
// 32 bytes rather than 80
//
// precomputing coverage as bits is affordable in a way that precomputing
// it as values is not - a prefix of length L within a stride covers
// 2^(8-L) octets - spreading a value into each of them costs four bytes
// apiece and, under a default route, would fill every stride with 256
// copies - spreading a single bit costs nothing beyond the mask that is
// already there
type MemberIndex struct {
	rootHi4 *[rootBlock]uint32
	rootLo4 []uint32
	rootHi6 *[rootBlock]uint32
	rootLo6 []uint32

	nodes []memberNode
	stops [][4]uint64
	refs  []uint32

	leaf4 []memberLeaf4
	leaf6 []memberLeaf6
}

// memberNode is a stride with children: the child block followed by the
// coverage mask
type memberNode struct {
	groups [4]group
	cover  [4]uint64
}

type memberLeaf4 struct {
	key  uint32
	bits uint8
	_    [3]byte
}

type memberLeaf6 struct {
	hi, lo uint64
	bits   uint8
	_      [7]byte
}

// Contains reports whether any stored prefix covers addr
// 4-in-6 is treated as v4 after Unmap, zoned addrs are a miss
func (ix *MemberIndex) Contains(addr netip.Addr) bool {
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
// one bit test per stride, no rank
func (ix *MemberIndex) Contains4(key uint32) bool {
	slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
	if slot < tagNode {
		return slot != 0
	}
	octet := uint(uint8(key >> 8))
	if slot >= tagStop {
		return covered(&ix.stops[slot&refMask], octet)
	}
	if slot < tagLeaf {
		n := &ix.nodes[slot&refMask]
		g := &n.groups[(octet>>6)&3]
		bit := uint64(1) << (octet & 63)
		if g.mask&bit == 0 {
			return covered(&n.cover, octet)
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
		last := uint(uint8(key))
		if slot >= tagStop {
			return covered(&ix.stops[slot&refMask], last)
		}
		if slot < tagLeaf {
			return covered(&ix.nodes[slot&refMask].cover, last)
		}
	}
	lf := &ix.leaf4[slot&refMask]
	return (key^lf.key)>>(32-lf.bits) == 0
}

// Contains6 is the decoded IPv6 membership path
func (ix *MemberIndex) Contains6(hi, lo uint64) bool {
	slot := ix.rootLo6[ix.rootHi6[hi>>56]+uint32(hi>>48&0xff)]
	word := hi
	for byteIndex := rootBits / 8; byteIndex < 16; byteIndex++ {
		if byteIndex == 8 {
			word = lo
		}
		octet := uint(uint8(word >> (56 - 8*(byteIndex&7))))
		if slot >= tagStop {
			return covered(&ix.stops[slot&refMask], octet)
		}
		if slot < tagNode {
			return slot != 0
		}
		if slot >= tagLeaf {
			lf := &ix.leaf6[slot&refMask]
			return lf.covers(hi, lo)
		}
		n := &ix.nodes[slot&refMask]
		g := &n.groups[(octet>>6)&3]
		bit := uint64(1) << (octet & 63)
		if g.mask&bit == 0 {
			return covered(&n.cover, octet)
		}
		slot = ix.refs[g.slot+uint32(bits.OnesCount64(g.mask&(bit-1)))]
	}
	return false
}

// covered is one bit out of the 256-bit cover mask
func covered(cover *[4]uint64, octet uint) bool {
	return cover[(octet>>6)&3]>>(octet&63)&1 != 0
}

// covers is the IPv6 leaf match for membership - no inherit to consult
func (lf *memberLeaf6) covers(hi, lo uint64) bool {
	if lf.bits <= 64 {
		return (hi^lf.hi)>>(64-lf.bits) == 0
	}
	return hi == lf.hi && (lo^lf.lo)>>(128-lf.bits) == 0
}

// Bytes reports the retained size of the index
func (ix *MemberIndex) Bytes() int {
	return 4*(rootBlock+len(ix.rootLo4)+rootBlock+len(ix.rootLo6)) +
		96*len(ix.nodes) + 32*len(ix.stops) + 4*len(ix.refs) +
		8*len(ix.leaf4) + 24*len(ix.leaf6)
}

// Strides reports the arena stride count, counting both kinds
func (ix *MemberIndex) Strides() int { return len(ix.nodes) + len(ix.stops) }

// BuildMember compiles the accumulated prefixes into a membership index
// the references passed to Insert are ignored
func (b *Builder) BuildMember() (*MemberIndex, error) {
	ix := &MemberIndex{}
	c := &memberCompiler{ix: ix}
	if err := c.buildFamily(&b.v4, true); err != nil {
		return nil, err
	}
	if err := c.buildFamily(&b.v6, false); err != nil {
		return nil, err
	}
	return ix, nil
}

type memberCompiler struct {
	ix *MemberIndex
}

// buildFamily compiles one family's membership root
// a root slot already covered by a shorter prefix never compiles its subtree
func (c *memberCompiler) buildFamily(f *fam, is4 bool) error {
	if f.count == 0 {
		c.setRoot(is4, emptyRootHi, emptyRootLo)
		return nil
	}
	root := make([]uint32, 1<<rootBits)
	for packed := range f.rootPfx {
		key, prefixBits := packed>>8, uint8(packed)
		span := uint32(1) << (rootBits - prefixBits)
		for i := key; i < key+span; i++ {
			root[i] = 1
		}
	}

	firstByte := rootBits / 8
	for key, bn := range f.subtrees {
		// coverage is monotone: if a shorter prefix already covers this whole
		// root slot then nothing below it can change any answer, so the subtree
		// is never compiled
		if root[key] != 0 {
			continue
		}
		pathHi := uint64(key) << (64 - rootBits)
		summarize(bn, firstByte, pathHi, 0)
		ref, err := c.flatten(bn, firstByte, pathHi, 0, is4)
		if err != nil {
			return err
		}
		root[key] = ref
	}

	hi, lo := splitRoot(root)
	c.setRoot(is4, hi, lo)
	return nil
}

// setRoot writes the split root onto this family's MemberIndex
func (c *memberCompiler) setRoot(is4 bool, hi *[rootBlock]uint32, lo []uint32) {
	if is4 {
		c.ix.rootHi4, c.ix.rootLo4 = hi, lo
		return
	}
	c.ix.rootHi6, c.ix.rootLo6 = hi, lo
}

// flatten emits bn as a membership stride
// only ever called for a path that nothing above covers, because a covered
// path is replaced by a single terminal slot rather than a subtree
func (c *memberCompiler) flatten(bn *bnode, byteIndex int, hi, lo uint64, is4 bool) (uint32, error) {
	if bn.count == 1 {
		return c.emitLeaf(bn.only, is4)
	}

	var cover [4]uint64
	for idx := range bn.pfx {
		first, last := idxOctetRange(uint(idx))
		setRange(&cover, first, last)
	}

	if len(bn.children) == 0 {
		index := uint32(len(c.ix.stops))
		if index > refMask {
			return 0, ErrTooLarge
		}
		c.ix.stops = append(c.ix.stops, cover)
		return tagStop | index, nil
	}

	octets := make([]uint8, 0, len(bn.children))
	for octet := range bn.children {
		octets = append(octets, octet)
	}
	sort.Slice(octets, func(i, j int) bool { return octets[i] < octets[j] })

	nodeIndex := uint32(len(c.ix.nodes))
	if nodeIndex > refMask {
		return 0, ErrTooLarge
	}
	c.ix.nodes = append(c.ix.nodes, memberNode{cover: cover})

	refBase := uint32(len(c.ix.refs))
	if uint64(refBase)+uint64(len(octets)) > refMask {
		return 0, ErrTooLarge
	}
	for range octets {
		c.ix.refs = append(c.ix.refs, 0)
	}
	for i, octet := range octets {
		// an octet this stride already covers needs no subtree of its own
		if covered(&cover, uint(octet)) {
			c.ix.refs[refBase+uint32(i)] = 1
			continue
		}
		childHi, childLo := withOctet(hi, lo, byteIndex, octet)
		ref, err := c.flatten(bn.children[octet], byteIndex+1, childHi, childLo, is4)
		if err != nil {
			return 0, err
		}
		c.ix.refs[refBase+uint32(i)] = ref
	}

	n := &c.ix.nodes[nodeIndex]
	below := uint32(0)
	for g := 0; g < 4; g++ {
		var mask uint64
		for _, octet := range octets {
			if int(octet>>6) == g {
				mask |= uint64(1) << (octet & 63)
			}
		}
		n.groups[g].mask = mask
		n.groups[g].slot = refBase + below
		below += uint32(bits.OnesCount64(mask))
	}
	return tagNode | nodeIndex, nil
}

// emitLeaf is the path-compressed single-prefix case, no value to store
func (c *memberCompiler) emitLeaf(only onlyPfx, is4 bool) (uint32, error) {
	if is4 {
		index := uint32(len(c.ix.leaf4))
		if index > refMask {
			return 0, ErrTooLarge
		}
		c.ix.leaf4 = append(c.ix.leaf4, memberLeaf4{key: uint32(only.hi >> 32), bits: only.bits})
		return tagLeaf | index, nil
	}
	index := uint32(len(c.ix.leaf6))
	if index > refMask {
		return 0, ErrTooLarge
	}
	c.ix.leaf6 = append(c.ix.leaf6, memberLeaf6{hi: only.hi, lo: only.lo, bits: only.bits})
	return tagLeaf | index, nil
}

// idxOctetRange returns the inclusive octet range an ART index covers
func idxOctetRange(idx uint) (first, last uint) {
	length := uint(bits.Len(idx)) - 1
	octet := (idx & (1<<length - 1)) << (8 - length)
	return octet, octet | 0xff>>length
}

// setRange paints bits first..last inclusive into the 256-bit cover mask
func setRange(cover *[4]uint64, first, last uint) {
	firstWord, lastWord := first>>6, last>>6
	for w := firstWord; w <= lastWord && w < 4; w++ {
		low := uint(0)
		if w == firstWord {
			low = first & 63
		}
		high := uint(63)
		if w == lastWord {
			high = last & 63
		}
		cover[w] |= ^uint64(0) << low & (^uint64(0) >> (63 - high))
	}
}
