package flatart

import (
	"math/bits"
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/internal/art"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// emptyRootHi and emptyRootLo back families that hold no prefixes, so an
// absent family costs a shared read-only array rather than a length test
// on every lookup - they're allocated during package initialisation to
// keep them out of any caller's memory measurement window
var (
	emptyRootHi *[rootBlock]uint32
	emptyRootLo []uint32
)

// init allocates the shared empty roots once, not per empty family
func init() {
	emptyRootHi = new([rootBlock]uint32)
	emptyRootLo = make([]uint32, rootBlock)
}

// bnode is a build-time stride node
// the maps keep insertion simple, the compiler converts them into the
// arena layout the lookup path reads
type bnode struct {
	pfx      map[uint16]uint32 // ART index -> caller reference
	children map[uint8]*bnode

	count int     // prefixes stored in this subtree
	only  onlyPfx // the single prefix, valid when count == 1
}

// onlyPfx describes the sole prefix of a subtree that can collapse into a
// path-compressed leaf
type onlyPfx struct {
	hi, lo uint64
	bits   uint8
	ref    uint32
}

type fam struct {
	// rootPfx holds prefixes no longer than the root stride, keyed by packed
	// root key and length so a repeated insert replaces rather than duplicates
	rootPfx  map[uint32]uint32
	subtrees map[uint32]*bnode
	count    int
}

// Builder accumulates prefixes and compiles them into an Index
type Builder struct {
	opts Options
	v4   fam
	v6   fam
}

// NewBuilder returns a Builder for the given options
func NewBuilder(opts Options) *Builder {
	return &Builder{
		opts: opts,
		v4:   fam{rootPfx: make(map[uint32]uint32), subtrees: make(map[uint32]*bnode)},
		v6:   fam{rootPfx: make(map[uint32]uint32), subtrees: make(map[uint32]*bnode)},
	}
}

// Insert records prefix against the caller's non-zero reference
// re-inserting a prefix replaces its reference - we report whether the
// prefix was usable
func (b *Builder) Insert(prefix netip.Prefix, ref uint32) bool {
	hi, lo, prefixBits, is4, ok := decompose(prefix)
	if !ok || ref == 0 {
		return false
	}
	f := &b.v6
	if is4 {
		f = &b.v4
	}
	f.count++

	rootKey := uint32(hi >> (64 - rootBits))
	if prefixBits <= rootBits {
		f.rootPfx[packExact(rootKey, prefixBits)] = ref
		return true
	}

	depth := int(prefixBits-rootBits-1) / 8
	remain := prefixBits - rootBits - uint8(8*depth)
	firstByte := rootBits / 8

	bn := f.subtrees[rootKey]
	if bn == nil {
		bn = newBnode()
		f.subtrees[rootKey] = bn
	}
	for d := 0; d < depth; d++ {
		octet := octetAt(hi, lo, firstByte+d)
		child := bn.children[octet]
		if child == nil {
			child = newBnode()
			bn.children[octet] = child
		}
		bn = child
	}
	bn.pfx[uint16(art.PfxToIdx(octetAt(hi, lo, firstByte+depth), remain))] = ref
	return true
}

// newBnode is just the maps, we don't pre-size them
func newBnode() *bnode {
	return &bnode{pfx: make(map[uint16]uint32), children: make(map[uint8]*bnode)}
}

// Build compiles the accumulated prefixes into an immutable Index
// it also returns the reference each assigned value index belongs to, so
// the caller can lay out its value slice in the order the index addresses
// it - element zero is the reserved "no match" index
//
// the index assigns the value order rather than accepting one so that a
// stride's prefixes occupy consecutive indices, that's what lets
// resolution be base+rank with no per-prefix indirection array
func (b *Builder) Build() (*Index, []uint32, error) {
	if b.v4.count+b.v6.count > MaxEntries {
		return nil, nil, ErrTooLarge
	}
	ix := &Index{}
	c := &compiler{ix: ix, opts: b.opts, refOf: make([]uint32, 1, b.v4.count+b.v6.count+2)}

	if err := c.buildFamily(&b.v4, true); err != nil {
		return nil, nil, err
	}
	ix.exact4 = c.takeExact()

	if err := c.buildFamily(&b.v6, false); err != nil {
		return nil, nil, err
	}
	ix.exact6 = c.takeExact()

	ix.values = len(c.refOf)
	return ix, c.refOf, nil
}

type compiler struct {
	ix    *Index
	opts  Options
	refOf []uint32
	exact []uint64
}

// assign allocates the next value index for a caller reference
func (c *compiler) assign(ref uint32) uint32 {
	index := uint32(len(c.refOf))
	c.refOf = append(c.refOf, ref)
	return index
}

// takeExact sorts and hands off the exact-prefix side table for one family
func (c *compiler) takeExact() exactTable {
	if !c.opts.Exact || len(c.exact) == 0 {
		c.exact = nil
		return exactTable{}
	}
	sort.Slice(c.exact, func(i, j int) bool { return c.exact[i] < c.exact[j] })
	t := exactTable{entries: c.exact}
	c.exact = nil
	return t
}

// buildFamily compiles one family's root plus subtrees
// empty family gets the shared empty roots, don't allocate a private copy
func (c *compiler) buildFamily(f *fam, is4 bool) error {
	if f.count == 0 {
		c.setRoot(is4, emptyRootHi, emptyRootLo)
		return nil
	}
	// the root is compiled flat and then split into the two levels the lookup
	// path reads, so the leaf-pushing below stays straightforward
	root := make([]uint32, 1<<rootBits)

	// push the root-stride prefixes in shortest-first order, so a longer
	// prefix overwrites the shorter ones it nests inside
	pushed := make([]uint32, 0, len(f.rootPfx))
	for packed := range f.rootPfx {
		pushed = append(pushed, packed)
	}
	sort.Slice(pushed, func(i, j int) bool {
		if uint8(pushed[i]) != uint8(pushed[j]) {
			return uint8(pushed[i]) < uint8(pushed[j])
		}
		return pushed[i] < pushed[j]
	})
	for _, packed := range pushed {
		key, prefixBits := packed>>8, uint8(packed)
		value := c.assign(f.rootPfx[packed])
		span := uint32(1) << (rootBits - prefixBits)
		for i := key; i < key+span; i++ {
			root[i] = value
		}
		if c.opts.Exact {
			c.exact = append(c.exact, uint64(packed)<<32|uint64(value))
		}
	}

	keys := make([]uint32, 0, len(f.subtrees))
	for key := range f.subtrees {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	firstByte := rootBits / 8
	for _, key := range keys {
		bn := f.subtrees[key]
		pathHi := uint64(key) << (64 - rootBits)
		summarize(bn, firstByte, pathHi, 0)
		ref, err := c.flatten(bn, root[key], firstByte, pathHi, 0, is4)
		if err != nil {
			return err
		}
		root[key] = ref
	}

	hi, lo := splitRoot(root)
	c.setRoot(is4, hi, lo)
	return nil
}

// splitRoot converts the flat root stride into a /8 index over 256-slot blocks
// blocks whose slots are all equal describe a /8 that holds nothing but a
// covering route, and every such /8 with the same value shares one block,
// which is what makes a sparse or IPv6 root cost kilobytes instead of 256 KiB
func splitRoot(root []uint32) (hi *[rootBlock]uint32, lo []uint32) {
	hi = new([rootBlock]uint32)
	lo = make([]uint32, 0, rootBlock)
	uniform := make(map[uint32]uint32, 8)
	for top := 0; top < rootBlock; top++ {
		block := root[top*rootBlock : (top+1)*rootBlock]
		same := true
		for _, slot := range block[1:] {
			if slot != block[0] {
				same = false
				break
			}
		}
		if same {
			if base, ok := uniform[block[0]]; ok {
				hi[top] = base
				continue
			}
			uniform[block[0]] = uint32(len(lo))
		}
		hi[top] = uint32(len(lo))
		lo = append(lo, block...)
	}
	return hi, lo
}

// setRoot writes the split root onto the family the compiler is building
func (c *compiler) setRoot(is4 bool, hi *[rootBlock]uint32, lo []uint32) {
	if is4 {
		c.ix.rootHi4, c.ix.rootLo4 = hi, lo
		return
	}
	c.ix.rootHi6, c.ix.rootLo6 = hi, lo
}

// summarize computes each subtree's prefix count and, for subtrees holding
// exactly one prefix, that prefix's full address
// those subtrees collapse into path-compressed leaves, which is what keeps
// sparse IPv6 tails shallow
func summarize(bn *bnode, byteIndex int, hi, lo uint64) {
	total := len(bn.pfx)
	for octet, child := range bn.children {
		childHi, childLo := withOctet(hi, lo, byteIndex, octet)
		summarize(child, byteIndex+1, childHi, childLo)
		total += child.count
	}
	bn.count = total
	if total != 1 {
		return
	}
	for idx, ref := range bn.pfx {
		octet, pfxLen := art.IdxToPfx(uint(idx))
		keyHi, keyLo := withOctet(hi, lo, byteIndex, octet)
		bn.only = onlyPfx{hi: keyHi, lo: keyLo, bits: uint8(8*byteIndex) + pfxLen, ref: ref}
		return
	}
	for _, child := range bn.children {
		if child.count == 1 {
			bn.only = child.only
			return
		}
	}
}

// staged is the resolution state of a stride before it is committed to
// whichever arena its shape calls for
type staged struct {
	host, short         [4]uint64
	hostBase, shortBase uint32
	hostPre, shortPre   uint32
}

// flatten emits bn into the arenas and returns the tagged reference to it
// inherit is the value index of the shortest-prefix match covering the
// whole subtree, which the stride records at ART index 1 so the lookup
// path never has to remember it
func (c *compiler) flatten(bn *bnode, inherit uint32, byteIndex int, hi, lo uint64, is4 bool) (uint32, error) {
	if bn.count == 1 {
		return c.emitLeaf(bn.only, inherit, is4)
	}

	// prefixes are split by shape: those ending exactly on this stride
	// boundary go to host, the partial-stride ones and the inherited default
	// to short - value indices are assigned in ascending index order within
	// each set, so resolution is base+rank with no indirection array
	var s staged
	hostIdx := make([]uint, 0, len(bn.pfx))
	shortIdx := make([]uint, 0, len(bn.pfx)+1)
	if inherit != 0 {
		shortIdx = append(shortIdx, 1)
	}
	for idx := range bn.pfx {
		if idx >= art.MaxChildren {
			hostIdx = append(hostIdx, uint(idx))
		} else {
			shortIdx = append(shortIdx, uint(idx))
		}
	}
	sort.Slice(hostIdx, func(i, j int) bool { return hostIdx[i] < hostIdx[j] })
	sort.Slice(shortIdx, func(i, j int) bool { return shortIdx[i] < shortIdx[j] })

	for i, idx := range hostIdx {
		s.host[(idx>>6)&3] |= uint64(1) << (idx & 63)
		if value := c.assign(bn.pfx[uint16(idx)]); i == 0 {
			s.hostBase = value
		}
	}
	for i, idx := range shortIdx {
		s.short[(idx>>6)&3] |= uint64(1) << (idx & 63)
		ref := bn.pfx[uint16(idx)]
		if idx == 1 && inherit != 0 {
			ref = c.refOf[inherit]
		}
		if value := c.assign(ref); i == 0 {
			s.shortBase = value
		}
	}
	s.hostPre = packPrefixSums(&s.host)
	s.shortPre = packPrefixSums(&s.short)

	if len(bn.children) == 0 {
		return c.emitStop(&s)
	}
	return c.emitNode(bn, &s, byteIndex, hi, lo, is4)
}

// emitStop parks a childless stride in the stop arena
func (c *compiler) emitStop(s *staged) (uint32, error) {
	index := uint32(len(c.ix.stops))
	if index > refMask {
		return 0, ErrTooLarge
	}
	c.ix.stops = append(c.ix.stops, stop{
		hostBase:  s.hostBase,
		shortBase: s.shortBase,
		hostPre:   s.hostPre,
		shortPre:  s.shortPre,
		host:      s.host,
		short:     s.short,
	})
	return tagStop | index, nil
}

// emitNode parks a stride with children - we resolve child inheritance
// before copying into the arena, because the arena may move while the
// children are emitted
func (c *compiler) emitNode(bn *bnode, s *staged, byteIndex int, hi, lo uint64, is4 bool) (uint32, error) {
	octets := make([]uint8, 0, len(bn.children))
	for octet := range bn.children {
		octets = append(octets, octet)
	}
	sort.Slice(octets, func(i, j int) bool { return octets[i] < octets[j] })

	var pending node
	pending.host, pending.short = s.host, s.short
	pending.groups[0].aux = s.hostBase
	pending.groups[1].aux = s.shortBase
	pending.groups[2].aux = s.hostPre
	pending.groups[3].aux = s.shortPre

	// child inheritance is read before the stride is copied into the arena,
	// because the arena may move while the children are emitted
	childInherit := make([]uint32, len(octets))
	for i, octet := range octets {
		childInherit[i] = resolveNode(&pending, octet)
	}

	nodeIndex := uint32(len(c.ix.nodes))
	if nodeIndex > refMask {
		return 0, ErrTooLarge
	}
	c.ix.nodes = append(c.ix.nodes, pending)

	refBase := uint32(len(c.ix.refs))
	if uint64(refBase)+uint64(len(octets)) > refMask {
		return 0, ErrTooLarge
	}
	for range octets {
		c.ix.refs = append(c.ix.refs, 0)
	}
	for i, octet := range octets {
		childHi, childLo := withOctet(hi, lo, byteIndex, octet)
		ref, err := c.flatten(bn.children[octet], childInherit[i], byteIndex+1, childHi, childLo, is4)
		if err != nil {
			return 0, err
		}
		c.ix.refs[refBase+uint32(i)] = ref
	}

	// taken after the recursion because nested emits may have grown the arena
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

// emitLeaf is the path-compressed single-prefix case
func (c *compiler) emitLeaf(only onlyPfx, inherit uint32, is4 bool) (uint32, error) {
	value := c.assign(only.ref)
	if is4 {
		index := uint32(len(c.ix.leaf4))
		if index > refMask {
			return 0, ErrTooLarge
		}
		c.ix.leaf4 = append(c.ix.leaf4, leaf4{
			key:     uint32(only.hi >> 32),
			value:   value,
			inherit: inherit,
			bits:    only.bits,
		})
		return tagLeaf | index, nil
	}
	index := uint32(len(c.ix.leaf6))
	if index > refMask {
		return 0, ErrTooLarge
	}
	c.ix.leaf6 = append(c.ix.leaf6, leaf6{
		hi:      only.hi,
		lo:      only.lo,
		value:   value,
		inherit: inherit,
		bits:    only.bits,
	})
	return tagLeaf | index, nil
}

// decompose normalises a prefix into masked address words plus its length
// IPv4 is held in the top 32 bits of hi so that the root stride, octet
// extraction and leaf comparison are shared with IPv6
func decompose(prefix netip.Prefix) (hi, lo uint64, prefixBits uint8, is4 bool, ok bool) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return 0, 0, 0, false, false
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	prefixBits = uint8(prefix.Bits())
	if addr.Is4In6() {
		if prefixBits < 96 {
			return 0, 0, 0, false, false
		}
		addr = addr.Unmap()
		prefixBits -= 96
	}
	if addr.Is4() {
		return uint64(prefixentry.Addr4(addr)) << 32, 0, prefixBits, true, true
	}
	hi, lo = prefixentry.Addr6(addr)
	return hi, lo, prefixBits, false, true
}

// octetAt pulls one byte out of the 128-bit address, hi then lo
func octetAt(hi, lo uint64, byteIndex int) uint8 {
	if byteIndex < 8 {
		return uint8(hi >> (56 - 8*byteIndex))
	}
	return uint8(lo >> (56 - 8*(byteIndex-8)))
}

// withOctet plants one octet into the address words at byteIndex
func withOctet(hi, lo uint64, byteIndex int, octet uint8) (uint64, uint64) {
	shift := uint(56 - 8*(byteIndex&7))
	if byteIndex < 8 {
		return hi | uint64(octet)<<shift, lo
	}
	return hi, lo | uint64(octet)<<shift
}
