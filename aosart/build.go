package aosart

import (
	"math/bits"
	"net/netip"
)

// buildNode is the mutable form of a node, used only while compiling
// bitsets are fixed [4]uint64, items grow as we insert. freeze() writes these
// into the AoS node array and precomputes the per-word ranks
type buildNode struct {
	pfx      [4]uint64
	kids     [4]uint64
	pfxItems []uint32
	kidItems []uint32
}

// buildTree is the mutable trie we insert into, one family
// nodes[0] is the root; leaves grow as we path-compress. depth is 4 or 16
type buildTree struct {
	nodes  []buildNode
	leaves []leaf
	depth  int
}

// newBuildTree allocates a tree with a single empty root at the given stride
// depth
// one-element nodes slice so insert can start at node 0 without a nil check
func newBuildTree(depth int) *buildTree {
	return &buildTree{nodes: make([]buildNode, 1), depth: depth}
}

// newNode appends an empty node and returns its index
// we never recycle slots - freeze walks the whole slice once
func (b *buildTree) newNode() uint32 {
	b.nodes = append(b.nodes, buildNode{})
	return uint32(len(b.nodes) - 1)
}

// insertAt splices value into items at at, shifting the tail up
// append a zero then copy the tail forward - the usual Go insert
func insertAt[T any](items []T, at int, value T) []T {
	var zero T
	items = append(items, zero)
	copy(items[at+1:], items[at:])
	items[at] = value
	return items
}

// buildRank counts the set bits below i. only the builder uses it; the frozen
// form has the counts precomputed
// same word-then-masked-popcount as soaart's rank, but against a *[4]uint64
func buildRank(words *[4]uint64, i uint) int {
	word := i >> 6
	total := 0
	for k := uint(0); k < word; k++ {
		total += bits.OnesCount64(words[k])
	}
	return total + bits.OnesCount64(words[word]&(1<<(i&63)-1))
}

// setPfx stores a route id at an ART prefix index, overwriting any existing one
// buildRank tells us the compressed slot; if the bit is already set we
// overwrite, otherwise we set the bit and splice the id in
func (b *buildTree) setPfx(node uint32, idx uint, id uint32) {
	n := &b.nodes[node]
	at := buildRank(&n.pfx, idx)
	if testBit(&n.pfx, idx) {
		n.pfxItems[at] = id
		return
	}
	n.pfx[idx>>6] |= 1 << (idx & 63)
	n.pfxItems = insertAt(n.pfxItems, at, id)
}

// kid returns the tagged child at octet, if any
// test the kid bitset, buildRank to the compressed slot
func (b *buildTree) kid(node uint32, octet uint8) (uint32, bool) {
	n := &b.nodes[node]
	if !testBit(&n.kids, uint(octet)) {
		return 0, false
	}
	return n.kidItems[buildRank(&n.kids, uint(octet))], true
}

// setKid stores a tagged child at octet, overwriting or inserting
// same overwrite-or-splice as setPfx, against the kid bitset
func (b *buildTree) setKid(node uint32, octet uint8, ref uint32) {
	n := &b.nodes[node]
	at := buildRank(&n.kids, uint(octet))
	if testBit(&n.kids, uint(octet)) {
		n.kidItems[at] = ref
		return
	}
	n.kids[uint(octet)>>6] |= 1 << (uint(octet) & 63)
	n.kidItems = insertAt(n.kidItems, at, ref)
}

// insert places a prefix, starting the descent at node/level. reinsertion
// after a split re-enters here, which is why the starting point is a parameter
//
// same algorithm as soaart: loop for the new prefix, recurse only when we
// split a leaf. remainder 0 at the prefix's stride is ART index 1. a prefix
// that fills a whole child slot is a fringe. empty slot: fringe or a new
// leaf. existing node: keep descending. existing fringe of the same prefix:
// overwrite. shorter fringe: split into a node holding it as index 1
// same-prefix leaf: overwrite id. different leaf: split, reinsert old, continue
func (b *buildTree) insert(node uint32, level int, high, low uint64, bits uint8, id uint32) {
	depth := int(bits) / 8
	remainder := bits % 8
	for {
		if level == depth {
			// a prefix ending on a stride boundary is this node's own
			// zero-length entry; otherwise it is indexed by octet and length
			if remainder == 0 {
				b.setPfx(node, 1, id)
				return
			}
			b.setPfx(node, pfxIndex(octetAt(high, low, level), remainder), id)
			return
		}
		octet := octetAt(high, low, level)
		// a prefix that fills a whole child slot is stored as a fringe there,
		// which costs one child entry instead of a node
		fringePosition := remainder == 0 && level == depth-1

		ref, exists := b.kid(node, octet)
		if !exists {
			if fringePosition {
				b.setKid(node, octet, refFringe|id)
			} else {
				b.setKid(node, octet, refLeaf|uint32(len(b.leaves)))
				b.leaves = append(b.leaves, leaf{high: high, low: low, bits: bits, id: id})
			}
			return
		}

		switch ref & tagMask {
		case refNode:
			node = ref & payloadMask
			level++

		case refFringe:
			if fringePosition {
				b.setKid(node, octet, refFringe|id) // same prefix, new value
				return
			}
			// something longer needs to branch below: turn the fringe into a
			// node holding it as that node's zero-length prefix
			child := b.newNode()
			b.setKid(node, octet, refNode|child)
			b.setPfx(child, 1, ref&payloadMask)
			node = child
			level++

		default: // refLeaf
			existing := b.leaves[ref&payloadMask]
			if existing.bits == bits && existing.high == high && existing.low == low {
				b.leaves[ref&payloadMask].id = id
				return
			}
			child := b.newNode()
			b.setKid(node, octet, refNode|child)
			b.insert(child, level+1, existing.high, existing.low, existing.bits, existing.id)
			node = child
			level++
		}
	}
}

// freeze flattens the mutable tree into the interleaved node array the lookup
// path reads, computing each node's per-word ranks so that locating an item
// needs no loop
//
// we size the compressed item runs, then for each node copy bitsets, record
// bases, and fill pfxRank/kidRank as the running popcount of preceding words
// empty (no prefixes, no kids) sets nodes to nil so lookup is a length check
func (b *buildTree) freeze() tree {
	count := len(b.nodes)
	t := tree{
		nodes:  make([]node, count),
		leaves: b.leaves,
		depth:  b.depth,
	}
	pfxTotal, kidTotal := 0, 0
	for i := range b.nodes {
		pfxTotal += len(b.nodes[i].pfxItems)
		kidTotal += len(b.nodes[i].kidItems)
	}
	t.pfxItems = make([]uint32, 0, pfxTotal)
	t.kidItems = make([]uint32, 0, kidTotal)
	for i := range b.nodes {
		source := &b.nodes[i]
		target := &t.nodes[i]
		target.pfx = source.pfx
		target.kids = source.kids
		target.pfxBase = uint32(len(t.pfxItems))
		target.kidBase = uint32(len(t.kidItems))
		pfxRunning, kidRunning := 0, 0
		for word := 0; word < 4; word++ {
			target.pfxRank[word] = uint16(pfxRunning)
			target.kidRank[word] = uint16(kidRunning)
			pfxRunning += bits.OnesCount64(source.pfx[word])
			kidRunning += bits.OnesCount64(source.kids[word])
		}
		t.pfxItems = append(t.pfxItems, source.pfxItems...)
		t.kidItems = append(t.kidItems, source.kidItems...)
	}
	if pfxTotal == 0 && kidTotal == 0 {
		t.nodes = nil
	}
	return t
}

// Builder accumulates prefixes and compiles them into an Index
// ids dedups for Add only. AddKey4 and AddKey6 skip it, so rebuilding from an
// already-deduplicated key list allocates no map at all
type Builder struct {
	v4       *buildTree
	v6       *buildTree
	prefixes []netip.Prefix
	nextID   uint32
	// ids deduplicates for Add only. AddKey4 and AddKey6 skip it, so rebuilding
	// from an already-deduplicated key list allocates no map at all
	ids map[netip.Prefix]uint32
}

// AddKey4 records an already-masked IPv4 prefix and returns its route id
// no dedup, no error - the packed-slice rebuild path already made keys unique
// we just bump nextID and insert. key is the 32-bit addr, we shift it into
// high the same way Lookup does
func (b *Builder) AddKey4(key uint32, bits uint8) uint32 {
	b.nextID++
	b.v4.insert(0, 0, uint64(key)<<32, 0, bits, b.nextID)
	return b.nextID
}

// AddKey6 is the IPv6 equivalent
// same as AddKey4: no map, no canonicalise, just insert into the v6 tree
func (b *Builder) AddKey6(high, low uint64, bits uint8) uint32 {
	b.nextID++
	b.v6.insert(0, 0, high, low, bits, b.nextID)
	return b.nextID
}

// NewBuilder returns an empty Builder
// v4 depth 4, v6 depth 16. ids is left nil - Add lazily allocates it, AddKey*
// never does
func NewBuilder() *Builder {
	return &Builder{v4: newBuildTree(4), v6: newBuildTree(16)}
}

// Add records a prefix and returns its route id. adding the same prefix twice
// returns the same id
//
// decompose to a canonical key, lazy-init the ids map, reject if we'd overflow
// the 30-bit payload, then insert into the matching family's build tree
func (b *Builder) Add(prefix netip.Prefix) (uint32, error) {
	canonical, high, low, bits, is4, ok := decompose(prefix)
	if !ok {
		return 0, ErrBadPrefix
	}
	if b.ids == nil {
		b.ids = make(map[netip.Prefix]uint32)
	}
	if id, exists := b.ids[canonical]; exists {
		return id, nil
	}
	if b.nextID >= maxPayload-1 {
		return 0, ErrTooManyRoutes
	}
	b.nextID++
	id := b.nextID
	b.ids[canonical] = id
	b.prefixes = append(b.prefixes, canonical)
	if is4 {
		b.v4.insert(0, 0, high, low, bits, id)
	} else {
		b.v6.insert(0, 0, high, low, bits, id)
	}
	return id, nil
}

// Routes returns the number of distinct prefixes added
// nextID is the last id we handed out, and id 0 isn't a route
func (b *Builder) Routes() int { return int(b.nextID) }

// Prefix returns the prefix assigned the given route id
// id 0 or past the slice is the zero Prefix - AddKey* never fill prefixes, so
// this is only meaningful after Add
func (b *Builder) Prefix(id uint32) netip.Prefix {
	if id == 0 || int(id) > len(b.prefixes) {
		return netip.Prefix{}
	}
	return b.prefixes[id-1]
}

// Build compiles the accumulated prefixes into an immutable Index
// freeze both families; routes is nextID so Index.Routes matches Add count
func (b *Builder) Build() *Index {
	return &Index{v4: b.v4.freeze(), v6: b.v6.freeze(), routes: int(b.nextID)}
}

// decomposeKey validates a prefix and returns its masked key. it does not
// build a canonical netip.Prefix, because constructing one costs an AddrFrom4
// or AddrFrom16 that the lookup and traversal paths never read
//
// invalid / zoned out. 4in6 needs length >= 96 then we Unmap and subtract 96
// so it becomes a v4 prefix. v4 length > 32 or v6 > 128 is also out. we mask
// the host bits so two writings of the same prefix compare equal in the
// packed slices
func decomposeKey(prefix netip.Prefix) (high, low uint64, bits uint8, is4, ok bool) {
	if !prefix.IsValid() {
		return 0, 0, 0, false, false
	}
	addr := prefix.Addr()
	length := prefix.Bits()
	if addr.Is4In6() {
		if length < 96 {
			return 0, 0, 0, false, false
		}
		addr = addr.Unmap()
		length -= 96
	}
	if addr.Zone() != "" {
		return 0, 0, 0, false, false
	}
	if addr.Is4() {
		if length > 32 {
			return 0, 0, 0, false, false
		}
		key := be32(addr.As4())
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		return uint64(key&mask) << 32, 0, uint8(length), true, true
	}
	if length > 128 {
		return 0, 0, 0, false, false
	}
	high, low = words16(addr.As16())
	high, low = maskKey(high, low, length)
	return high, low, uint8(length), false, true
}

// decompose additionally returns the canonical prefix, which Add needs as a
// map key
//
// same validation as decomposeKey, then we actually construct the masked
// netip.Prefix via addrOf. that's the expensive bit AddKey* skip
func decompose(prefix netip.Prefix) (canonical netip.Prefix, high, low uint64, bits uint8, is4, ok bool) {
	if !prefix.IsValid() {
		return canonical, 0, 0, 0, false, false
	}
	addr := prefix.Addr()
	length := prefix.Bits()
	if addr.Is4In6() {
		if length < 96 {
			return canonical, 0, 0, 0, false, false
		}
		addr = addr.Unmap()
		length -= 96
	}
	if addr.Zone() != "" {
		return canonical, 0, 0, 0, false, false
	}
	if addr.Is4() {
		if length > 32 {
			return canonical, 0, 0, 0, false, false
		}
		key := be32(addr.As4())
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		key &= mask
		high = uint64(key) << 32
		canonical = netip.PrefixFrom(addrOf(high, 0, true), length)
		return canonical, high, 0, uint8(length), true, true
	}
	if length > 128 {
		return canonical, 0, 0, 0, false, false
	}
	high, low = words16(addr.As16())
	high, low = maskKey(high, low, length)
	canonical = netip.PrefixFrom(addrOf(high, low, false), length)
	return canonical, high, low, uint8(length), false, true
}
