// Package arenaartlpm is the pointer-free ART LPM: arena indices, shared
// child/value runs, IPv4 /16 front table. Build-once, read-many. We kept
// it because Rebuild's DFS layout is a useful analogue; we don't mutate
// this thing in production - dead-run churn is the deal-breaker
package arenaartlpm

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

// Table is the memory-optimised ART. Three changes vs a pointer trie:
//
//  1. Arena indices instead of pointers. Children are uint32 indices into
//     one flat []compactNode. Halves the link, and the whole structure is
//     pointer-free so GC never scans it
//
//  2. Shared child and value arenas. Every node's kids occupy a contiguous
//     run of one global []uint32, addressed by offset+count. One alloc
//     across the table instead of one per node
//
//  3. A 256-bit child bitmap only. Prefix storage still needs the 512-bit
//     ART bitmap, but the node itself is a fixed 48 bytes with no slice
//     headers
//
// The trade: inserting into a full run relocates it to the end of the arena
// and abandons the old space. Amortised, not worst-case cheap, and a
// churny table accumulates dead slots until Rebuild. Fine for build-once
type Table[V any] struct {
	nodes  []compactNode
	childs []uint32 // shared child-index arena
	vals   []V      // shared value arena
	root4  uint32
	root6  uint32
	size4  int
	size6  int
	// dead counts arena slots abandoned by relocation, so callers can decide
	// when a Rebuild is worthwhile
	dead int

	// front is the IPv4 /16 acceleration table: per /16, the arena index of
	// the depth-2 node and the value-arena index of the best match from the
	// two levels above. uint32s, not pointers, so we stay GC-invisible
	// 8 bytes per slot, 512 KiB. We drop it on any mutation
	front   []compactFront
	frontOK bool
}

// compactFront is one /16 slot. nodeIdx is noNode when no depth-2 node exists,
// and valIdx is noVal when the upper levels contributed no match
type compactFront struct {
	nodeIdx uint32
	valIdx  uint32
}

const (
	noNode = ^uint32(0)
	noVal  = ^uint32(0)
)

// compactNode is 48 bytes and contains no pointers
type compactNode struct {
	pfxBits   art.Bitset512 // 64 bytes of prefix bitmap
	childBits art.Bitset256 // 32 bytes of child bitmap
	childOff  uint32        // start of this node's run in Table.childs
	childCap  uint32        // capacity of that run
	valOff    uint32        // start of this node's run in Table.vals
	valCap    uint32        // capacity of that run
	pfxCount  uint16
	childN    uint16
}

// New returns an empty Table. Slot 0 is the v4 root, slot 1 the v6 root -
// we pre-allocate both so rootFor never has to grow
func New[V any]() *Table[V] {
	c := &Table[V]{}
	// index 0 is the IPv4 root, index 1 the IPv6 root
	c.nodes = make([]compactNode, 2)
	c.root4, c.root6 = 0, 1
	return c
}

// Size returns the number of stored prefixes. Both families, live entries
// only - dead arena slots don't count
func (c *Table[V]) Size() int { return c.size4 + c.size6 }

// Dead returns the number of arena slots abandoned by relocation. A large
// value relative to Size means Rebuild would actually reclaim something
func (c *Table[V]) Dead() int { return c.dead }

// rootFor picks the family root index. Tiny, but we call it a lot
func (c *Table[V]) rootFor(is4 bool) uint32 {
	if is4 {
		return c.root4
	}
	return c.root6
}

// Lookup performs a longest-prefix match. v4 with a live front table skips
// the first two strides via one indexed read; otherwise we descend octet by
// octet, updating the best ART LPM at each node. Arena indirection is the
// only structural difference vs a pointer ART
func (c *Table[V]) Lookup(addr netip.Addr) (val V, ok bool) {
	// register-resident IPv4 descent. The arena indirection (c.nodes[i],
	// c.childs[...]) is the only structural difference vs a pointer trie
	if addr.Is4() || addr.Is4In6() {
		key := be32(addr.As4())
		if c.frontOK {
			e := &c.front[key>>16]
			if e.valIdx != noVal {
				val, ok = c.vals[e.valIdx], true
			}
			if e.nodeIdx == noNode {
				return val, ok
			}
			n := &c.nodes[e.nodeIdx]
			octet := uint(key>>8) & 0xff
			if n.pfxCount != 0 {
				if idx, hit := n.pfxBits.LpmTop(uint8(octet)); hit {
					val, ok = c.vals[n.valOff+uint32(n.pfxBits.Rank0(idx))], true
				}
			}
			if !n.childBits.Test(octet) {
				return val, ok
			}
			n = &c.nodes[c.childs[n.childOff+uint32(n.childBits.Rank0(octet))]]
			last := uint(key) & 0xff
			if n.pfxCount != 0 {
				if idx, hit := n.pfxBits.LpmTop(uint8(last)); hit {
					val, ok = c.vals[n.valOff+uint32(n.pfxBits.Rank0(idx))], true
				}
			}
			return val, ok
		}
		ni := c.root4
		for shift := 24; ; shift -= 8 {
			octet := uint(key>>shift) & 0xff
			n := &c.nodes[ni]
			if n.pfxCount != 0 {
				if idx, hit := n.pfxBits.LpmTop(uint8(octet)); hit {
					val, ok = c.vals[n.valOff+uint32(n.pfxBits.Rank0(idx))], true
				}
			}
			if shift == 0 || !n.childBits.Test(octet) {
				return val, ok
			}
			ni = c.childs[n.childOff+uint32(n.childBits.Rank0(octet))]
		}
	}
	k, valid := addrkey.FromAddr(addr)
	if !valid {
		return val, false
	}
	ni := c.rootFor(k.Is4)
	last := int(k.Len) - 1
	for depth := 0; ; depth++ {
		n := &c.nodes[ni]
		if n.pfxCount != 0 {
			if idx, hit := n.pfxBits.LpmTop(k.Octets[depth]); hit {
				val, ok = c.vals[n.valOff+uint32(n.pfxBits.Rank0(idx))], true
			}
		}
		if depth == last {
			return val, ok
		}
		octet := uint(k.Octets[depth])
		if !n.childBits.Test(octet) {
			return val, ok
		}
		ni = c.childs[n.childOff+uint32(n.childBits.Rank0(octet))]
	}
}

// Contains reports whether any stored prefix covers addr. Same descent as
// Lookup but we return on the first covering hit - no LPM, no values
func (c *Table[V]) Contains(addr netip.Addr) bool {
	k, valid := addrkey.FromAddr(addr)
	if !valid {
		return false
	}
	ni := c.rootFor(k.Is4)
	last := int(k.Len) - 1
	for depth := 0; ; depth++ {
		n := &c.nodes[ni]
		if n.pfxCount != 0 && n.pfxBits.IntersectsOctet(k.Octets[depth]) {
			return true
		}
		if depth == last {
			return false
		}
		octet := uint(k.Octets[depth])
		if !n.childBits.Test(octet) {
			return false
		}
		ni = c.childs[n.childOff+uint32(n.childBits.Rank0(octet))]
	}
}

// Get returns the value stored for exactly pfx. Descend to the terminal
// stride, test the ART index, rank into the value run. Not LPM
func (c *Table[V]) Get(pfx netip.Prefix) (val V, ok bool) {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return val, false
	}
	ni := c.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	for d := 0; d < depth; d++ {
		n := &c.nodes[ni]
		octet := uint(pk.Octets[d])
		if !n.childBits.Test(octet) {
			return val, false
		}
		ni = c.childs[n.childOff+uint32(n.childBits.Rank0(octet))]
	}
	n := &c.nodes[ni]
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if !n.pfxBits.Test(idx) {
		return val, false
	}
	return c.vals[n.valOff+uint32(n.pfxBits.Rank0(idx))], true
}

// Insert stores val for pfx, reporting whether it was newly added. We
// allocate missing children as we descend, then splice the value into the
// node's run. dropFront because the accelerator is stale after any write
func (c *Table[V]) Insert(pfx netip.Prefix, val V) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	c.dropFront()
	ni := c.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)

	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		if c.nodes[ni].childBits.Test(octet) {
			rank := c.nodes[ni].childBits.Rank0(octet)
			ni = c.childs[c.nodes[ni].childOff+uint32(rank)]
			continue
		}
		// allocate the child first, then splice its index into the parent's
		// run. Every access to the parent is re-indexed through c.nodes rather
		// than held as a pointer, because the append above may have moved the
		// node arena
		rank := c.nodes[ni].childBits.Rank0(octet)
		c.nodes = append(c.nodes, compactNode{})
		child := uint32(len(c.nodes) - 1)
		c.insertChild(ni, rank, child)
		c.nodes[ni].childBits.Set(octet)
		c.nodes[ni].childN++
		ni = child
	}

	idx := art.PfxToIdx(pk.Octets[depth], remain)
	rank := c.nodes[ni].pfxBits.Rank0(idx)
	if c.nodes[ni].pfxBits.Test(idx) {
		c.vals[c.nodes[ni].valOff+uint32(rank)] = val
		return false
	}
	c.insertVal(ni, rank, val)
	c.nodes[ni].pfxBits.Set(idx)
	c.nodes[ni].pfxCount++
	if pk.Is4 {
		c.size4++
	} else {
		c.size6++
	}
	return true
}

// growth returns the capacity to allocate for a run that needs n slots. Runs
// grow geometrically so repeated appends to one node are amortised O(1),
// but start small because most nodes have very few children
//
// Ceiling is 512, not 256: a child run holds at most 256 entries (one per
// octet) but a value run holds at most 512 (one per ART prefix index)
// Capping at 256 silently under-allocates dense value runs - we found that
// the hard way
func growth(n uint32) uint32 {
	c := uint32(2)
	for c < n {
		c <<= 1
	}
	if c > art.MaxPrefixes {
		return art.MaxPrefixes
	}
	return c
}

// insertChild splices child into node ni's child run at position rank,
// relocating the run to the end of the arena if it has no spare capacity
// That's where dead space comes from
func (c *Table[V]) insertChild(ni uint32, rank int, child uint32) {
	// read the run descriptor by value. A &c.nodes[ni] pointer must not be
	// held here: growing c.childs below can trigger a reallocation
	off, capacity, count := c.nodes[ni].childOff, c.nodes[ni].childCap, uint32(c.nodes[ni].childN)
	need := count + 1
	if need > capacity {
		newCap := growth(need)
		newOff := uint32(len(c.childs))
		c.childs = append(c.childs, make([]uint32, newCap)...)
		copy(c.childs[newOff:], c.childs[off:off+count])
		c.dead += int(capacity)
		off, capacity = newOff, newCap
		c.nodes[ni].childOff, c.nodes[ni].childCap = newOff, newCap
	}
	_ = capacity
	run := c.childs[off : off+need]
	copy(run[rank+1:], run[rank:])
	run[rank] = child
}

// insertVal splices val into node ni's value run at position rank. Same
// relocate-and-abandon as insertChild
func (c *Table[V]) insertVal(ni uint32, rank int, val V) {
	// as in insertChild, the run descriptor is read by value because growing
	// c.vals can reallocate the arena
	off, capacity, count := c.nodes[ni].valOff, c.nodes[ni].valCap, uint32(c.nodes[ni].pfxCount)
	need := count + 1
	if need > capacity {
		newCap := growth(need)
		newOff := uint32(len(c.vals))
		c.vals = append(c.vals, make([]V, newCap)...)
		copy(c.vals[newOff:], c.vals[off:off+count])
		c.dead += int(capacity)
		off = newOff
		c.nodes[ni].valOff, c.nodes[ni].valCap = newOff, newCap
	}
	run := c.vals[off : off+need]
	copy(run[rank+1:], run[rank:])
	run[rank] = val
}

// BuildFront constructs the IPv4 /16 acceleration table. 512 KiB, stale
// after any mutation, so it's a build-once thing. Rebuild calls it for us
func (c *Table[V]) BuildFront() {
	front := make([]compactFront, 65536)
	for hi := 0; hi < 65536; hi++ {
		o0 := uint(hi >> 8)
		o1 := uint(hi & 0xff)
		valIdx := noVal

		n := &c.nodes[c.root4]
		if n.pfxCount != 0 {
			if idx, hit := n.pfxBits.LpmTop(uint8(o0)); hit {
				valIdx = n.valOff + uint32(n.pfxBits.Rank0(idx))
			}
		}
		if !n.childBits.Test(o0) {
			front[hi] = compactFront{noNode, valIdx}
			continue
		}
		ni := c.childs[n.childOff+uint32(n.childBits.Rank0(o0))]
		n = &c.nodes[ni]
		if n.pfxCount != 0 {
			if idx, hit := n.pfxBits.LpmTop(uint8(o1)); hit {
				valIdx = n.valOff + uint32(n.pfxBits.Rank0(idx))
			}
		}
		if !n.childBits.Test(o1) {
			front[hi] = compactFront{noNode, valIdx}
			continue
		}
		front[hi] = compactFront{c.childs[n.childOff+uint32(n.childBits.Rank0(o1))], valIdx}
	}
	c.front = front
	c.frontOK = true
}

// dropFront invalidates the acceleration table after a mutation. We nil
// the slice so the 512 KiB can actually get collected
func (c *Table[V]) dropFront() {
	if c.frontOK {
		c.front = nil
		c.frontOK = false
	}
}

// Delete removes pfx, reporting whether it was present. Nodes aren't
// reclaimed and runs aren't shrunk; the vacated slot becomes dead arena
// space. Keeps deletion O(depth) and matches the build-once pitch. Call
// Rebuild if you actually care about the bytes
func (c *Table[V]) Delete(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	c.dropFront()
	ni := c.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	for d := 0; d < depth; d++ {
		n := &c.nodes[ni]
		octet := uint(pk.Octets[d])
		if !n.childBits.Test(octet) {
			return false
		}
		ni = c.childs[n.childOff+uint32(n.childBits.Rank0(octet))]
	}
	n := &c.nodes[ni]
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if !n.pfxBits.Test(idx) {
		return false
	}
	rank := uint32(n.pfxBits.Rank0(idx))
	run := c.vals[n.valOff : n.valOff+uint32(n.pfxCount)]
	copy(run[rank:], run[rank+1:])
	var zero V
	run[len(run)-1] = zero
	n.pfxBits.Clear(idx)
	n.pfxCount--
	c.dead++
	if pk.Is4 {
		c.size4--
	} else {
		c.size6--
	}
	return true
}

// Rebuild returns a new Table holding the same prefixes with every run
// sized exactly and every node laid out in depth-first order. That's the
// whole point of this type: incremental insert can't know final counts so
// it doubles and abandons; Rebuild can allocate exact. DFS also puts a
// node's kids next to it so descent prefetches. Costs O(n) and a second
// copy of the structure during the call
func (c *Table[V]) Rebuild() *Table[V] {
	out := &Table[V]{
		root4: 0,
		root6: 1,
		size4: c.size4,
		size6: c.size6,
	}
	nodeCount, childCount := c.census(c.root4)
	n6, c6 := c.census(c.root6)
	nodeCount, childCount = nodeCount+n6, childCount+c6

	out.nodes = make([]compactNode, 2, nodeCount)
	out.childs = make([]uint32, 0, childCount)
	out.vals = make([]V, 0, c.size4+c.size6)

	out.copyFrom(c, c.root4, out.root4)
	out.copyFrom(c, c.root6, out.root6)
	// the rebuilt table is the read-optimised form, so build the accelerator
	out.BuildFront()
	return out
}

// census counts the nodes and total child links in a subtree, so Rebuild can
// size its arenas exactly and never reallocate. Recursive; tables aren't
// deep enough for that to matter
func (c *Table[V]) census(ni uint32) (nodes, children int) {
	n := &c.nodes[ni]
	nodes, children = 1, int(n.childN)
	var buf [256]uint8
	for _, oct := range n.childBits.All(buf[:0]) {
		cn := &c.nodes[ni]
		sub := c.childs[cn.childOff+uint32(cn.childBits.Rank0(uint(oct)))]
		dn, dc := c.census(sub)
		nodes += dn
		children += dc
	}
	return nodes, children
}

// copyFrom copies src's node srcIdx into out's already-allocated node dstIdx,
// then emits its children depth-first so a node's subtree is contiguous
func (out *Table[V]) copyFrom(src *Table[V], srcIdx, dstIdx uint32) {
	sn := &src.nodes[srcIdx]
	pfxBits, childBits := sn.pfxBits, sn.childBits
	pfxCount, childN := sn.pfxCount, sn.childN
	srcValOff, srcChildOff := sn.valOff, sn.childOff

	// values: one exact-length run
	valOff := uint32(len(out.vals))
	if pfxCount > 0 {
		out.vals = append(out.vals, src.vals[srcValOff:srcValOff+uint32(pfxCount)]...)
	}
	// children: reserve the exact-length run before allocating the child
	// nodes, so the run stays contiguous
	childOff := uint32(len(out.childs))
	if childN > 0 {
		out.childs = append(out.childs, make([]uint32, childN)...)
	}

	out.nodes[dstIdx] = compactNode{
		pfxBits:   pfxBits,
		childBits: childBits,
		childOff:  childOff,
		childCap:  uint32(childN),
		valOff:    valOff,
		valCap:    uint32(pfxCount),
		pfxCount:  pfxCount,
		childN:    childN,
	}

	for i := uint32(0); i < uint32(childN); i++ {
		out.nodes = append(out.nodes, compactNode{})
		newChild := uint32(len(out.nodes) - 1)
		out.childs[childOff+i] = newChild
		out.copyFrom(src, src.childs[srcChildOff+i], newChild)
	}
}

// All calls fn for every stored prefix. v4 then v6; we stop early if fn
// returns false. Walk mutates the key octets in place and restores them
func (c *Table[V]) All(fn func(netip.Prefix, V) bool) {
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	if !c.walk(c.root4, &key, 0, fn) {
		return
	}
	key = addrkey.Key{Len: 16}
	c.walk(c.root6, &key, 0, fn)
}

// walk enumerates one subtree: stored prefixes at this node, then children
// We stash/restore the octet we're walking so the caller's key is reusable
func (c *Table[V]) walk(ni uint32, key *addrkey.Key, depth int, fn func(netip.Prefix, V) bool) bool {
	n := &c.nodes[ni]
	if n.pfxCount != 0 {
		var buf [16]uint
		for _, idx := range n.pfxBits.All(buf[:0]) {
			octet, pfxLen := art.IdxToPfx(idx)
			saved := key.Octets[depth]
			key.Octets[depth] = octet
			pk := addrkey.PrefixKey{Key: *key, Bits: uint8(depth*8) + pfxLen}
			ok := fn(pk.Prefix(), c.vals[n.valOff+uint32(n.pfxBits.Rank0(idx))])
			key.Octets[depth] = saved
			if !ok {
				return false
			}
		}
	}
	if n.childBits.IsEmpty() {
		return true
	}
	var cbuf [256]uint8
	for _, octet := range n.childBits.All(cbuf[:0]) {
		// re-read the node each iteration: fn may not mutate, but the arena
		// slice header can be reallocated by a concurrent Rebuild source walk
		cn := &c.nodes[ni]
		child := c.childs[cn.childOff+uint32(cn.childBits.Rank0(uint(octet)))]
		saved := key.Octets[depth]
		key.Octets[depth] = octet
		ok := c.walk(child, key, depth+1, fn)
		key.Octets[depth] = saved
		if !ok {
			return false
		}
	}
	return true
}

// decompose splits a prefix length into stride depth and remaining bits
// within that stride. /0 is the awkward (0, 0) case
func decompose(bits uint8) (depth int, pfxLen uint8) {
	if bits == 0 {
		return 0, 0
	}
	depth = int(bits-1) >> 3
	return depth, bits - uint8(depth<<3)
}

// be32 packs four bytes as a big-endian uint32. Hot-path helper so we
// don't drag netip into the inner loop
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
