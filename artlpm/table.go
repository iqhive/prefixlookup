// Package artlpm is the stride-8 ART LPM table we actually want on the hot path
//
// each node eats one octet so v4 is at most 4 dependent loads (v6 16), not 32/128
// like the old bit-at-a-time tree. prefixes of length 0..8 live in a 512-bit ART
// bitmap, LPM inside a node is a shift-and-test that hits one cache line. kids
// and values are popcount-compressed so three children cost three pointers, not 256
//
// v4 and v6 are separate tries - see internal/addrkey for why that helps locality
//
// not safe for concurrent mutation, that's versioned.Table's job. this is the
// single-writer building block
package artlpm

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/internal/art"
)

// Table is implementation (2): match an addr, hand back a value
//
// stride-8 ART, v4/v6 split, optional /16 front table for v4. writers only,
// readers go through versioned.Table if they need lock-free
type Table[V any] struct {
	root4 node[V]
	root6 node[V]
	size4 int
	size6 int

	// front is the IPv4 /16 accel table, see BuildFront
	front   []frontEntry[V]
	frontOK bool
}

// frontEntry is one /16 slot of the v4 accel table
//
// we collapse the first two trie levels into one indexed read: node is the
// depth-2 node those two octets land on (nil if none), val/ok is the best match
// the two levels above would have contributed so we don't recompute it
type frontEntry[V any] struct {
	node *node[V]
	val  V
	ok   bool
	// slow is set when a path-compressed leaf sits in the first two levels of
	// this /16. a leaf can only be resolved against the full key, which the
	// precomputation doesn't have, so we fall back to a full descent
	// they're rare: a leaf up there means a prefix shorter than /24 with no
	// siblings underneath it
	slow bool
}

// node is one stride of the trie
//
// prefix data is behind a pointer on purpose. naive layout embeds the 512-bit
// bitmap and you get a 152-byte node - that's the dominant cost and almost all
// of it is wasted. on a 500k-prefix table we measured 63901 nodes of which
// 57173 are leaves, average node holds under 8 prefixes. every leaf was
// dragging around a 64-byte bitmap and a 24-byte slice header for a handful of
// entries
//
// at 152 bytes the node array alone is 9 MiB, doesn't fit L2, barely L3. v4
// lookup makes three dependent accesses into that array so we were missing
// cache at almost every level, and that - not instruction count - was the limit
//
// shoving the prefix kit behind a pointer shrinks the node to 48 bytes. whole
// descent structure is ~3 MiB, L2/L3 resident, nodes-per-cache-line goes from
// 0.42 to 1.33. we only chase pfx when the node actually has prefixes, which
// we already know from a two-byte count in the first cache line
//
// cost is one extra indirection on levels that do have prefixes. that's an L1
// hit (we just prefetched the block with the node) and we pay it far less
// often than the miss it avoids
type node[V any] struct {
	childBits art.Bitset256 // 32 bytes: which octets have a child
	children  []*node[V]    // 24 bytes: popcount-compressed child pointers
	pfxCount  uint16        // popcount of pfx.bits, 0 means pfx may be nil
	pfx       *prefixBlock[V]

	// leaves holds path-compressed terminal prefixes, parallel to leafBits
	//
	// we need this for IPv6: without it a single /128 forces a chain of sixteen
	// nodes, last thirteen have exactly one child and no prefixes. on a 200k
	// IPv6 table the uncompressed trie had 382004 nodes - almost two per stored
	// prefix - and depths 8 through 15 each held 1646 nodes that exist only to
	// be walked through
	//
	// a leaf stores the remaining octets inline instead of allocating that
	// chain. descent stops when it hits one and compares the tail, which for a
	// deep v6 prefix replaces up to thirteen dependent pointer loads with one
	// comparison
	//
	// v4 benefits less (/32 is only four levels) but the mechanism is shared
	// and costs nothing when unused
	leafBits art.Bitset256
	leaves   []leaf[V]
}

// leaf is a path-compressed terminal: the full key whose tail we elided, plus
// length and value
type leaf[V any] struct {
	key  addrkey.Key
	bits uint8
	val  V
}

// prefixBlock is the prefix bitmap + values for one node
// we only allocate one when the node actually stores a prefix
type prefixBlock[V any] struct {
	bits   art.Bitset512
	values []V
}

// New returns an empty Table
// just a zero struct, roots are embedded so there's nothing to allocate yet
func New[V any]() *Table[V] { return &Table[V]{} }

// decompose splits a prefix length into the trie depth that holds it and the
// residual length inside that stride
//
// the obvious split (depth = bits/8, pfxLen = bits%8) is wrong at the top of
// the range: a /32 would land at depth 4 of a 4-byte key, one past the end
// it's also wasteful because it shoves every multiple-of-8 prefix down into a
// child that exists only to hold that node's index-1 slot
//
// canonical split puts length b at depth (b-1)/8 with stride length in [1,8],
// so depth is always in [0, keyLen-1] and a /8 /16 /24 /32 lives in the node it
// naturally belongs to rather than a child. that's one fewer node alloc and one
// fewer dependent load per such prefix, and those lengths dominate real tables
//
// only prefix with stride length 0 is the default route, at depth 0
func decompose(bits uint8) (depth int, pfxLen uint8) {
	if bits == 0 {
		return 0, 0
	}
	depth = int(bits-1) >> 3
	return depth, bits - uint8(depth<<3)
}

// Size returns how many prefixes we've stored
// just size4+size6, we keep the families split so this is a pair of adds
func (t *Table[V]) Size() int { return t.size4 + t.size6 }

// Size4 returns the IPv4 prefix count
// we track it on Insert/Delete so we don't have to walk the trie
func (t *Table[V]) Size4() int { return t.size4 }

// Size6 returns the IPv6 prefix count
// same as Size4, just the other counter
func (t *Table[V]) Size6() int { return t.size6 }

// rootFor picks the v4 or v6 root
// two fields, one branch, nothing clever
func (t *Table[V]) rootFor(is4 bool) *node[V] {
	if is4 {
		return &t.root4
	}
	return &t.root6
}

// -----------------------------------------------------------------------------
// Lookup
// -----------------------------------------------------------------------------

// Lookup does LPM for addr and returns the associated value, never allocates
//
// we record the best match at each level and return whatever we last wrote -
// deeper node always wins so the last write is the longest match
func (t *Table[V]) Lookup(addr netip.Addr) (val V, ok bool) {
	// IPv4 fast path: keep the key in a uint32 so we don't materialise addrkey
	//
	// stuffing this into the generic 16-byte addrkey.Key costs more than the
	// trie descent itself: it materialises an array, copies a 24-byte struct,
	// then the descent indexes memory rather than a register
	//
	// for v4 the whole key is 4 bytes so it fits in a uint32 that stays in a
	// register for the entire descent. each level extracts its octet with a
	// shift and mask instead of a load. biggest win on the hot path
	if addr.Is4() {
		return t.lookup4(be32(addr.As4()))
	}
	if addr.Is4In6() {
		return t.lookup4(be32(addr.As4()))
	}
	if !addr.IsValid() {
		return val, false
	}
	return t.lookup6(addr.As16())
}

// lookup6 is IPv6 LPM with the key held in two uint64s
//
// same trick as lookup4: netip.Addr already stores v6 as two uint64 halves so
// we extract octets by shifting instead of indexing an array. that's one fewer
// dependent load per level, and v6 has four times as many levels as v4 so it
// actually matters more here
//
// we split the loop into the two halves rather than one 16-iteration loop over
// a byte array so the shift amount is a constant in each unrolled step and the
// compiler never has to materialise the array
func (t *Table[V]) lookup6(b [16]byte) (val V, ok bool) {
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])

	n := &t.root6
	word := hi
	for depth := 0; ; depth++ {
		if depth == 8 {
			word = lo
		}
		octet := uint((word >> (56 - 8*(uint(depth)&7))) & 0xff)
		if n.pfxCount != 0 {
			if idx, hit := n.pfx.bits.LpmTop(uint8(octet)); hit {
				val, ok = n.pfx.values[n.pfx.bits.Rank0(idx)], true
			}
		}
		if n.leafBits.Test(octet) {
			lf := &n.leaves[n.leafBits.Rank0(octet)]
			if lf.covers(&b) {
				return lf.val, true
			}
			return val, ok
		}
		if depth == 15 || !n.childBits.Test(octet) {
			return val, ok
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// be32 packs four octets into a big-endian uint32
// octet 0 is the high byte, same as you'd write the address
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// lookup4 is IPv4 LPM with the key held in a register
//
// front-table fast path: a realistic v4 table is dominated by /24s so the trie
// is three levels deep and the middle is by far the widest. on a 500k-entry
// table we measured 222 depth-1 nodes but 56804 depth-2 nodes. descent therefore
// makes three dependent pointer loads, and the second and third almost always
// miss cache because the depth-2 array is several MiB
//
// the first two of those loads are determined entirely by the top 16 bits, of
// which there are only 65536 possibilities, so we precompute them. two
// dependent cache misses become one indexed read of a flat array, leaving a
// single pointer chase for the last level
//
// the slot also carries the best match from the two levels it replaces, so a
// /8 or /16 covering route is already resolved without descent
func (t *Table[V]) lookup4(key uint32) (val V, ok bool) {
	var ob [16]byte
	ob[0], ob[1], ob[2], ob[3] = byte(key>>24), byte(key>>16), byte(key>>8), byte(key)

	if t.frontOK {
		e := &t.front[key>>16]
		if !e.slow {
			if e.node == nil {
				return e.val, e.ok
			}
			return t.descend4(e.node, key, &ob, 2, e.val, e.ok)
		}
		// a path-compressed leaf lives in the first two levels of this /16, so
		// it can't be resolved without the full key - fall through
	}
	return t.descend4(&t.root4, key, &ob, 0, val, ok)
}

// descend4 walks the v4 trie from depth to the end, carrying the best match so far
// shared by the accelerated and unaccelerated paths so we don't duplicate the loop
func (t *Table[V]) descend4(n *node[V], key uint32, ob *[16]byte, depth int, val V, ok bool) (V, bool) {
	for d := depth; ; d++ {
		octet := uint(ob[d])
		if n.pfxCount != 0 {
			if idx, hit := n.pfx.bits.LpmTop(uint8(octet)); hit {
				val, ok = n.pfx.values[n.pfx.bits.Rank0(idx)], true
			}
		}
		if n.leafBits.Test(octet) {
			lf := &n.leaves[n.leafBits.Rank0(octet)]
			if lf.covers(ob) {
				return lf.val, true
			}
			return val, ok
		}
		if d == 3 || !n.childBits.Test(octet) {
			return val, ok
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// BuildFront constructs the IPv4 /16 accel table, trading memory and build time
// for lookup latency
//
// costs 65536 entries of (pointer + value + bool), ~1.6 MiB for a pointer-sized
// value type, and it must be rebuilt after any mutation - Insert and Delete
// invalidate it automatically. so it's for a build-once, read-many table and
// pointless under constant churn
//
// versioned.Table calls this automatically when publishing a generation, which
// is the intended way: the generation is immutable so we build once and then
// serve every read of that gen
func (t *Table[V]) BuildFront() {
	front := make([]frontEntry[V], 65536)
	for hi := 0; hi < 65536; hi++ {
		o0 := uint(hi >> 8)
		o1 := uint(hi & 0xff)
		var val V
		var ok bool

		n := &t.root4
		if n.pfxCount != 0 {
			if idx, hit := n.pfx.bits.LpmTop(uint8(o0)); hit {
				val, ok = n.pfx.values[n.pfx.bits.Rank0(idx)], true
			}
		}
		if n.leafBits.Test(o0) {
			front[hi] = frontEntry[V]{slow: true}
			continue
		}
		if !n.childBits.Test(o0) {
			front[hi] = frontEntry[V]{node: nil, val: val, ok: ok}
			continue
		}
		n = n.children[n.childBits.Rank0(o0)]
		if n.pfxCount != 0 {
			if idx, hit := n.pfx.bits.LpmTop(uint8(o1)); hit {
				val, ok = n.pfx.values[n.pfx.bits.Rank0(idx)], true
			}
		}
		if n.leafBits.Test(o1) {
			front[hi] = frontEntry[V]{slow: true}
			continue
		}
		if !n.childBits.Test(o1) {
			front[hi] = frontEntry[V]{node: nil, val: val, ok: ok}
			continue
		}
		front[hi] = frontEntry[V]{node: n.children[n.childBits.Rank0(o1)], val: val, ok: ok}
	}
	t.front = front
	t.frontOK = true
}

// dropFront invalidates the accel table after a mutation
// we just nil it out rather than trying to patch individual slots
func (t *Table[V]) dropFront() {
	if t.frontOK {
		t.front = nil
		t.frontOK = false
	}
}

// lookupKey is the generic LPM used when we've already got an addrkey
// v4/v6 share this, we pick the root from k.Is4 then walk octets
func (t *Table[V]) lookupKey(k *addrkey.Key) (val V, ok bool) {
	n := t.rootFor(k.Is4)
	// prefixes live at depths 0..Len-1 (see decompose), so we never run past
	// the last octet and we don't need an end-of-address special case
	last := int(k.Len) - 1

	// single downward pass, no backtracking stack
	//
	// textbook ART lookup descends to the deepest node while pushing the path
	// onto a stack, then unwinds looking for the first covering prefix. that
	// stack is a 16-element pointer array Go must zero on every call - 128
	// bytes of stores on the hot path to serve a search that almost always
	// resolves at the deepest level anyway
	//
	// we don't need it. a deeper node always holds a longer prefix, so the last
	// covering prefix found on the way down is by definition the longest match
	// recording it as we descend gives the same answer with no stack, no unwind
	// loop and no zeroing
	for depth := 0; ; depth++ {
		if n.pfxCount != 0 {
			if idx, hit := n.pfx.bits.LpmTop(k.Octets[depth]); hit {
				val, ok = n.pfx.values[n.pfx.bits.Rank0(idx)], true
			}
		}
		octet := uint(k.Octets[depth])
		if n.leafBits.Test(octet) {
			lf := &n.leaves[n.leafBits.Rank0(octet)]
			if lf.covers(&k.Octets) {
				return lf.val, true
			}
			return val, ok
		}
		if depth == last || !n.childBits.Test(octet) {
			return val, ok
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
}

// Contains reports whether any stored prefix covers addr
// membership form of Lookup, we just throw away the value
//
// for a pure membership workload prefer Set (implementation 1), which is
// smaller and faster still because it stores no values at all
func (t *Table[V]) Contains(addr netip.Addr) bool {
	_, ok := t.Lookup(addr)
	return ok
}

// LookupPrefix does LPM for an entire prefix rather than a host addr
// returns the longest stored prefix that covers pfx
//
// we walk down recording the path on a stack, then unwind looking for a
// covering prefix that's no longer than the query - at the terminal level we
// start the ancestor walk at the query's own ART index rather than the host
func (t *Table[V]) LookupPrefix(pfx netip.Prefix) (val V, ok bool) {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return val, false
	}
	n := t.rootFor(pk.Is4)
	lastDepth, remain := decompose(pk.Bits)

	var stack [16]*node[V]
	depth := 0
	for {
		stack[depth] = n
		if depth == lastDepth {
			break
		}
		octet := uint(pk.Octets[depth])
		if n.leafBits.Test(octet) {
			lf := &n.leaves[n.leafBits.Rank0(octet)]
			// a leaf covers the query only if it is no longer than it and
			// matches on its own significant bits
			if lf.bits <= pk.Bits && lf.covers(&pk.Octets) {
				return lf.val, true
			}
			break
		}
		if !n.childBits.Test(octet) {
			break
		}
		n = n.children[n.childBits.Rank0(octet)]
		depth++
	}
	for d := depth; d >= 0; d-- {
		n = stack[d]
		if n.pfxCount == 0 {
			continue
		}
		// at the terminal level a covering prefix may be no longer than the
		// query itself, so start the ancestor walk at the query's own index
		// rather than at the host index
		host := art.HostIdx(pk.Octets[d])
		if d == lastDepth {
			host = art.PfxToIdx(pk.Octets[d], remain)
		}
		if idx, hit := n.pfx.bits.Lpm(host); hit {
			return n.pfx.values[n.pfx.bits.Rank0(idx)], true
		}
	}
	return val, false
}

// Get returns the value stored for exactly pfx, no LPM fallback
// we walk to the decompose depth then test the ART index, or match a leaf
func (t *Table[V]) Get(pfx netip.Prefix) (val V, ok bool) {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return val, false
	}
	n := t.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)
	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		if n.leafBits.Test(octet) {
			// exact match against a path-compressed entry
			lf := &n.leaves[n.leafBits.Rank0(octet)]
			if lf.bits == pk.Bits && lf.key.Octets == pk.Octets {
				return lf.val, true
			}
			return val, false
		}
		if !n.childBits.Test(octet) {
			return val, false
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if n.pfx == nil || !n.pfx.bits.Test(idx) {
		return val, false
	}
	return n.pfx.values[n.pfx.bits.Rank0(idx)], true
}

// -----------------------------------------------------------------------------
// Mutation
// -----------------------------------------------------------------------------

// Insert stores val for pfx, overwriting any existing value
// reports whether the prefix was newly added
//
// write cost: one node alloc per newly occupied stride (at most 4 for v4, 16
// for v6) plus a slice insert per level, which is a memmove of the
// popcount-compressed arrays. more expensive than the legacy tree's pointer
// store, and that's the deliberate trade: writes pay so reads don't. see
// OPTIMISATION.md
func (t *Table[V]) Insert(pfx netip.Prefix, val V) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	t.dropFront()
	n := t.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)

	for d := 0; d < depth; d++ {
		octet := uint(pk.Octets[d])
		rank := n.childBits.Rank0(octet)

		// a leaf already occupies this slot. either it's the same key, in
		// which case we replace the value, or the two keys diverge deeper and
		// we have to push the leaf down so both can coexist
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			if lf.bits == pk.Bits && lf.key.Octets == pk.Octets {
				n.leaves[lrank].val = val
				return false
			}
			// convert the leaf into a real child and reinsert it, then carry
			// on inserting the new prefix through the node we just created
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			child := &node[V]{}
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			n = child
			t.insertAtDepth(child, lf.key, lf.bits, lf.val, d+1)
			continue
		}

		if !n.childBits.Test(octet) {
			// no child and no leaf: store the remainder as a leaf rather than
			// building the whole chain of single-child nodes down to it
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, leaf[V]{key: pk.Key, bits: pk.Bits, val: val})
			if pk.Is4 {
				t.size4++
			} else {
				t.size6++
			}
			return true
		}
		n = n.children[rank]
	}

	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if n.pfx == nil {
		n.pfx = &prefixBlock[V]{}
	}
	rank := n.pfx.bits.Rank0(idx)
	if n.pfx.bits.Test(idx) {
		n.pfx.values[rank] = val
		return false
	}
	n.pfx.bits.Set(idx)
	n.pfxCount++
	n.pfx.values = insertAt(n.pfx.values, rank, val)
	if pk.Is4 {
		t.size4++
	} else {
		t.size6++
	}
	return true
}

// insertAtDepth reinserts a displaced leaf beginning at trie depth from
//
// only called when a leaf collides with a new prefix, so we re-walk the
// remaining octets and either land the entry in a node's prefix block or
// re-compress it into a deeper leaf. we don't bump the size counters because
// the entry is being moved, not added
func (t *Table[V]) insertAtDepth(n *node[V], key addrkey.Key, bits uint8, val V, from int) {
	depth, remain := decompose(bits)
	for d := from; d < depth; d++ {
		octet := uint(key.Octets[d])
		rank := n.childBits.Rank0(octet)
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := n.leaves[lrank]
			if lf.bits == bits && lf.key.Octets == key.Octets {
				n.leaves[lrank].val = val
				return
			}
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			child := &node[V]{}
			n.childBits.Set(octet)
			n.children = insertAt(n.children, rank, child)
			n = child
			t.insertAtDepth(child, lf.key, lf.bits, lf.val, d+1)
			continue
		}
		if !n.childBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			n.leafBits.Set(octet)
			n.leaves = insertAt(n.leaves, lrank, leaf[V]{key: key, bits: bits, val: val})
			return
		}
		n = n.children[rank]
	}
	idx := art.PfxToIdx(key.Octets[depth], remain)
	if n.pfx == nil {
		n.pfx = &prefixBlock[V]{}
	}
	rank := n.pfx.bits.Rank0(idx)
	if n.pfx.bits.Test(idx) {
		n.pfx.values[rank] = val
		return
	}
	n.pfx.bits.Set(idx)
	n.pfxCount++
	n.pfx.values = insertAt(n.pfx.values, rank, val)
}

// covers reports whether this path-compressed leaf covers the given octets
// we compare whole bytes then mask the residual bits
func (lf *leaf[V]) covers(octets *[16]byte) bool {
	full := int(lf.bits) >> 3
	for i := 0; i < full; i++ {
		if lf.key.Octets[i] != octets[i] {
			return false
		}
	}
	if rem := lf.bits & 7; rem != 0 {
		m := byte(0xff) << (8 - rem)
		if lf.key.Octets[full]&m != octets[full]&m {
			return false
		}
	}
	return true
}

// Delete removes pfx and reports whether it was present
// nodes that become empty get pruned so a delete-heavy workload doesn't leak structure
func (t *Table[V]) Delete(pfx netip.Prefix) bool {
	pk, valid := addrkey.FromPrefix(pfx)
	if !valid {
		return false
	}
	t.dropFront()
	root := t.rootFor(pk.Is4)
	depth, remain := decompose(pk.Bits)

	// record the path so we can prune empty nodes on the way back up
	var stack [17]*node[V]
	n := root
	for d := 0; d < depth; d++ {
		stack[d] = n
		octet := uint(pk.Octets[d])
		if n.leafBits.Test(octet) {
			lrank := n.leafBits.Rank0(octet)
			lf := &n.leaves[lrank]
			if lf.bits != pk.Bits || lf.key.Octets != pk.Octets {
				return false
			}
			n.leafBits.Clear(octet)
			n.leaves = deleteAt(n.leaves, lrank)
			if pk.Is4 {
				t.size4--
			} else {
				t.size6--
			}
			t.prune(stack[:], pk, d)
			return true
		}
		if !n.childBits.Test(octet) {
			return false
		}
		n = n.children[n.childBits.Rank0(octet)]
	}
	stack[depth] = n

	idx := art.PfxToIdx(pk.Octets[depth], remain)
	if n.pfx == nil || !n.pfx.bits.Test(idx) {
		return false
	}
	rank := n.pfx.bits.Rank0(idx)
	n.pfx.bits.Clear(idx)
	n.pfxCount--
	n.pfx.values = deleteAt(n.pfx.values, rank)
	if n.pfxCount == 0 {
		n.pfx = nil // release the block so an emptied node costs 48 bytes
	}
	if pk.Is4 {
		t.size4--
	} else {
		t.size6--
	}

	// prune upward while nodes are empty - the root is never removed
	t.prune(stack[:], pk, depth)
	return true
}

// prune removes nodes that have become entirely empty, walking back up the
// recorded path. a node is empty only when it holds no prefixes, no children
// and no path-compressed leaves
func (t *Table[V]) prune(stack []*node[V], pk addrkey.PrefixKey, depth int) {
	for d := depth; d > 0; d-- {
		cur := stack[d]
		if cur == nil || cur.pfxCount != 0 || !cur.childBits.IsEmpty() || !cur.leafBits.IsEmpty() {
			return
		}
		parent := stack[d-1]
		if parent == nil {
			return
		}
		octet := uint(pk.Octets[d-1])
		if !parent.childBits.Test(octet) {
			return
		}
		r := parent.childBits.Rank0(octet)
		parent.childBits.Clear(octet)
		parent.children = deleteAt(parent.children, r)
	}
}

// -----------------------------------------------------------------------------
// Enumeration
// -----------------------------------------------------------------------------

// All calls fn for every stored prefix, stops early if fn returns false
// order is unspecified but deterministic for a given table
// we walk v4 then v6, mutating a scratch key as we go
func (t *Table[V]) All(fn func(pfx netip.Prefix, val V) bool) {
	var key addrkey.Key
	key.Is4, key.Len = true, 4
	if !t.root4.walk(&key, 0, fn) {
		return
	}
	key = addrkey.Key{Len: 16}
	t.root6.walk(&key, 0, fn)
}

// walk enumerates prefixes/leaves/children under n
// we poke the current octet into key, call fn, then restore it so the caller
// can keep using the same scratch buffer
func (n *node[V]) walk(key *addrkey.Key, depth int, fn func(netip.Prefix, V) bool) bool {
	if n.pfxCount != 0 {
		var buf [16]uint
		for _, idx := range n.pfx.bits.All(buf[:0]) {
			octet, pfxLen := art.IdxToPfx(idx)
			saved := key.Octets[depth]
			key.Octets[depth] = octet
			// decompose puts a length-b prefix at depth (b-1)/8 with stride
			// length in [1,8], so the total length is depth*8 + pfxLen
			pk := addrkey.PrefixKey{Key: *key, Bits: uint8(depth*8) + pfxLen}
			ok := fn(pk.Prefix(), n.pfx.values[n.pfx.bits.Rank0(idx)])
			key.Octets[depth] = saved
			if !ok {
				return false
			}
		}
	}
	if !n.leafBits.IsEmpty() {
		var lbuf [16]uint8
		for _, octet := range n.leafBits.All(lbuf[:0]) {
			lf := &n.leaves[n.leafBits.Rank0(uint(octet))]
			pk := addrkey.PrefixKey{Key: lf.key, Bits: lf.bits}
			if !fn(pk.Prefix(), lf.val) {
				return false
			}
		}
	}
	if n.childBits.IsEmpty() {
		return true
	}
	var cbuf [16]uint8
	for _, octet := range n.childBits.All(cbuf[:0]) {
		saved := key.Octets[depth]
		key.Octets[depth] = octet
		child := n.children[n.childBits.Rank0(uint(octet))]
		ok := child.walk(key, depth+1, fn)
		key.Octets[depth] = saved
		if !ok {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Slice helpers
// -----------------------------------------------------------------------------

// insertAt inserts v at position i, growing s by one
// append a zero then memmove the tail, classic insert-into-sorted-slice
func insertAt[T any](s []T, i int, v T) []T {
	var zero T
	s = append(s, zero)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

// deleteAt removes position i, shrinking s by one
// we clear the vacated tail slot so a pointer payload doesn't keep an object alive
func deleteAt[T any](s []T, i int) []T {
	var zero T
	copy(s[i:], s[i+1:])
	s[len(s)-1] = zero
	return s[:len(s)-1]
}
