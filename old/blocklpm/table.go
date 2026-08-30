// Package blocklpm is the leaf-pushed compiled FIB: /16-8-8 for v4, /16
// then 8-bit stride blocks for v6. Entries are a value index or a tagged
// next-block. This is what compiledfib wraps; we parked the raw compiler
// here so the managed table can import a stable snapshot builder
package blocklpm

import (
	"errors"
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

const fibNext = uint32(1 << 31)

var errTableFull = errors.New("compiled FIB has too many entries")

// Table is an immutable leaf-pushed forwarding index. IPv4 uses a /16-8-8
// layout. IPv6 uses a /16 root followed by full 8-bit stride blocks. Entries
// contain only a value index or a tagged next-block index. Fast reads,
// rebuild-on-write, which is why we manage it behind compiledfib
type Table[V any] struct {
	v4Root   [1 << 16]uint32
	v4Level2 []uint32
	v4Level3 []uint32
	v6Root   [1 << 16]uint32
	v6Blocks []uint32
	values   []V
}

// New compiles entries for maximum read speed. We normalise, stash payloads
// (last-wins via later overwrite during compile), sort shortest-first so
// leaf-push inherits covering values, then compile each family
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	t := &Table[V]{values: make([]V, 1, len(entries)+1)}
	v4 := make([]compiled4Entry, 0, len(entries))
	v6 := make([]compiled6Entry, 0, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		if len(t.values) == int(fibNext) {
			return nil, errTableFull
		}
		t.values = append(t.values, entry.Value)
		value := uint32(len(t.values) - 1)
		if prefix.Addr().Is4() {
			v4 = append(v4, compiled4Entry{prefixentry.Addr4(prefix.Addr()), uint8(prefix.Bits()), value})
		} else {
			hi, lo := prefixentry.Addr6(prefix.Addr())
			v6 = append(v6, compiled6Entry{hi, lo, uint8(prefix.Bits()), value})
		}
	}
	sort.SliceStable(v4, func(i, j int) bool { return v4[i].bits < v4[j].bits })
	sort.SliceStable(v6, func(i, j int) bool { return v6[i].bits < v6[j].bits })
	t.compile4(v4)
	t.compile6(v6)
	return t, nil
}

type compiled4Entry struct {
	key   uint32
	bits  uint8
	value uint32
}

// compile4 leaf-pushes IPv4 into the /16-8-8 arrays. Shortest first so a
// covering /8 fills the root, then longer prefixes punch holes and allocate
// L2/L3 blocks only where something actually goes deeper than /16 or /24
func (t *Table[V]) compile4(entries []compiled4Entry) {
	var inherited uint32
	need2 := make([]bool, 1<<16)
	need3 := make(map[uint32]struct{})
	for _, entry := range entries {
		bits := int(entry.bits)
		if bits == 0 {
			inherited = entry.value
			continue
		}
		if bits > 16 {
			need2[entry.key>>16] = true
		}
		if bits > 24 {
			need3[entry.key>>8] = struct{}{}
		}
	}
	for i := range t.v4Root {
		t.v4Root[i] = inherited
	}
	for _, entry := range entries {
		bits := int(entry.bits)
		if bits == 0 || bits > 16 {
			continue
		}
		start := entry.key >> 16
		count := uint32(1) << (16 - bits)
		for i := start; i < start+count; i++ {
			t.v4Root[i] = entry.value
		}
	}
	for key, needed := range need2 {
		if !needed {
			continue
		}
		block := uint32(len(t.v4Level2) >> 8)
		base := t.v4Root[key]
		for range 256 {
			t.v4Level2 = append(t.v4Level2, base)
		}
		t.v4Root[key] = fibNext | block
	}
	for _, entry := range entries {
		bits := int(entry.bits)
		if bits <= 16 || bits > 24 {
			continue
		}
		block := t.v4Root[entry.key>>16] &^ fibNext
		start := uint32(entry.key>>8) & 0xff
		count := uint32(1) << (24 - bits)
		base := block << 8
		for i := start; i < start+count; i++ {
			t.v4Level2[base+i] = entry.value
		}
	}
	for key24 := range need3 {
		root := t.v4Root[key24>>8]
		block2 := root &^ fibNext
		offset2 := key24 & 0xff
		index2 := block2<<8 | offset2
		block3 := uint32(len(t.v4Level3) >> 8)
		base := t.v4Level2[index2]
		for range 256 {
			t.v4Level3 = append(t.v4Level3, base)
		}
		t.v4Level2[index2] = fibNext | block3
	}
	for _, entry := range entries {
		bits := int(entry.bits)
		if bits <= 24 {
			continue
		}
		block2 := t.v4Root[entry.key>>16] &^ fibNext
		entry2 := t.v4Level2[block2<<8|entry.key>>8&0xff]
		block3 := entry2 &^ fibNext
		start := entry.key & 0xff
		count := uint32(1) << (32 - bits)
		base := block3 << 8
		for i := start; i < start+count; i++ {
			t.v4Level3[base+i] = entry.value
		}
	}
}

type compiled6Entry struct {
	hi, lo uint64
	bits   uint8
	value  uint32
}

type build6Node struct {
	child map[byte]*build6Node
	value uint32
}

// compile6 builds a pointer trie then flattens it into v6Root plus stride
// blocks. We expand the first two bytes into the /16 root so the hot path
// starts at stride 2. Pointer trie is throwaway
func (t *Table[V]) compile6(entries []compiled6Entry) {
	root := new(build6Node)
	for _, entry := range entries {
		insertCompiled6(root, entry)
	}
	for i := range t.v6Root {
		t.v6Root[i] = root.value
	}
	for i, child := range root.child {
		if child == nil {
			continue
		}
		inherited := root.value
		if child.value != 0 {
			inherited = child.value
		}
		for j := range 256 {
			key := int(i)<<8 | j
			t.v6Root[key] = compile6Slot(t, child.child[byte(j)], 2, inherited)
		}
	}
}

// insertCompiled6 walks/creates 8-bit strides in the throwaway trie
// Partial last octets get expanded into every covered child so leaf-push
// is just "write the value on those nodes"
func insertCompiled6(root *build6Node, entry compiled6Entry) {
	node := root
	full := int(entry.bits) / 8
	remaining := int(entry.bits) & 7
	for stride := 0; stride < full; stride++ {
		key := byte6(entry.hi, entry.lo, stride)
		if node.child == nil {
			node.child = make(map[byte]*build6Node)
		}
		if node.child[key] == nil {
			node.child[key] = new(build6Node)
		}
		node = node.child[key]
	}
	if remaining == 0 {
		node.value = entry.value
		return
	}
	start := int(byte6(entry.hi, entry.lo, full)) & (0xff << (8 - remaining))
	count := 1 << (8 - remaining)
	if node.child == nil {
		node.child = make(map[byte]*build6Node, count)
	}
	for i := start; i < start+count; i++ {
		key := byte(i)
		if node.child[key] == nil {
			node.child[key] = new(build6Node)
		}
		node.child[key].value = entry.value
	}
}

// compile6Slot flattens one stride: inherit the covering value, allocate a
// 256-slot block if there are children, recurse. Returns a value index or
// fibNext|block. Stops at stride 16 because that's a /128
func compile6Slot[V any](t *Table[V], node *build6Node, stride int, inherited uint32) uint32 {
	if node == nil {
		return inherited
	}
	if node.value != 0 {
		inherited = node.value
	}
	if len(node.child) == 0 || stride >= 16 {
		return inherited
	}
	block := uint32(len(t.v6Blocks) >> 8)
	for range 256 {
		t.v6Blocks = append(t.v6Blocks, inherited)
	}
	for i, child := range node.child {
		if child != nil {
			t.v6Blocks[block<<8|uint32(i)] = compile6Slot(t, child, stride+1, inherited)
		}
	}
	return fibNext | block
}

// byte6 pulls stride's octet from the 128-bit key. First 8 from hi, rest lo
func byte6(hi, lo uint64, stride int) byte {
	if stride < 8 {
		return byte(hi >> (56 - 8*stride))
	}
	return byte(lo >> (56 - 8*(stride-8)))
}

// Lookup performs an allocation-free forwarding lookup. Zone/invalid is a
// miss; then we dispatch on family
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		var zero V
		return zero, false
	}
	if addr.Is4() {
		return t.lookup4(prefixentry.Addr4(addr))
	}
	hi, lo := prefixentry.Addr6(addr)
	return t.lookup6(hi, lo)
}

// Lookup4 avoids netip decoding on an IPv4 hot path. One-liner onto lookup4
func (t *Table[V]) Lookup4(key uint32) (V, bool) { return t.lookup4(key) }

// lookup4 follows the /16-8-8 chain. High bit set means "go to that block";
// otherwise the slot is already a value index. At most two extra loads
func (t *Table[V]) lookup4(key uint32) (V, bool) {
	entry := t.v4Root[key>>16]
	if entry&fibNext != 0 {
		entry = t.v4Level2[(entry&^fibNext)<<8|key>>8&0xff]
		if entry&fibNext != 0 {
			entry = t.v4Level3[(entry&^fibNext)<<8|key&0xff]
		}
	}
	if entry != 0 {
		return t.values[entry], true
	}
	var zero V
	return zero, false
}

// Lookup6 avoids netip decoding on an IPv6 hot path
func (t *Table[V]) Lookup6(hi, lo uint64) (V, bool) { return t.lookup6(hi, lo) }

// lookup6 starts at the /16 root then follows tagged blocks by successive
// octets until we land on a value. Worst case is a lot of hops, which is
// why v6 tables with deep uniques get fat
func (t *Table[V]) lookup6(hi, lo uint64) (V, bool) {
	entry := t.v6Root[hi>>48]
	for stride := 2; entry&fibNext != 0 && stride < 16; stride++ {
		entry = t.v6Blocks[(entry&^fibNext)<<8|uint32(byte6(hi, lo, stride))]
	}
	if entry != 0 {
		return t.values[entry], true
	}
	var zero V
	return zero, false
}

// ForwardingBytes reports bytes in hot forwarding arrays, excluding payloads
// The number we quote when arguing about FIB size vs a pointer trie
func (t *Table[V]) ForwardingBytes() int {
	return 4 * (len(t.v4Root) + len(t.v4Level2) + len(t.v4Level3) + len(t.v6Root) + len(t.v6Blocks))
}
