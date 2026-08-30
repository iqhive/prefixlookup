package dirlpm

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/internal/flatart"
	"github.com/iqhive/prefixlookup/prefixentry"
)

const rootSlots = 1 << 16

// buildGeneration splits the catalogue by family and compiles each half
// v4 gets the expanded DIR tables, v6 gets the compressed arena
func buildGeneration[V any](catalog map[netip.Prefix]V, number uint64) (*generation[V], error) {
	var v4 []netip.Prefix
	var v6 []netip.Prefix
	for prefix := range catalog {
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	if len(v4) > maxSlot || len(v6) > maxSlot {
		return nil, ErrTooLarge
	}

	g := &generation[V]{number: number}
	if err := g.compile4(v4, catalog); err != nil {
		return nil, err
	}
	if err := g.compile6(v6, catalog); err != nil {
		return nil, err
	}
	return g, nil
}

// compile4 expands the IPv4 prefixes into a 16-bit root over 256-entry blocks
//
// we paint shortest-first so a longer prefix just overwrites the span a
// shorter one filled - a block is created only when something longer than
// its stride exists beneath it, and is initialised from the slot it
// replaces - that's how a covering route reaches every address under it
// without being stored more than once
func (g *generation[V]) compile4(prefixes []netip.Prefix, catalog map[netip.Prefix]V) error {
	// value indices are positions in the sorted exact-prefix array, so one
	// array answers Exact and carries the rebuild catalogue
	g.exact4 = make([]uint64, len(prefixes))
	for i, prefix := range prefixes {
		g.exact4[i] = packExact4(prefixentry.Addr4(prefix.Addr()), uint8(prefix.Bits()))
	}
	sort.Slice(g.exact4, func(i, j int) bool { return g.exact4[i] < g.exact4[j] })

	g.value4 = make([]V, len(prefixes)+1)
	for i, packed := range g.exact4 {
		g.value4[i+1] = catalog[unpackExact4(packed)]
	}
	if len(prefixes) == 0 {
		g.root4 = make([]uint32, rootSlots)
		return nil
	}

	// expansion order: shortest first - ties keep the sorted key order so
	// the build is deterministic, don't switch to an unstable sort
	order := make([]int, len(g.exact4))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return uint8(g.exact4[order[i]]) < uint8(g.exact4[order[j]])
	})

	g.root4 = make([]uint32, rootSlots)

	// /0../16 get painted straight into the root, no extra block
	position := 0
	for ; position < len(order); position++ {
		index := order[position]
		key, prefixBits := uint32(g.exact4[index]>>8), uint8(g.exact4[index])
		if prefixBits > 16 {
			break
		}
		value := uint32(index + 1)
		base := key >> 16
		for i := base; i < base+1<<(16-prefixBits); i++ {
			g.root4[i] = value
		}
	}

	// a /16 needs a level2 block when anything longer lives beneath it
	needLevel2 := make(map[uint32]struct{})
	needLevel3 := make(map[uint32]struct{})
	for _, index := range order[position:] {
		key, prefixBits := uint32(g.exact4[index]>>8), uint8(g.exact4[index])
		needLevel2[key>>16] = struct{}{}
		if prefixBits > 24 {
			needLevel3[key>>8] = struct{}{}
		}
	}

	g.level2 = make([]uint32, 0, blockSize*len(needLevel2))
	for _, key := range sortedKeys(needLevel2) {
		base := uint32(len(g.level2))
		if base >= tagBlock {
			return ErrTooLarge
		}
		// inherit the covering /16 (or shorter) so every slot starts with an answer
		inherited := g.root4[key]
		for range blockSize {
			g.level2 = append(g.level2, inherited)
		}
		g.root4[key] = tagBlock | base
	}

	// /17../24 fill spans of their /16's block
	for _, index := range order[position:] {
		key, prefixBits := uint32(g.exact4[index]>>8), uint8(g.exact4[index])
		if prefixBits > 24 {
			continue
		}
		base := g.root4[key>>16] &^ tagBlock
		start := (key >> 8) & 0xff
		value := uint32(index + 1)
		for i := start; i < start+1<<(24-prefixBits); i++ {
			g.level2[base+i] = value
		}
	}

	g.level3 = make([]uint32, 0, blockSize*len(needLevel3))
	for _, key24 := range sortedKeys(needLevel3) {
		base2 := g.root4[key24>>8] &^ tagBlock
		slot2 := base2 + key24&0xff
		base := uint32(len(g.level3))
		if base >= tagBlock {
			return ErrTooLarge
		}
		inherited := g.level2[slot2]
		for range blockSize {
			g.level3 = append(g.level3, inherited)
		}
		g.level2[slot2] = tagBlock | base
	}

	// /25../32 fill spans of their /24's block - sparse on a real table
	for _, index := range order[position:] {
		key, prefixBits := uint32(g.exact4[index]>>8), uint8(g.exact4[index])
		if prefixBits <= 24 {
			continue
		}
		base2 := g.root4[key>>16] &^ tagBlock
		base := g.level2[base2+(key>>8)&0xff] &^ tagBlock
		start := key & 0xff
		value := uint32(index + 1)
		for i := start; i < start+1<<(32-prefixBits); i++ {
			g.level3[base+i] = value
		}
	}
	return nil
}

// compile6 builds the compressed arena trie for IPv6
// expanding IPv6 the way IPv4 is expanded would need a block at four
// successive strides for a table dominated by /48, which is where the
// compressed form earns its keep
func (g *generation[V]) compile6(prefixes []netip.Prefix, catalog map[netip.Prefix]V) error {
	// sort so slot assignment is deterministic - not required for correctness
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr() != prefixes[j].Addr() {
			return prefixes[i].Addr().Less(prefixes[j].Addr())
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	builder := flatart.NewBuilder(flatart.Options{Exact: true})
	for i, prefix := range prefixes {
		if !builder.Insert(prefix, uint32(i+1)) {
			return prefixentry.ErrBadIP
		}
	}
	index, refOf, err := builder.Build()
	if err != nil {
		return err
	}
	g.index6 = *index
	g.value6 = make([]V, len(refOf))
	for slot, ref := range refOf {
		if ref != 0 {
			g.value6[slot] = catalog[prefixes[ref-1]]
		}
	}
	return nil
}

// sortedKeys is just so we allocate blocks in a stable order - maps aren't
func sortedKeys(set map[uint32]struct{}) []uint32 {
	keys := make([]uint32, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
