// Package dirset is our boolean prefix-membership set tuned to the shape
// of a real BGP table
//
// membership specialist - two properties of a full table drive the design
// genPrefixes in fibbench now follows both, makeFixture does not
//
// IPv4 membership is decided at /24 - a collector's full table is 63% /24
// and only about one prefix in a thousand is longer, so almost every answer
// is already determined by the /24 an address falls in - we therefore keep
// a direct table of two bits per /24 - covered, not covered, or decided by
// longer prefixes - which is 4 MiB for the entire IPv4 space regardless of
// how many prefixes the table holds - an IPv4 query is one load, one shift
// and one mask, with no trie descent, no bitmask rank and no branch on
// prefix shape - the handful of /24s whose answer depends on longer prefixes
// fall through to a merged range array, which for a full table holds a
// couple of thousand entries and stays in cache
//
// the fixed 4 MiB is the trade: at a million prefixes it's under four bytes
// each, at a thousand it's four kilobytes each - pick flatset for small sets
// and this for large ones
//
// IPv6 stays compressed - a full table's IPv6 half occupies 66 of the 65536
// /16 blocks and is dominated by /48, so there's no equivalent level at
// which a direct table is affordable - it keeps the flatart arena trie
//
// both families short-circuit when their prefixes cover the whole address
// space, which is the common case for a table carrying a default route
package dirset

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/internal/flatart"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// front table codes, two bits per /24 slot
const (
	stateNone   = 0 // no address in this /24 is covered
	stateAll    = 1 // every address in this /24 is covered
	stateDeeper = 2 // some are, consult the longer-prefix ranges
)

const (
	frontSlots = 1 << 24 // one slot per IPv4 /24
	frontWords = frontSlots / 32
)

// Set is an immutable membership set over IPv4 and IPv6 prefixes
// lookups are allocation-free and safe for unsynchronised concurrent use
type Set struct {
	all4 bool
	all6 bool

	// front4 holds two bits per /24, nil when IPv4 is absent or fully covered
	front4 []uint64

	// deepFirst and deepLast are the merged address ranges covered by prefixes
	// longer than /24, consulted only for a /24 marked stateDeeper
	deepFirst []uint32
	deepLast  []uint32

	index6 *flatart.MemberIndex
}

// New compiles prefixes into a membership set
// we split by family up front so compile4 never sees a v6 prefix
func New(prefixes []netip.Prefix) (*Set, error) {
	var v4, v6 []netip.Prefix
	for _, input := range prefixes {
		prefix, ok := prefixentry.NormalizePrefix(input)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}

	s := new(Set)
	// IPv4 first, the 4 MiB table, then the compressed v6 arena
	s.compile4(v4)
	if err := s.compile6(v6); err != nil {
		return nil, err
	}
	return s, nil
}

// Contains reports whether any stored prefix covers addr
//
// the whole-space tests come before the address is decoded, because a table
// carrying a default route answers every query from them and decoding costs
// more than the answer does - don't reorder this, we measured it
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() {
		// all4 is the default-route / whole-space fast path
		return s.all4 || s.front4 != nil && s.lookup4(prefixentry.Addr4(addr))
	}
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	if addr.Is4In6() {
		// mapped v4 uses the v4 tables, same as native
		return s.all4 || s.front4 != nil && s.lookup4(prefixentry.Addr4(addr.Unmap()))
	}
	if s.all6 {
		return true
	}
	if s.index6 == nil {
		return false
	}
	hi, lo := prefixentry.Addr6(addr)
	return s.index6.Contains6(hi, lo)
}

// Contains4 is the decoded IPv4 fast path: one load from the /24 table
func (s *Set) Contains4(key uint32) bool {
	return s.all4 || s.front4 != nil && s.lookup4(key)
}

// lookup4 consults the /24 table
// callers have already excluded the fully covered and absent cases
func (s *Set) lookup4(key uint32) bool {
	slot := key >> 8
	switch s.front4[slot>>5] >> ((slot & 31) * 2) & 3 {
	case stateNone:
		return false
	case stateAll:
		return true
	}
	// stateDeeper: a handful of /25+ prefixes live under this /24
	return s.searchDeep(key)
}

// Contains6 is the decoded IPv6 fast path - all6 or the arena, that's it
func (s *Set) Contains6(hi, lo uint64) bool {
	return s.all6 || s.index6 != nil && s.index6.Contains6(hi, lo)
}

// searchDeep locates the last merged range starting at or below key and
// confirms the key against that range's end
// written out rather than delegated to sort.Search so the closure and its
// indirect call per probe are avoided on a path that a /24 marked
// stateDeeper always takes
func (s *Set) searchDeep(key uint32) bool {
	first := s.deepFirst
	low, high := 0, len(first)
	for low < high {
		// unsigned so we don't overflow on a huge table, we won't but still
		mid := int(uint(low+high) >> 1)
		if first[mid] > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	// predecessor range, key has to sit at or before its end
	return low > 0 && key <= s.deepLast[low-1]
}

// Bytes reports the retained size of the compiled set
// all4/all6 tables contribute nothing, that's the point of the short-circuit
func (s *Set) Bytes() int {
	total := 8*len(s.front4) + 4*(len(s.deepFirst)+len(s.deepLast))
	if s.index6 != nil {
		total += s.index6.Bytes()
	}
	return total
}

// compile4 paints the /24 front table shortest-first, then parks anything
// longer in the merged deep ranges - promoting a /24 that its own long
// prefixes happen to tile keeps those queries on the one-load path
func (s *Set) compile4(prefixes []netip.Prefix) {
	if len(prefixes) == 0 {
		return
	}

	// shortest first, so a longer prefix never has to undo a shorter one
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Bits() < prefixes[j].Bits() })

	front := make([]uint64, frontWords)
	split := len(prefixes)
	for i, prefix := range prefixes {
		if prefix.Bits() > 24 {
			split = i
			break
		}
		base := prefixentry.Addr4(prefix.Addr()) >> 8
		setRange(front, base, base+1<<(24-uint(prefix.Bits()))-1, stateAll)
	}

	// prefixes longer than /24 only matter where nothing shorter already
	// covers their /24
	deep := make([]addrRange, 0, len(prefixes)-split)
	for _, prefix := range prefixes[split:] {
		key := prefixentry.Addr4(prefix.Addr())
		if get(front, key>>8) == stateAll {
			continue
		}
		set(front, key>>8, stateDeeper)
		deep = append(deep, addrRange{key, key | ^prefixentry.IPv4Mask(prefix.Bits())})
	}
	deep = mergeRanges(deep)

	// a /24 whose longer prefixes happen to tile it is really fully covered
	// promoting it keeps those queries on the one-load path and lets the
	// whole-space check below see the coverage
	for i := range deep {
		firstSlot := (deep[i].first + 0xff) >> 8
		lastSlot := (deep[i].last + 1) >> 8
		for slot := firstSlot; slot < lastSlot; slot++ {
			set(front, slot, stateAll)
		}
	}

	if allCovered(front) {
		s.all4 = true
		return
	}
	s.front4 = front
	if len(deep) != 0 {
		s.deepFirst = make([]uint32, len(deep))
		s.deepLast = make([]uint32, len(deep))
		for i, r := range deep {
			s.deepFirst[i], s.deepLast[i] = r.first, r.last
		}
	}
}

// compile6 either marks the whole v6 space covered or builds a MemberIndex
// we don't expand v6, there's no /24 analogue that's affordable
func (s *Set) compile6(prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return nil
	}
	if coversIPv6(prefixes) {
		s.all6 = true
		return nil
	}
	builder := flatart.NewBuilder(flatart.Options{})
	for _, prefix := range prefixes {
		if !builder.Insert(prefix, 1) {
			return prefixentry.ErrBadIP
		}
	}
	index, err := builder.BuildMember()
	if err != nil {
		return err
	}
	s.index6 = index
	return nil
}

type addrRange struct{ first, last uint32 }

// mergeRanges collapses overlapping/adjacent ranges so searchDeep is one probe
func mergeRanges(ranges []addrRange) []addrRange {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	out := ranges[:1]
	for _, current := range ranges[1:] {
		last := &out[len(out)-1]
		adjacent := last.last != ^uint32(0) && current.first == last.last+1
		if current.first <= last.last || adjacent {
			if current.last > last.last {
				last.last = current.last
			}
			continue
		}
		out = append(out, current)
	}
	return out
}

// get reads two bits from the packed /24 table
func get(front []uint64, slot uint32) uint64 {
	return front[slot>>5] >> ((slot & 31) * 2) & 3
}

// set writes two bits into one /24 slot - used for the sparse deeper marks
func set(front []uint64, slot uint32, code uint64) {
	shift := (slot & 31) * 2
	front[slot>>5] = front[slot>>5]&^(3<<shift) | code<<shift
}

// setRange writes one code across an inclusive slot range, filling whole
// words directly where it can - a short prefix covers up to 2^24 slots, so
// the fast path matters at build time - don't replace this with a naive loop
func setRange(front []uint64, first, last uint32, code uint64) {
	repeated := uint64(0)
	for i := 0; i < 32; i++ {
		repeated |= code << (i * 2)
	}
	// lead: up to the next word boundary
	for first <= last && first&31 != 0 {
		set(front, first, code)
		if first == last {
			return
		}
		first++
	}
	for first+31 <= last {
		front[first>>5] = repeated
		first += 32
	}
	for first <= last {
		set(front, first, code)
		if first == last {
			return
		}
		first++
	}
}

// allCovered is the whole-space check: stateAll in every /24 slot
func allCovered(front []uint64) bool {
	const allWord = uint64(0x5555555555555555) // stateAll in every slot
	for _, word := range front {
		if word != allWord {
			return false
		}
	}
	return true
}

// coversIPv6 reports whether the prefixes tile the whole IPv6 space
// only prefixes at or shorter than /16 are considered: a tiling assembled
// purely from longer ones would need 2^17 or more of them and doesn't occur
func coversIPv6(prefixes []netip.Prefix) bool {
	var seen [(1 << 16) / 64]uint64
	for _, prefix := range prefixes {
		if prefix.Bits() > 16 {
			continue
		}
		hi, _ := prefixentry.Addr6(prefix.Addr())
		base := uint32(hi >> 48)
		for i := base; i < base+1<<(16-uint(prefix.Bits())); i++ {
			seen[i>>6] |= uint64(1) << (i & 63)
		}
	}
	for _, word := range seen {
		if word != ^uint64(0) {
			return false
		}
	}
	return true
}
