// Package rangematch is our immutable "is this addr in the union?" set - we
// merge prefixes into ranges so memory tracks the union, not the input count
package rangematch

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// range4 is a closed IPv4 interval in host-order uint32s - we merge these
type range4 struct{ first, last uint32 }

// range6 is the v6 analogue as two uint64s so we can compare without netip
type range6 struct{ firstHi, firstLo, lastHi, lastLo uint64 }

// Set is an immutable boolean prefix set - we merge overlapping and adjacent
// prefixes into ranges, so retained memory is proportional to the union
type Set struct {
	v4      []range4
	v6      []range6
	v4Front [1 << 16]uint8
}

// New compiles prefixes into a read-only membership set - we normalise each
// one, expand it to a closed [first,last] range, then merge overlaps and
// stamp a /16 front table so Match can skip the binary search most of the time
func New(prefixes []netip.Prefix) (*Set, error) {
	t := &Set{}
	for _, input := range prefixes {
		prefix, ok := prefixentry.NormalizePrefix(input)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		bits := prefix.Bits()
		if prefix.Addr().Is4() {
			first := prefixentry.Addr4(prefix.Addr())
			// last = first with host bits all ones (mask inverted)
			last := first | ^prefixentry.IPv4Mask(bits)
			t.v4 = append(t.v4, range4{first, last})
			continue
		}
		hi, lo := prefixentry.Addr6(prefix.Addr())
		lastHi, lastLo := hi, lo
		if bits < 64 {
			// host bits spill into both words - hi gets the rest, lo is all ones
			lastHi |= ^uint64(0) >> bits
			lastLo = ^uint64(0)
		} else if bits < 128 {
			lastLo |= ^uint64(0) >> (bits - 64)
		}
		t.v6 = append(t.v6, range6{hi, lo, lastHi, lastLo})
	}
	t.merge()
	t.buildFront()
	return t, nil
}

// buildFront classifies every IPv4 /16 as empty / fully covered / mixed so
// Match can return without a search - we binary-search for an overlapping
// range and stamp 1 if it swallows the whole block, else 2
func (t *Set) buildFront() {
	for key := uint32(0); key < 1<<16; key++ {
		first, last := key<<16, key<<16|0xffff
		// first range whose last is still >= this /16's start
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].last >= first })
		if i == len(t.v4) || t.v4[i].first > last {
			continue
		}
		t.v4Front[key] = 2 // mixed until we prove this range swallows the whole /16
		if t.v4[i].first <= first && t.v4[i].last >= last {
			t.v4Front[key] = 1
		}
	}
}

// merge collapses overlapping and adjacent ranges so we don't keep more
// intervals than the union actually needs - sort by first then linear scan
// compacting in place (the classic interval-union sweep)
func (t *Set) merge() {
	// lowest first so the sweep only looks at the previous interval
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].first < t.v4[j].first })
	out4 := t.v4[:0]
	for _, current := range t.v4 {
		if len(out4) != 0 {
			last := &out4[len(out4)-1]
			// overlap, or adjacent (watch the all-ones wrap so last+1 doesn't overflow)
			if current.first <= last.last || (last.last != ^uint32(0) && current.first == last.last+1) {
				if current.last > last.last {
					last.last = current.last
				}
				continue
			}
		}
		out4 = append(out4, current)
	}
	t.v4 = out4

	// v6: sort by (firstHi, firstLo), same sweep
	sort.Slice(t.v6, func(i, j int) bool {
		return t.v6[i].firstHi < t.v6[j].firstHi || t.v6[i].firstHi == t.v6[j].firstHi && t.v6[i].firstLo < t.v6[j].firstLo
	})
	out6 := t.v6[:0]
	for _, current := range t.v6 {
		if len(out6) != 0 {
			last := &out6[len(out6)-1]
			// adjacent on the low word, unless lastLo is max then we wrap into lastHi+1
			adjacent := last.lastLo != ^uint64(0) && current.firstHi == last.lastHi && current.firstLo == last.lastLo+1
			if last.lastLo == ^uint64(0) && last.lastHi != ^uint64(0) {
				adjacent = current.firstHi == last.lastHi+1 && current.firstLo == 0
			}
			overlaps := current.firstHi < last.lastHi || current.firstHi == last.lastHi && current.firstLo <= last.lastLo
			if overlaps || adjacent {
				if current.lastHi > last.lastHi || current.lastHi == last.lastHi && current.lastLo > last.lastLo {
					last.lastHi, last.lastLo = current.lastHi, current.lastLo
				}
				continue
			}
		}
		out6 = append(out6, current)
	}
	t.v6 = out6
}

// Match reports whether addr is covered by at least one compiled prefix - v4
// consults v4Front then binary-searches the predecessor range; v6 is search
// only (no /16 table, the space is too sparse to bother)
func (t *Set) Match(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		// zoned / invalid - we don't want As4 to panic
		return false
	}
	if addr.Is4() {
		key := prefixentry.Addr4(addr)
		switch t.v4Front[key>>16] {
		case 0:
			// this /16 is empty
			return false
		case 1:
			// whole /16 is covered, no need to search
			return true
		}
		// predecessor: last range with first <= key, then check last
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].first > key }) - 1
		return i >= 0 && key <= t.v4[i].last
	}
	hi, lo := prefixentry.Addr6(addr)
	// predecessor in the (hi,lo) order, then test against lastHi/lastLo
	i := sort.Search(len(t.v6), func(i int) bool {
		return t.v6[i].firstHi > hi || t.v6[i].firstHi == hi && t.v6[i].firstLo > lo
	}) - 1
	return i >= 0 && (hi < t.v6[i].lastHi || hi == t.v6[i].lastHi && lo <= t.v6[i].lastLo)
}

// Ranges counts merged v4+v6 intervals after union - just the two slice lengths
func (t *Set) Ranges() int { return len(t.v4) + len(t.v6) }
