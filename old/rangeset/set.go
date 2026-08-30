// Package rangeset is the rangematch shrink: same merged-range membership,
// packed 2-bit /16 classifier, trimmed slices. We kept it for equivalence
// against rangematch; thinrangeset and soarangeset are the later splits
package rangeset

import (
	"cmp"
	"net/netip"
	"slices"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// Classifier codes, two bits per /16 slot
const (
	codeNone   = 0 // no range intersects this slot
	codeAll    = 1 // a range fully covers this slot
	codeDeeper = 2 // ranges intersect but none covers: fall back to search
)

type range4 struct{ first, last uint32 }
type range6 struct{ firstHi, firstLo, lastHi, lastLo uint64 }

// Set is an immutable boolean prefix set. It merges overlapping and adjacent
// prefixes into ranges, making memory proportional to their union
type Set struct {
	v4 []range4
	v6 []range6

	// front is the IPv4 classifier: 65536 /16 slots, two bits each, packed
	// into 64-bit words, 16 KiB total
	front [65536 * 2 / 64]uint64
}

// New compiles prefixes into a read-only membership set. Convert to inclusive
// ranges, merge, drop capacity slack, stamp the classifier. Fail on a bad
// prefix rather than silently skipping
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
			last := first | ^prefixentry.IPv4Mask(bits)
			t.v4 = append(t.v4, range4{first, last})
			continue
		}
		hi, lo := prefixentry.Addr6(prefix.Addr())
		lastHi, lastLo := hi, lo
		if bits < 64 {
			lastHi |= ^uint64(0) >> bits
			lastLo = ^uint64(0)
		} else if bits < 128 {
			lastLo |= ^uint64(0) >> (bits - 64)
		}
		t.v6 = append(t.v6, range6{hi, lo, lastHi, lastLo})
	}
	t.merge()
	t.v4 = exact4(t.v4)
	t.v6 = exact6(t.v6)
	t.buildFront()
	return t, nil
}

// exact4 drops the pre-merge capacity slack so the retained size is
// proportional to the merged ranges. No-op if we're already tight
func exact4(r []range4) []range4 {
	if len(r) == cap(r) {
		return r
	}
	out := make([]range4, len(r))
	copy(out, r)
	return out
}

// exact6 is exact4 for the 128-bit range structs
func exact6(r []range6) []range6 {
	if len(r) == cap(r) {
		return r
	}
	out := make([]range6, len(r))
	copy(out, r)
	return out
}

// getFront reads the two-bit code for the /16 slot containing key. Word
// index and shift fold out of the address bits so the decode is cheap
func (t *Set) getFront(key uint32) uint64 {
	return (t.front[key>>21] >> ((key & 0x1F0000) >> 15)) & 3
}

// setFront writes the two-bit code for a /16 slot. Mask-then-OR so we can
// overwrite, unlike soarangeset's build-from-zeros OR
func (t *Set) setFront(slot uint32, c uint64) {
	sh := (slot & 31) * 2
	t.front[slot>>5] = (t.front[slot>>5] &^ (3 << sh)) | (c << sh)
}

// merge sorts both range families and coalesces overlapping or adjacent
// ranges in place. slices.SortFunc so we don't pay the reflect swapper
func (t *Set) merge() {
	slices.SortFunc(t.v4, func(a, b range4) int {
		if c := cmp.Compare(a.first, b.first); c != 0 {
			return c
		}
		return cmp.Compare(a.last, b.last)
	})
	out4 := t.v4[:0]
	for _, current := range t.v4 {
		if len(out4) != 0 {
			last := &out4[len(out4)-1]
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

	slices.SortFunc(t.v6, func(a, b range6) int {
		if c := cmp.Compare(a.firstHi, b.firstHi); c != 0 {
			return c
		}
		return cmp.Compare(a.firstLo, b.firstLo)
	})
	out6 := t.v6[:0]
	for _, current := range t.v6 {
		if len(out6) != 0 {
			last := &out6[len(out6)-1]
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

// buildFront classifies every /16 slot by walking the merged v4 ranges and
// slots together in one linear sweep: both are sorted, so the range pointer
// only moves forward. Merged ranges are disjoint so one comparison decides
func (t *Set) buildFront() {
	r := 0
	for slot := uint32(0); slot < 65536; slot++ {
		first := slot << 16
		last := first | 0xffff
		for r < len(t.v4) && t.v4[r].last < first {
			r++
		}
		if r == len(t.v4) || t.v4[r].first > last {
			continue // none; the zero value is codeNone
		}
		if t.v4[r].first <= first && t.v4[r].last >= last {
			t.setFront(slot, codeAll)
		} else {
			t.setFront(slot, codeDeeper)
		}
	}
}

// Match reports whether addr is covered by at least one compiled prefix
// v4: classifier then sort.Search; v6: just the search. Closure-per-probe
// is the bit we later inlined
func (t *Set) Match(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	if addr.Is4() {
		key := prefixentry.Addr4(addr)
		switch t.getFront(key) {
		case codeNone:
			return false
		case codeAll:
			return true
		}
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].first > key }) - 1
		return i >= 0 && key <= t.v4[i].last
	}
	hi, lo := prefixentry.Addr6(addr)
	i := sort.Search(len(t.v6), func(i int) bool {
		return t.v6[i].firstHi > hi || t.v6[i].firstHi == hi && t.v6[i].firstLo > lo
	}) - 1
	return i >= 0 && (hi < t.v6[i].lastHi || hi == t.v6[i].lastHi && lo <= t.v6[i].lastLo)
}

// Ranges returns the number of merged ranges retained by the set
func (t *Set) Ranges() int { return len(t.v4) + len(t.v6) }
