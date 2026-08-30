// Package soarangeset is the "split the range words, pack a /16 front table"
// membership set. Immutable, merged ranges, zero-alloc lookups. We kept
// it as a building block; thinrangeset is the version that actually
// bothers to elide empty low-words and skip the 16 KiB table on tiny sets
package soarangeset

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type range4 struct{ first, last uint32 }
type range6 struct{ firstHi, firstLo, lastHi, lastLo uint64 }

type Set struct {
	v4First []uint32
	v4Last  []uint32
	v6First []uint64
	v6Last  []uint64
	v4Front []uint64
}

// New compiles prefixes into a read-only membership set. Normalise, convert
// each prefix to an inclusive range, merge overlaps/adjacents, split into
// start/end arrays, then (if we have any v4) stamp a packed /16 classifier
func New(prefixes []netip.Prefix) (*Set, error) {
	var v4 []range4
	var v6 []range6
	for _, input := range prefixes {
		prefix, ok := prefixentry.NormalizePrefix(input)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		prefixBits := prefix.Bits()
		if prefix.Addr().Is4() {
			first := prefixentry.Addr4(prefix.Addr())
			v4 = append(v4, range4{first, first | ^prefixentry.IPv4Mask(prefixBits)})
			continue
		}
		hi, lo := prefixentry.Addr6(prefix.Addr())
		lastHi, lastLo := hi, lo
		if prefixBits < 64 {
			lastHi |= ^uint64(0) >> prefixBits
			lastLo = ^uint64(0)
		} else if prefixBits < 128 {
			lastLo |= ^uint64(0) >> (prefixBits - 64)
		}
		v6 = append(v6, range6{hi, lo, lastHi, lastLo})
	}
	v4 = merge4(v4)
	v6 = merge6(v6)
	t := &Set{}
	t.compact(v4, v6)
	if len(v4) != 0 {
		t.v4Front = make([]uint64, 65536*2/64)
		t.buildFront(v4)
	}
	return t, nil
}

// compact copies merged ranges into split start/end arrays. v6 is interleaved
// hi/lo pairs so a binary search strides 16 bytes of "first" instead of a
// 32-byte struct. We later split this further in thinrangeset
func (t *Set) compact(v4 []range4, v6 []range6) {
	if len(v4) != 0 {
		t.v4First = make([]uint32, len(v4))
		t.v4Last = make([]uint32, len(v4))
		for i, r := range v4 {
			t.v4First[i], t.v4Last[i] = r.first, r.last
		}
	}
	if len(v6) != 0 {
		t.v6First = make([]uint64, len(v6)*2)
		t.v6Last = make([]uint64, len(v6)*2)
		for i, r := range v6 {
			t.v6First[i*2], t.v6First[i*2+1] = r.firstHi, r.firstLo
			t.v6Last[i*2], t.v6Last[i*2+1] = r.lastHi, r.lastLo
		}
	}
}

// getFront reads the two-bit code for a /16 slot. Packed 32 slots per word
func (t *Set) getFront(slot uint32) uint64 {
	return (t.v4Front[slot>>5] >> ((slot & 31) * 2)) & 3
}

// setFront writes the two-bit code for a /16 slot. OR-only because we build
// from zeros; don't reuse this for updates
func (t *Set) setFront(slot uint32, code uint64) {
	shift := (slot & 31) * 2
	t.v4Front[slot>>5] |= code << shift
}

// buildFront classifies every /16 in one sweep over the merged ranges
// 0 = none, 1 = wholly covered, 2 = partial (caller must search)
func (t *Set) buildFront(v4 []range4) {
	rangeIndex := 0
	for slot := uint32(0); slot < 1<<16; slot++ {
		first, last := slot<<16, slot<<16|0xffff
		for rangeIndex < len(v4) && v4[rangeIndex].last < first {
			rangeIndex++
		}
		if rangeIndex == len(v4) || v4[rangeIndex].first > last {
			continue
		}
		code := uint64(2)
		if v4[rangeIndex].first <= first && v4[rangeIndex].last >= last {
			code = 1
		}
		t.setFront(slot, code)
	}
}

// merge4 sorts by start then coalesces overlapping or adjacent IPv4 ranges
// in place. Adjacent means last+1 without wrapping past ^uint32(0)
func merge4(ranges []range4) []range4 {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	out := ranges[:0]
	for _, current := range ranges {
		if len(out) != 0 {
			last := &out[len(out)-1]
			if current.first <= last.last || last.last != ^uint32(0) && current.first == last.last+1 {
				if current.last > last.last {
					last.last = current.last
				}
				continue
			}
		}
		out = append(out, current)
	}
	return out
}

// merge6 is merge4 for 128-bit bounds. Adjacent has to handle the lo-word
// wrapping into hi, which is the usual 128-bit headache
func merge6(ranges []range6) []range6 {
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].firstHi < ranges[j].firstHi || ranges[i].firstHi == ranges[j].firstHi && ranges[i].firstLo < ranges[j].firstLo
	})
	out := ranges[:0]
	for _, current := range ranges {
		if len(out) != 0 {
			last := &out[len(out)-1]
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
		out = append(out, current)
	}
	return out
}

// Match reports whether addr is covered by at least one compiled prefix
// v4 consults the front table then binary-searches; v6 is just the search
// sort.Search plus a confirming load - we later inlined this in thinrangeset
func (t *Set) Match(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	if addr.Is4() {
		if len(t.v4Front) == 0 {
			return false
		}
		key := prefixentry.Addr4(addr)
		switch t.getFront(key >> 16) {
		case 0:
			return false
		case 1:
			return true
		}
		i := sort.Search(len(t.v4First), func(i int) bool { return t.v4First[i] > key }) - 1
		return i >= 0 && key <= t.v4Last[i]
	}
	hi, lo := prefixentry.Addr6(addr)
	count := len(t.v6First) / 2
	i := sort.Search(count, func(i int) bool {
		return t.v6First[i*2] > hi || t.v6First[i*2] == hi && t.v6First[i*2+1] > lo
	}) - 1
	return i >= 0 && (hi < t.v6Last[i*2] || hi == t.v6Last[i*2] && lo <= t.v6Last[i*2+1])
}

// Ranges returns the number of merged ranges retained. After merge this is
// the union, not the input count
func (t *Set) Ranges() int { return len(t.v4First) + len(t.v6First)/2 }
