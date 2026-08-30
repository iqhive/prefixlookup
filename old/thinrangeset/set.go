// Package thinrangeset is soarangeset with the memory trims we actually
// wanted: split v6 words, elide all-zero low words, and skip the 16 KiB
// classifier on tiny v4 sets. Still immutable merged-range membership
// We kept it as the range-set building block; lookup shape is the same
package thinrangeset

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// frontThreshold is the number of merged IPv4 ranges above which the 16 KiB
// classifier earns its keep. Below it the range arrays sit in L1 anyway
const frontThreshold = 64

type range4 struct{ first, last uint32 }
type range6 struct{ firstHi, firstLo, lastHi, lastLo uint64 }

// Set is an immutable boolean prefix set. Overlapping and adjacent prefixes
// are merged, so size tracks the union rather than the input count
type Set struct {
	// v4 lookup fields sit together so a query touches fewer header lines
	v4First []uint32
	v4Last  []uint32
	// v4Front is the packed /16 classifier, two bits per slot. Nil when
	// the range count doesn't justify 16 KiB
	v4Front []uint64

	// v6 ranges split by word so the search strides only the high words
	// FirstLo and LastLo are nil when every low word is zero
	v6FirstHi []uint64
	v6FirstLo []uint64
	v6LastHi  []uint64
	v6LastLo  []uint64
}

// Front table codes, two bits per /16 slot
const (
	frontNone   = 0 // no range intersects this /16
	frontAll    = 1 // this /16 is wholly covered
	frontDeeper = 2 // partially covered; consult the ranges
)

// New compiles prefixes into a read-only membership set. Normalise, convert
// to inclusive ranges, merge, compact into split arrays, then maybe stamp
// the classifier if we've got enough v4 ranges to care
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
	t.compact4(v4)
	t.compact6(v6)
	if len(v4) >= frontThreshold {
		t.v4Front = make([]uint64, 65536*2/64)
		t.buildFront(v4)
	}
	return t, nil
}

// compact4 copies merged IPv4 ranges into split start and end arrays so
// the search only touches the starts
func (t *Set) compact4(ranges []range4) {
	if len(ranges) == 0 {
		return
	}
	t.v4First = make([]uint32, len(ranges))
	t.v4Last = make([]uint32, len(ranges))
	for i, r := range ranges {
		t.v4First[i], t.v4Last[i] = r.first, r.last
	}
}

// compact6 copies merged IPv6 ranges into per-word arrays, dropping the low
// words when every one of them is zero. That's most real tables (/64s)
func (t *Set) compact6(ranges []range6) {
	if len(ranges) == 0 {
		return
	}
	firstHi := make([]uint64, len(ranges))
	lastHi := make([]uint64, len(ranges))
	firstLo := make([]uint64, len(ranges))
	lastLo := make([]uint64, len(ranges))
	needLow := false
	for i, r := range ranges {
		firstHi[i], lastHi[i] = r.firstHi, r.lastHi
		firstLo[i], lastLo[i] = r.firstLo, r.lastLo
		if r.firstLo != 0 || r.lastLo != ^uint64(0) {
			// a start with a non-zero low word, or an end that stops short of
			// the top of its high word, can only be resolved with the low words
			needLow = true
		}
	}
	t.v6FirstHi, t.v6LastHi = firstHi, lastHi
	if needLow {
		t.v6FirstLo, t.v6LastLo = firstLo, lastLo
	}
}

// getFront reads the two-bit code for a /16 slot. Packed 32 slots per word
func (t *Set) getFront(slot uint32) uint64 {
	return (t.v4Front[slot>>5] >> ((slot & 31) * 2)) & 3
}

// setFront writes the two-bit code for a /16 slot. OR-only; we build from zeros
func (t *Set) setFront(slot uint32, code uint64) {
	t.v4Front[slot>>5] |= code << ((slot & 31) * 2)
}

// buildFront classifies every /16 in a single sweep over the merged ranges
// Same 0/1/2 codes as the other range sets
func (t *Set) buildFront(ranges []range4) {
	index := 0
	for slot := uint32(0); slot < 1<<16; slot++ {
		first, last := slot<<16, slot<<16|0xffff
		for index < len(ranges) && ranges[index].last < first {
			index++
		}
		if index == len(ranges) || ranges[index].first > last {
			continue
		}
		code := uint64(frontDeeper)
		if ranges[index].first <= first && ranges[index].last >= last {
			code = frontAll
		}
		t.setFront(slot, code)
	}
}

// merge4 sorts by start then coalesces overlapping or adjacent IPv4 ranges
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

// merge6 is merge4 for 128-bit bounds, including lo wrapping into hi
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
// Mapped v4-in-v6 is unmapped onto the v4 arrays. Classifier first when
// present, then the inlined search so Match stays inlinable itself
func (t *Set) Match(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	if addr.Is4() || addr.Is4In6() {
		key := prefixentry.Addr4(addr.Unmap())
		if t.v4Front != nil {
			// the classifier decides the overwhelming majority of queries from
			// L1, so we test it here rather than inside the search
			switch t.getFront(key >> 16) {
			case frontNone:
				return false
			case frontAll:
				return true
			}
		}
		return t.search4(key)
	}
	hi, lo := prefixentry.Addr6(addr)
	return t.match6(hi, lo)
}

// search4 locates the last range starting at or below key and confirms the
// key against that range's end. Written out rather than sort.Search so we
// don't pay a closure call per probe and so Match can inline this
func (t *Set) search4(key uint32) bool {
	first := t.v4First
	low, high := 0, len(first)
	for low < high {
		mid := int(uint(low+high) >> 1)
		if first[mid] > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low > 0 && key <= t.v4Last[low-1]
}

// match6 is the IPv6 analogue of search4. When every low word is zero we
// skip those comparisons entirely and the search reads only the high array
func (t *Set) match6(hi, lo uint64) bool {
	firstHi := t.v6FirstHi
	if len(firstHi) == 0 {
		return false
	}
	low, high := 0, len(firstHi)
	if firstLo := t.v6FirstLo; firstLo != nil {
		for low < high {
			mid := int(uint(low+high) >> 1)
			// the low word is consulted only when the high words tie
			h := firstHi[mid]
			if h > hi || h == hi && firstLo[mid] > lo {
				high = mid
			} else {
				low = mid + 1
			}
		}
		if low == 0 {
			return false
		}
		lastHi := t.v6LastHi[low-1]
		return hi < lastHi || hi == lastHi && lo <= t.v6LastLo[low-1]
	}
	// every range starts on a high-word boundary and runs to the end of a high
	// word, so the low word of the query cannot affect the outcome
	for low < high {
		mid := int(uint(low+high) >> 1)
		if firstHi[mid] > hi {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low > 0 && hi <= t.v6LastHi[low-1]
}

// Ranges returns the number of merged ranges retained by the set
func (t *Set) Ranges() int { return len(t.v4First) + len(t.v6FirstHi) }
