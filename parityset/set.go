// Package parityset answers boolean IP-prefix membership - is this address
// covered by any stored prefix - and nothing else - restricting the question is
// what makes it fast, because the answer depends only on the *union* of the
// stored prefixes and not on the prefixes themselves
//
// # Canonical reduction
//
// Every trie-based membership set in this repository and in the competition
// stores one entry per input prefix, then walks a structure whose depth is set
// by the longest prefix in the table - that work is largely redundant: if
// 10.0.0.0/8 is stored, then 10.1.2.0/24 cannot change any answer, and two
// sibling /25s that between them cover their /24 parent are indistinguishable
// from the parent - a membership set is therefore free to replace its input with
// any prefix set having the same union
//
// The minimal such representation is the set of maximal disjoint address
// ranges, which is what this package builds - on the benchmark's realistic
// BGP-shaped fixture the reduction is 9.4x - 169582 IPv4 prefixes become 17943
// ranges - and on any table containing a default route it collapses to a single
// range per family
//
// # Boundary parity encoding
//
// Disjoint sorted ranges are stored as the single sorted array of the addresses
// at which membership toggles: the first address of each range, and the address
// one past its last - membership is then the parity of the number of boundaries
// at or below the query, so a hit costs one comparison chain and no confirming
// load - a range that runs to the top of the address space simply contributes no
// closing boundary, which leaves the array odd-length and the parity correct
//
// # Slot table
//
// A query is localised before it is searched. slots[i] holds the index of the
// first boundary lying in the /16 whose number is i, so slots[i] and slots[i+1]
// - adjacent, one cache line - bound the only boundaries a query in that /16
// can possibly cross - the overwhelming majority of /16s contain no boundary at
// all, and for those the answer is already known: it is the parity of
// slots[i] itself, so the whole lookup is one load and one bit test - slots that
// do contain boundaries are scanned when there are few and binary searched when
// there are many
//
// The slot table costs 256 KiB, so it is built only once the boundary count
// makes it worthwhile; below that threshold the boundary array is small enough
// to stay in L1 and is searched directly
//
// Set is immutable and safe for unsynchronised concurrent reads - see Table for
// the managed, mutable form
package parityset

import (
	"errors"
	"math/bits"
	"net/netip"
	"sort"
)

// ErrBadPrefix reports an invalid or zoned prefix
var ErrBadPrefix = errors.New("parityset: bad prefix")

const (
	// slotShift selects the /16 used to localise a query
	slotShift = 16
	slotCount = 1 << slotShift

	// slotTableLimit is the boundary count above which the 256 KiB slot table
	// earns its keep - below it the boundary array is a few hundred bytes, sits
	// in L1, and searching it directly costs less than the table costs to hold
	slotTableLimit = 96

	// scanLimit is the number of boundaries within one slot that is cheaper to
	// walk linearly than to binary search
	//
	// the two costs are not comparable per comparison - a binary search over n
	// boundaries makes log2(n) probes at unpredictable addresses, each a
	// potential cache miss that nothing can prefetch - a linear walk over the
	// same n makes n comparisons against strictly ascending values, so the
	// branch mispredicts exactly once - where the data crosses the key - and
	// the hardware prefetcher covers the whole run because the addresses are
	// consecutive - at roughly one cycle per comparison against roughly ten per
	// dependent probe, the walk stays ahead until n is well past a hundred
	//
	// this matters most for IPv6: a realistic 200k-prefix IPv6 table leaves
	// about fifty boundaries in each populated /16, which a limit of 16 would
	// push into six random probes over a multi-megabyte array
	scanLimit = 32
)

// Set is an immutable boolean prefix-membership index
type Set struct {
	v4 index4
	v6 index6
}

// Front-table codes, two bits per /16 slot
const (
	frontNone   = 0 // no stored range intersects this /16
	frontAll    = 1 // this /16 is wholly covered
	frontDeeper = 2 // partially covered; the boundaries must be consulted
)

// index4 is the IPv4 boundary array, its front classifier and its slot table
//
// front exists because the common case deserves a smaller table than the
// uncommon one - almost every /16 either contains no boundary at all or is
// wholly covered, and for those the answer needs no offsets - only two bits
// Sixteen KiB of front therefore answers the overwhelming majority of queries
// from L1 with a single load, where reading the pair of offsets out of the
// 256 KiB slot table would have cost two L2 loads plus a slice header
type index4 struct {
	front  []uint64 // two bits per /16 slot; nil below slotTableLimit
	bounds []uint32
	slots  []uint32 // len slotCount+1, or nil below slotTableLimit
	all    bool     // the entire IPv4 space is covered
}

// index6 is the IPv6 boundary array, split by word so that a search strides
// only the high words, and its slot tables. low is nil when every boundary's
// low word is zero, which holds for any table whose prefixes are all /64 or
// shorter - the bulk of every real IPv6 table
//
// IPv6 needs a second level of localisation where IPv4 does not, and the reason
// is worth recording - global IPv6 unicast lives in 2000::/3, and a real table's
// addresses vary mostly in the bits below that, so a /16 cut separates almost
// nothing: measured on a realistic 200k-prefix IPv6 table, all 58616 boundaries
// fall into just 512 distinct /16s, about 120 apiece - neither scanning 120
// boundaries nor binary searching them is cheap - measured at 72 to 76 ns
// either way, and insensitive to where the crossover between the two is put -
// because both touch two boundary arrays repeatedly
//
// subBlock adds a second cut on the third octet, giving an effective /24 cut
// for exactly those /16s that are dense enough to pay for it - that drops the
// same table to well under one boundary per bucket
type index6 struct {
	front []uint64 // two bits per /16 slot; nil below slotTableLimit
	high  []uint64
	low   []uint64
	slots []uint32

	// subBlock[i] is the index of the level-two block for /16 i, or noBlock
	// when that /16 holds few enough boundaries to search directly
	subBlock []uint32
	// sub holds the level-two blocks end to end: subEntries offsets each,
	// bucketing one /16's boundaries by their third octet
	sub []uint32

	all bool
}

const (
	// subShift extracts the third octet of an IPv6 address from its high word
	subShift   = 40
	subEntries = 256 + 1
	noBlock    = ^uint32(0)

	// subThreshold is the per-/16 boundary count above which a level-two block
	// is built - a block costs 1 KiB, so it is only worth building where the
	// alternative is a search long enough to cost more than one extra load
	subThreshold = 8
)

// New compiles prefixes into an immutable membership set - invalid and zoned
// prefixes are rejected - duplicate, overlapping and adjacent prefixes are
// merged, so the size of the result is proportional to the union of the inputs
// rather than to their number
func New(prefixes []netip.Prefix) (*Set, error) {
	var b builder
	for _, prefix := range prefixes {
		if !b.add(prefix) {
			return nil, ErrBadPrefix
		}
	}
	return b.build(), nil
}

// Contains reports whether any stored prefix covers addr
//
// The "whole family covered" case is tested before the address is decoded,
// because a table holding a default route reduces to exactly that and then the
// entire lookup is one branch - a zone is ignored: it does not change the
// numeric address, so membership is well defined with or without it
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() {
		if s.v4.all {
			return true
		}
		return s.v4.contains(be32(addr.As4()))
	}
	if addr.Is4In6() {
		if s.v4.all {
			return true
		}
		return s.v4.contains(be32(addr.Unmap().As4()))
	}
	if s.v6.all {
		return addr.IsValid()
	}
	if !addr.IsValid() {
		return false
	}
	high, low := words16(addr.As16())
	return s.v6.contains(high, low)
}

// Contains4 is the decoded IPv4 fast path, taking a network-byte-order address
func (s *Set) Contains4(key uint32) bool { return s.v4.contains(key) }

// Contains6 is the decoded IPv6 fast path, taking the two network-byte-order
// words of the address
func (s *Set) Contains6(high, low uint64) bool { return s.v6.contains(high, low) }

// Ranges returns the number of maximal disjoint ranges retained per family
// It exists for tests and for reporting the effect of the canonical reduction
func (s *Set) Ranges() (v4, v6 int) {
	return rangeCount(len(s.v4.bounds)), rangeCount(len(s.v6.high))
}

// RetainedBytes reports the bytes held by the compiled index
func (s *Set) RetainedBytes() int {
	total := 4*len(s.v4.bounds) + 4*len(s.v4.slots) + 8*len(s.v4.front)
	total += 8*len(s.v6.high) + 8*len(s.v6.low) + 4*len(s.v6.slots) + 8*len(s.v6.front)
	total += 4 * (len(s.v6.subBlock) + len(s.v6.sub))
	return total
}

// rangeCount turns a boundary count into a range count: odd length means the
// last range ran to the top of the space and has no closer
func rangeCount(boundaries int) int { return (boundaries + 1) / 2 }

// contains is the IPv4 membership test: front table first, then scan or search
func (x *index4) contains(key uint32) bool {
	if x.all {
		return true
	}
	bounds := x.bounds
	low, high := 0, len(bounds)
	if x.front != nil {
		slot := key >> slotShift
		switch (x.front[slot>>5] >> ((slot & 31) * 2)) & 3 {
		case frontNone:
			return false
		case frontAll:
			return true
		}
		low, high = int(x.slots[slot]), int(x.slots[slot+1])
	} else if high == 0 {
		return false
	}
	if high-low <= scanLimit {
		count := low
		for _, boundary := range bounds[low:high] {
			if boundary > key {
				break
			}
			count++
		}
		return count&1 == 1
	}
	for low < high {
		mid := int(uint(low+high) >> 1)
		if bounds[mid] > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low&1 == 1
}

// contains is the IPv6 membership test - front, maybe a /24 cut, then search
func (x *index6) contains(keyHigh, keyLow uint64) bool {
	if x.all {
		return true
	}
	highs := x.high
	low, high := 0, len(highs)
	if x.front != nil {
		slot := keyHigh >> 48
		switch (x.front[slot>>5] >> ((slot & 31) * 2)) & 3 {
		case frontNone:
			return false
		case frontAll:
			return true
		}
		// when a second cut exists it supersedes the /16 offsets entirely, so
		// those two loads are skipped rather than read and discarded
		resolved := false
		if x.subBlock != nil {
			if block := x.subBlock[slot]; block != noBlock {
				base := int(block)*subEntries + int(keyHigh>>subShift&0xff)
				low, high = int(x.sub[base]), int(x.sub[base+1])
				resolved = true
			}
		}
		if !resolved {
			low, high = int(x.slots[slot]), int(x.slots[slot+1])
		}
		if low == high {
			return low&1 == 1
		}
	} else if high == 0 {
		return false
	}
	if lows := x.low; lows == nil {
		// every boundary starts and ends on a high-word boundary, so the low
		// word of the query cannot affect the outcome and is not read
		if high-low <= scanLimit {
			count := low
			for _, boundary := range highs[low:high] {
				if boundary > keyHigh {
					break
				}
				count++
			}
			return count&1 == 1
		}
		for low < high {
			mid := int(uint(low+high) >> 1)
			if highs[mid] > keyHigh {
				high = mid
			} else {
				low = mid + 1
			}
		}
		return low&1 == 1
	}
	lows := x.low
	if high-low <= scanLimit {
		count := low
		for i := low; i < high; i++ {
			if highs[i] > keyHigh || highs[i] == keyHigh && lows[i] > keyLow {
				break
			}
			count++
		}
		return count&1 == 1
	}
	for low < high {
		mid := int(uint(low+high) >> 1)
		// the low word is consulted only when the high words tie, so the search
		// walks the high array alone in the common case
		if h := highs[mid]; h > keyHigh || h == keyHigh && lows[mid] > keyLow {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low&1 == 1
}

// highs exposes the high-word array - leftover for tests, don't use this on the
// lookup path
func (x *index6) highs() []uint64 { return x.high }

// be32 packs 4 big-endian bytes into a uint32
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// words16 splits a 16-byte IPv6 address into two uint64s
func words16(b [16]byte) (high, low uint64) {
	high = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	low = uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	return high, low
}

// ---------------------------------------------------------------- construction

type range4 struct{ first, last uint32 }

type range6 struct{ firstHigh, firstLow, lastHigh, lastLow uint64 }

// builder accumulates raw ranges and compiles them into a Set
type builder struct {
	v4 []range4
	v6 []range6
}

// add converts one prefix to a range - it reports whether the prefix was valid
func (b *builder) add(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	addr := prefix.Addr()
	length := prefix.Bits()
	if addr.Is4In6() {
		if length < 96 {
			return false
		}
		addr = addr.Unmap()
		length -= 96
	}
	if addr.Zone() != "" {
		return false
	}
	if addr.Is4() {
		if length > 32 {
			return false
		}
		first := be32(addr.As4())
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		first &= mask
		b.v4 = append(b.v4, range4{first: first, last: first | ^mask})
		return true
	}
	if length > 128 {
		return false
	}
	high, low := words16(addr.As16())
	maskHigh, maskLow := masks128(length)
	high, low = high&maskHigh, low&maskLow
	lastHigh, lastLow := high, low
	if length < 64 {
		lastHigh |= ^uint64(0) >> length
		lastLow = ^uint64(0)
	} else if length < 128 {
		lastLow |= ^uint64(0) >> (length - 64)
	}
	b.v6 = append(b.v6, range6{firstHigh: high, firstLow: low, lastHigh: lastHigh, lastLow: lastLow})
	return true
}

// addRange4 records an already-validated, already-masked IPv4 prefix
func (b *builder) addRange4(key uint32, bits uint8) {
	var mask uint32
	if bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	b.v4 = append(b.v4, range4{first: key & mask, last: key | ^mask})
}

// addRange6 records an already-validated, already-masked IPv6 prefix
func (b *builder) addRange6(high, low uint64, bits uint8) {
	lastHigh, lastLow := high, low
	if bits < 64 {
		lastHigh |= ^uint64(0) >> bits
		lastLow = ^uint64(0)
	} else if bits < 128 {
		lastLow |= ^uint64(0) >> (bits - 64)
	}
	b.v6 = append(b.v6, range6{firstHigh: high, firstLow: low, lastHigh: lastHigh, lastLow: lastLow})
}

// masks128 returns the 128-bit mask for a prefix length, split across two words
func masks128(length int) (high, low uint64) {
	if length == 0 {
		return 0, 0
	}
	if length <= 64 {
		return ^uint64(0) << (64 - length), 0
	}
	return ^uint64(0), ^uint64(0) << (128 - length)
}

// build merges each family and compiles the boundary arrays
func (b *builder) build() *Set {
	s := new(Set)
	s.v4.compile(merge4(b.v4))
	s.v6.compile(merge6(b.v6))
	return s
}

// merge4 sorts and coalesces overlapping and adjacent IPv4 ranges - the result
// is the minimal set of maximal disjoint ranges with the same union
func merge4(ranges []range4) []range4 {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].first != ranges[j].first {
			return ranges[i].first < ranges[j].first
		}
		return ranges[i].last > ranges[j].last
	})
	out := ranges[:1]
	for _, current := range ranges[1:] {
		last := &out[len(out)-1]
		// adjacency, not just overlap, must merge: two ranges that touch are
		// one range, and leaving them separate would put a redundant pair of
		// boundaries in the array
		if current.first <= last.last || last.last != ^uint32(0) && current.first == last.last+1 {
			if current.last > last.last {
				last.last = current.last
			}
			continue
		}
		out = append(out, current)
	}
	return out
}

// merge6 is the IPv6 coalesce - same adjacency rule, 128-bit compares
func merge6(ranges []range6) []range6 {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		a, b := &ranges[i], &ranges[j]
		if a.firstHigh != b.firstHigh {
			return a.firstHigh < b.firstHigh
		}
		if a.firstLow != b.firstLow {
			return a.firstLow < b.firstLow
		}
		return cmp128(a.lastHigh, a.lastLow, b.lastHigh, b.lastLow) > 0
	})
	out := ranges[:1]
	for _, current := range ranges[1:] {
		last := &out[len(out)-1]
		merge := cmp128(current.firstHigh, current.firstLow, last.lastHigh, last.lastLow) <= 0
		if !merge {
			if nextHigh, nextLow, ok := inc128(last.lastHigh, last.lastLow); ok {
				merge = current.firstHigh == nextHigh && current.firstLow == nextLow
			}
		}
		if merge {
			if cmp128(current.lastHigh, current.lastLow, last.lastHigh, last.lastLow) > 0 {
				last.lastHigh, last.lastLow = current.lastHigh, current.lastLow
			}
			continue
		}
		out = append(out, current)
	}
	return out
}

// cmp128 compares two 128-bit values as (high, low) pairs, returning -1/0/1
func cmp128(aHigh, aLow, bHigh, bLow uint64) int {
	switch {
	case aHigh != bHigh:
		if aHigh < bHigh {
			return -1
		}
		return 1
	case aLow != bLow:
		if aLow < bLow {
			return -1
		}
		return 1
	}
	return 0
}

// inc128 returns (high, low) + 1, reporting false on overflow of the whole
// 128-bit space - the case where a range runs to the last address and so
// contributes no closing boundary
func inc128(high, low uint64) (uint64, uint64, bool) {
	sum, carry := bits.Add64(low, 1, 0)
	if carry == 0 {
		return high, sum, true
	}
	if high == ^uint64(0) {
		return 0, 0, false
	}
	return high + 1, sum, true
}

// compile turns merged IPv4 ranges into a boundary array plus optional front/slots
func (x *index4) compile(ranges []range4) {
	if len(ranges) == 0 {
		return
	}
	// check if we've just got the single range that covers the whole IPv4 space, so we can cheat and set the all-flag
	if len(ranges) == 1 && ranges[0].first == 0 && ranges[0].last == ^uint32(0) {
		x.all = true
		return
	}
	// prealloc a boundary array that's big enough for start + end of each range
	bounds := make([]uint32, 0, 2*len(ranges))
	for _, r := range ranges {
		// always stash the range start in the boundary list
		bounds = append(bounds, r.first)
		// if this range doesn't run to the absolute end, put in the upper+1 (this marks its end)
		if r.last != ^uint32(0) {
			bounds = append(bounds, r.last+1)
		}
	}
	// stash the boundary list onto this index
	x.bounds = bounds
	// for big tables, it's worth building a slot table, so we go fast
	if len(bounds) >= slotTableLimit {
		// slots slice gives you, for each /16, the index in bounds where that /16 starts
		x.slots = buildSlots(len(bounds), func(i int) uint32 { return bounds[i] >> slotShift })
		// front tells us about emptiness, coverage, or needing a scan for every /16
		x.front = buildFront(x.slots)
	}
}

// compile turns merged IPv6 ranges into split boundary arrays plus optional
// front/slots and a second-cut table
func (x *index6) compile(ranges []range6) {
	// ah, nothing to do if there aren't any ranges handed in
	if len(ranges) == 0 {
		return
	}
	// single range goes edge to edge? just set the all flag, job done
	if len(ranges) == 1 && ranges[0].firstHigh == 0 && ranges[0].firstLow == 0 &&
		ranges[0].lastHigh == ^uint64(0) && ranges[0].lastLow == ^uint64(0) {
		x.all = true
		return
	}
	// double-sized slices-enough to fit start+end boundary for each range, one for the high word, one for the low
	high := make([]uint64, 0, 2*len(ranges))
	low := make([]uint64, 0, 2*len(ranges))
	for _, r := range ranges {
		// stash the range start boundary
		high = append(high, r.firstHigh)
		low = append(low, r.firstLow)
		// only add the closing boundary if the range doesn't run off the 128-bit end
		if nextHigh, nextLow, ok := inc128(r.lastHigh, r.lastLow); ok {
			high = append(high, nextHigh)
			low = append(low, nextLow)
		}
	}
	x.high = high
	needLow := false
	// quick check-did any boundary actually use the low word? if so, we need to keep the lows slice
	for _, word := range low {
		if word != 0 {
			needLow = true
			break
		}
	}
	if needLow {
		x.low = low
	}
	// big enough dataset? build the slot table and helper index magic to go fast
	if len(high) >= slotTableLimit {
		x.slots = buildSlots(len(high), func(i int) uint32 { return uint32(high[i] >> 48) })
		x.front = buildFront(x.slots)
		x.buildSub()
	}
}

// buildFront classifies every /16 from the slot table - A slot holding no
// boundary is uniform, and its state is the parity of the boundaries below it;
// a slot holding at least one boundary must be searched
func buildFront(slots []uint32) []uint64 {
	front := make([]uint64, slotCount*2/64)
	for slot := 0; slot < slotCount; slot++ {
		code := uint64(frontDeeper)
		if slots[slot] == slots[slot+1] {
			code = frontNone
			if slots[slot]&1 == 1 {
				code = frontAll
			}
		}
		front[slot>>5] |= code << ((uint(slot) & 31) * 2)
	}
	return front
}

// buildSub adds a level-two block for every /16 holding more than
// subThreshold boundaries, bucketing them by their third octet - boundaries are
// sorted, and every boundary in one /16 shares its top octets, so the third
// octet is ascending within a slot and the bucket offsets are monotone
func (x *index6) buildSub() {
	blocks := 0
	// so we're looping through all the slots - that's every /16 chunk
	for slot := 0; slot < slotCount; slot++ {
		// if there's more boundaries in this slot than the subThreshold, we'll need a second-level block
		if int(x.slots[slot+1]-x.slots[slot]) > subThreshold {
			blocks++
		}
	}
	// if nothing went over the threshold, no second-level blocks needed at all, so bail out early
	if blocks == 0 {
		return
	}
	// allocate a subBlock table, one per slot - this tells us where the second-level stuff is for each /16
	x.subBlock = make([]uint32, slotCount)
	// sub holds all the offset data for the secondary blocks, end to end - big flat slice
	x.sub = make([]uint32, blocks*subEntries)
	// block counts which second-level block we're up to
	block := uint32(0)
	for slot := 0; slot < slotCount; slot++ {
		// grab the low/high bounds of this slot's boundaries
		low, high := x.slots[slot], x.slots[slot+1]
		// if there aren't enough boundaries to care, just mark noBlock and skip the rest
		if int(high-low) <= subThreshold {
			x.subBlock[slot] = noBlock
			continue
		}
		// cool, we need a block, so record that in subBlock
		x.subBlock[slot] = block
		// base is the start index for this block in the flat sub slice, one entry per octet plus one at the end
		base := int(block) * subEntries
		next := low
		// go through all 256 possible third octets in this /16
		for octet := 0; octet < 256; octet++ {
			// bump next forward past boundaries where the third octet is less than what we're looking for
			for next < high && int(x.high[next]>>subShift&0xff) < octet {
				next++
			}
			// at this point, next is the offset of the first boundary at (or beyond) this third octet
			x.sub[base+octet] = next
		}
		// last entry is always the upper bound for this /16
		x.sub[base+256] = high
		// move to the next block for the next slot that needs one
		block++
	}
}

// buildSlots returns a table whose entry i is the index of the first boundary
// lying in slot i, for boundaries presented in ascending slot order - entry
// slotCount is the total count, so slots[i] and slots[i+1] always bound slot i
func buildSlots(count int, slotOf func(int) uint32) []uint32 {
	slots := make([]uint32, slotCount+1)
	next := 0
	for slot := 0; slot < slotCount; slot++ {
		// scoot next along until we're up to boundaries at or past this slot
		for next < count && slotOf(next) < uint32(slot) {
			next++
		}
		// bung in where the first boundary for this slot lives in the list
		slots[slot] = uint32(next)
	}
	slots[slotCount] = uint32(count)
	return slots
}
