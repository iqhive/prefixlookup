package steplpm

import (
	"math/bits"
	"net/netip"
	"sort"
)

// route4 is one stored IPv4 prefix as a closed address range plus its route id
type route4 struct {
	first, last uint32
	id          uint32
}

// route6 is the IPv6 equivalent
type route6 struct {
	firstHigh, firstLow uint64
	lastHigh, lastLow   uint64
	id                  uint32
}

// Builder accumulates prefixes and compiles them into an Index - prefixes are
// deduplicated by their masked form; the last one added wins, matching the
// convention of every other index in this repository
type Builder struct {
	v4       []route4
	v6       []route6
	seen4    map[uint64]int // packed prefix -> position in v4
	seen6    map[key6]int
	nextID   uint32
	prefixes []netip.Prefix // route id (minus one) -> prefix, for callers
}

type key6 struct {
	high, low uint64
	bits      uint8
}

// NewBuilder returns an empty Builder with the duplicate maps already allocated
// We make the maps up front because Add is the common path and we'd pay the
// first-insert allocation anyway
func NewBuilder() *Builder {
	return &Builder{seen4: make(map[uint64]int), seen6: make(map[key6]int)}
}

// Add records a prefix and returns its route id - adding the same prefix twice
// returns the same id, so the caller's value vector stays dense
// We unmap 4-in-6, reject zones and over-length prefixes, then pack the masked
// key into seen4/seen6 so a second Add of the same prefix is a map hit
func (b *Builder) Add(prefix netip.Prefix) (uint32, error) {
	addr := prefix.Addr()
	length := prefix.Bits()
	if !prefix.IsValid() {
		return 0, ErrBadPrefix
	}
	if addr.Is4In6() {
		if length < 96 {
			return 0, ErrBadPrefix
		}
		addr = addr.Unmap()
		length -= 96
	}
	if addr.Zone() != "" {
		return 0, ErrBadPrefix
	}
	if b.nextID >= denseTag-1 {
		return 0, ErrTooManyRoutes
	}

	if addr.Is4() {
		if length > 32 {
			return 0, ErrBadPrefix
		}
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		first := be32(addr.As4()) & mask
		packed := uint64(first)<<8 | uint64(length)
		if at, ok := b.seen4[packed]; ok {
			// already have this masked prefix, reuse the id
			return b.v4[at].id, nil
		}
		b.nextID++
		id := b.nextID
		b.seen4[packed] = len(b.v4)
		// last is first with host bits set, closed range
		b.v4 = append(b.v4, route4{first: first, last: first | ^mask, id: id})
		b.prefixes = append(b.prefixes, netip.PrefixFrom(addr, length))
		return id, nil
	}

	if length > 128 {
		return 0, ErrBadPrefix
	}
	high, low := words16(addr.As16())
	maskHigh, maskLow := masks128(length)
	high, low = high&maskHigh, low&maskLow
	k := key6{high: high, low: low, bits: uint8(length)}
	if at, ok := b.seen6[k]; ok {
		return b.v6[at].id, nil
	}
	lastHigh, lastLow := high, low
	if length < 64 {
		// host bits span both words
		lastHigh |= ^uint64(0) >> length
		lastLow = ^uint64(0)
	} else if length < 128 {
		lastLow |= ^uint64(0) >> (length - 64)
	}
	b.nextID++
	id := b.nextID
	b.seen6[k] = len(b.v6)
	b.v6 = append(b.v6, route6{firstHigh: high, firstLow: low, lastHigh: lastHigh, lastLow: lastLow, id: id})
	b.prefixes = append(b.prefixes, netip.PrefixFrom(addr, length))
	return id, nil
}

// Routes returns the number of distinct prefixes added
func (b *Builder) Routes() int { return int(b.nextID) }

// Prefix returns the prefix that was assigned the given route id
// ids are 1-based so we look at prefixes[id-1], and 0 / out-of-range is empty
func (b *Builder) Prefix(id uint32) netip.Prefix {
	if id == 0 || int(id) > len(b.prefixes) {
		return netip.Prefix{}
	}
	return b.prefixes[id-1]
}

// Build compiles the accumulated prefixes into an immutable Index
// Sweep produces the step function, then each family localises it
func (b *Builder) Build() *Index {
	x := &Index{routes: int(b.nextID)}
	x.v4.compile(sweep4(b.v4))
	x.v6.compile(sweep6(b.v6))
	return x
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

// sweep4 turns nested prefix ranges into ascending, run-collapsed steps
//
// Any two prefixes are either disjoint or nested, so sorting by start ascending
// and end descending yields a preorder walk of the containment forest - a stack
// of the ranges currently covering the sweep position then gives the winner at
// every point: entering a range makes it the winner, and leaving one restores
// whatever encloses it
func sweep4(routes []route4) []step4 {
	if len(routes) == 0 {
		return nil
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].first != routes[j].first {
			return routes[i].first < routes[j].first
		}
		// equal starts: the wider range is the outer one and must come first
		return routes[i].last > routes[j].last
	})

	steps := make([]step4, 0, 2*len(routes)+1)
	emit := func(bound, id uint32) {
		if n := len(steps); n > 0 {
			if steps[n-1].bound == bound {
				// a more specific prefix starting at the same address wins
				steps[n-1].id = id
				return
			}
			if steps[n-1].id == id {
				return // run collapse: nothing changes here
			}
		} else if id == 0 {
			return
		}
		steps = append(steps, step4{bound: bound, id: id})
	}
	if routes[0].first != 0 {
		// no default covering 0, so the step function starts unmatched
		steps = append(steps, step4{bound: 0, id: 0})
	}

	stack := make([]route4, 0, 33)
	for _, r := range routes {
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if top.last >= r.first {
				break
			}
			stack = stack[:len(stack)-1]
			var id uint32
			if len(stack) > 0 {
				id = stack[len(stack)-1].id
			}
			emit(top.last+1, id) // top.last < r.first, so this cannot overflow
		}
		emit(r.first, r.id)
		stack = append(stack, r)
	}
	// drain whatever is still covering the top of the space
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		var id uint32
		if len(stack) > 0 {
			id = stack[len(stack)-1].id
		}
		if top.last != ^uint32(0) {
			emit(top.last+1, id)
		}
	}
	return steps
}

// sweep6 is the IPv6 stack sweep - same algorithm, 128-bit compares
func sweep6(routes []route6) []step6 {
	if len(routes) == 0 {
		return nil
	}
	sort.Slice(routes, func(i, j int) bool {
		a, b := &routes[i], &routes[j]
		if a.firstHigh != b.firstHigh {
			return a.firstHigh < b.firstHigh
		}
		if a.firstLow != b.firstLow {
			return a.firstLow < b.firstLow
		}
		// wider last-address first, same preorder trick as v4
		return cmp128(a.lastHigh, a.lastLow, b.lastHigh, b.lastLow) > 0
	})

	steps := make([]step6, 0, 2*len(routes)+1)
	emit := func(high, low uint64, id uint32) {
		if n := len(steps); n > 0 {
			if steps[n-1].high == high && steps[n-1].low == low {
				steps[n-1].id = id
				return
			}
			if steps[n-1].id == id {
				return
			}
		} else if id == 0 {
			return
		}
		steps = append(steps, step6{high: high, low: low, id: id})
	}
	if routes[0].firstHigh != 0 || routes[0].firstLow != 0 {
		steps = append(steps, step6{})
	}

	stack := make([]route6, 0, 129)
	for _, r := range routes {
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if cmp128(top.lastHigh, top.lastLow, r.firstHigh, r.firstLow) >= 0 {
				break
			}
			stack = stack[:len(stack)-1]
			var id uint32
			if len(stack) > 0 {
				id = stack[len(stack)-1].id
			}
			high, low, ok := inc128(top.lastHigh, top.lastLow)
			if ok {
				emit(high, low, id)
			}
		}
		emit(r.firstHigh, r.firstLow, r.id)
		stack = append(stack, r)
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		var id uint32
		if len(stack) > 0 {
			id = stack[len(stack)-1].id
		}
		if high, low, ok := inc128(top.lastHigh, top.lastLow); ok {
			emit(high, low, id)
		}
	}
	return steps
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

// inc128 returns (high, low)+1, or false if we'd wrap the whole 128-bit space
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

// ---------------------------------------------------------------- localisation

// compile builds the IPv4 localisation tables over a run-collapsed step array
// Uniform tables collapse to a single id with no level1; otherwise we pick 8
// or 16 bits of window, then hang a dense record (and maybe a second cut) off
// every non-uniform slot
func (x *index4) compile(steps []step4) {
	steps = rightSize4(steps)
	x.steps = steps
	if len(steps) == 0 {
		x.uniform = 0
		return
	}
	// a single step at address 0 means one id wins everywhere
	if len(steps) == 1 {
		x.uniform = steps[0].id
		x.steps = nil
		return
	}

	bits := chooseLevel1Bits(len(steps), func(i int) uint32 { return steps[i].bound >> 16 })
	x.level1Shift = 32 - bits
	shift := x.level1Shift
	count := 1 << bits
	slotOff := buildSlotOffsets(len(steps), count, func(i int) uint32 { return steps[i].bound >> shift })

	x.level1 = make([]uint32, count)
	for slot := 0; slot < count; slot++ {
		low, high := slotOff[slot], slotOff[slot+1]
		// the id winning at the first address of this slot is the one carried in
		// by the last step at or below it
		baseID := uint32(0)
		if low > 0 {
			baseID = steps[low-1].id
		}
		if low == high {
			x.level1[slot] = baseID // uniform slot, answered in one load
			continue
		}
		d := dense4{off: low, end: high, baseID: baseID, subBase: noBlock}
		if int(high-low) > subThreshold {
			// enough steps to pay for a second cut - pick the octet that spreads
			d.subShift = bestShift4(steps[low:high], shift-8)
			d.subBase = uint32(len(x.sub))
			x.sub = appendSubBlock(x.sub, int(low), int(high), baseID,
				func(i int) uint8 { return uint8(steps[i].bound >> d.subShift) },
				func(i int) uint32 { return steps[i].id })
		}
		x.level1[slot] = denseTag | uint32(len(x.dense))
		x.dense = append(x.dense, d)
	}
}

// compile is the IPv6 localisation, same shape as v4 but the window is the
// high word and the second cut only looks at that word
func (x *index6) compile(steps []step6) {
	steps = rightSize6(steps)
	x.steps = steps
	if len(steps) == 0 {
		x.uniform = 0
		return
	}
	if len(steps) == 1 {
		x.uniform = steps[0].id
		x.steps = nil
		return
	}

	bits := chooseLevel1Bits(len(steps), func(i int) uint32 { return uint32(steps[i].high >> 48) })
	x.level1Shift = 64 - bits
	shift := x.level1Shift
	count := 1 << bits
	slotOff := buildSlotOffsets(len(steps), count, func(i int) uint32 { return uint32(steps[i].high >> shift) })

	x.level1 = make([]uint32, count)
	for slot := 0; slot < count; slot++ {
		low, high := slotOff[slot], slotOff[slot+1]
		baseID := uint32(0)
		if low > 0 {
			baseID = steps[low-1].id
		}
		if low == high {
			x.level1[slot] = baseID
			continue
		}
		d := dense6{off: low, end: high, baseID: baseID, subBase: noBlock}
		if int(high-low) > subThreshold {
			d.subShift = bestShift6(steps[low:high], shift-8)
			d.subBase = uint32(len(x.sub))
			x.sub = appendSubBlock(x.sub, int(low), int(high), baseID,
				func(i int) uint8 { return uint8(steps[i].high >> d.subShift) },
				func(i int) uint32 { return steps[i].id })
		}
		x.level1[slot] = denseTag | uint32(len(x.dense))
		x.dense = append(x.dense, d)
	}
}

// minSeparatedSlots is the number of level-one slots a 16-bit index must
// actually separate to be worth its 256 KiB - below it the wide table is holding
// one dense record and 65535 copies of the same route id, and the narrower
// 8-bit index - one KiB - separates the data just as well, leaving the real work
// to the second cut either way
const minSeparatedSlots = 8

// chooseLevel1Bits returns the level-one width in bits, given a function
// yielding each step's 16-bit slot - we walk until we've seen enough distinct
// slots to justify 16 bits, otherwise we stick with 8
func chooseLevel1Bits(count int, slotOf func(int) uint32) uint8 {
	var seen int
	previous := ^uint32(0)
	for i := 0; i < count; i++ {
		if slot := slotOf(i); slot != previous {
			previous = slot
			seen++
			if seen >= minSeparatedSlots {
				return 16
			}
		}
	}
	return 8
}

// rightSize4 trims the sweep's over-allocation - the sweep reserves two steps
// per prefix because that is the worst case, but run collapsing typically uses
// far fewer, and the unused capacity is retained memory like any other
func rightSize4(steps []step4) []step4 {
	if cap(steps) <= len(steps)+len(steps)/8 {
		return steps
	}
	exact := make([]step4, len(steps))
	copy(exact, steps)
	return exact
}

// rightSize6 is the IPv6 trim - same 12.5% slack rule as v4
func rightSize6(steps []step6) []step6 {
	if cap(steps) <= len(steps)+len(steps)/8 {
		return steps
	}
	exact := make([]step6, len(steps))
	copy(exact, steps)
	return exact
}

// buildSlotOffsets returns a table whose entry i is the index of the first item
// lying in slot i, for items presented in ascending slot order
func buildSlotOffsets(count, slots int, slotOf func(int) uint32) []uint32 {
	offsets := make([]uint32, slots+1)
	next := 0
	for slot := 0; slot < slots; slot++ {
		for next < count && slotOf(next) < uint32(slot) {
			next++
		}
		offsets[slot] = uint32(next)
	}
	offsets[slots] = uint32(count)
	return offsets
}

// appendSubBlock buckets the steps in [low, high) by octetOf and appends the
// resulting block - steps are ascending, so the octet is ascending too and the
// offsets are monotone; each bucket records the id winning at its first address
func appendSubBlock(sub []subEntry, low, high int, baseID uint32,
	octetOf func(int) uint8, idOf func(int) uint32) []subEntry {
	base := len(sub)
	sub = append(sub, make([]subEntry, subEntries)...)
	next := low
	carried := baseID
	for octet := 0; octet < 256; octet++ {
		for next < high && int(octetOf(next)) < octet {
			carried = idOf(next)
			next++
		}
		sub[base+octet] = subEntry{off: uint32(next), id: carried}
	}
	sub[base+256] = subEntry{off: uint32(high), id: carried}
	return sub
}

// bestShift4 picks the octet below the /16 whose value spreads the steps most
// evenly, measured by the largest bucket it would leave
//
// Only shifts that order the steps consistently with their full-key order may
// be considered - bucketing by an octet is monotone - and so compatible with the
// offset table appendSubBlock builds - only when every octet between the /16 and
// the chosen one holds the same value across all of the slot's steps - cutting on
// the third octet of a slot whose second octet varies would interleave buckets
// and silently return the wrong route
func bestShift4(steps []step4, first uint8) uint8 {
	best, bestMax := first, len(steps)+1
	for shift := first; ; shift -= 8 {
		if shift != first && !constantOctet4(steps, shift+8) {
			break
		}
		var counts [256]int
		worst := 0
		for i := range steps {
			bucket := uint8(steps[i].bound >> shift)
			counts[bucket]++
			if counts[bucket] > worst {
				worst = counts[bucket]
			}
		}
		if worst < bestMax {
			best, bestMax = shift, worst
		}
		if shift == 0 {
			break
		}
	}
	return best
}

// constantOctet4 reports whether every step in the slice shares the same value
// in the octet selected by shift - that's the monotonicity gate for bestShift4
func constantOctet4(steps []step4, shift uint8) bool {
	first := uint8(steps[0].bound >> shift)
	for i := range steps {
		if uint8(steps[i].bound>>shift) != first {
			return false
		}
	}
	return true
}

// bestShift6 does the same across the octets of the high word below the /16
// Only the high word is considered: it covers prefixes down to /64, which is
// the overwhelming bulk of any real IPv6 table, and a step array dense enough
// to reach past it is rare enough to leave to the binary search
// Only monotone shifts are eligible; see bestShift4 for why
func bestShift6(steps []step6, first uint8) uint8 {
	best, bestMax := first, len(steps)+1
	for shift := first; ; shift -= 8 {
		if shift != first && !constantOctet6(steps, shift+8) {
			break
		}
		var counts [256]int
		worst := 0
		for i := range steps {
			bucket := uint8(steps[i].high >> shift)
			counts[bucket]++
			if counts[bucket] > worst {
				worst = counts[bucket]
			}
		}
		if worst < bestMax {
			best, bestMax = shift, worst
		}
		if shift == 0 {
			break
		}
	}
	return best
}

// constantOctet6 is the IPv6 monotonicity check, looking at the high word
func constantOctet6(steps []step6, shift uint8) bool {
	first := uint8(steps[0].high >> shift)
	for i := range steps {
		if uint8(steps[i].high>>shift) != first {
			return false
		}
	}
	return true
}
