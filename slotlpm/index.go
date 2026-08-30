// Package slotlpm is steplpm with its localisation layer rebuilt to knock one
// dependent load off the lookup path
//
// # What changed and why
//
// steplpm indexes the top sixteen bits into a four-byte entry that is either a
// route id - the whole /16 has one winner - or a tag pointing at a dense record
// holding the /16's step range - measured against compiled-fib, that cost it four
// of the seven benchmarks, all of them tables whose prefixes are spread across
// the address space rather than clustered - the reason is visible in the shape of
// such a table: a realistic 200k-prefix IPv4 table leaves 54885 of its /16s
// non-uniform, so almost every query paid the dense indirection, giving a chain
// of level1, dense, steps and values where compiled-fib needs only root, block
// and values
//
// Here the level-one entry is eight bytes and carries the step range inline:
//
//	off - the index of the first step inside this /16
//	id  - the route id winning at the /16's first address
//
// The offsets are monotone across slots, so the end of a slot's range is simply
// the next slot's off, and the two entries are adjacent - the same cache line
// seven times in eight - a uniform /16 is then off == nextOff, answered from that
// one line; a non-uniform /16 reads its steps directly - nothing consults a dense
// record unless the /16 was dense enough to warrant a second cut, which on that
// same table was 1326 slots out of 54885
//
// The cost is four extra bytes per level-one slot, and the saving is the entire
// dense array - which on a spread table was over a megabyte, more than the
// widened table costs - only a clustered table, whose level-one array is mostly
// idle anyway, pays a net increase
//
// Index is immutable and safe for unsynchronised concurrent reads
package slotlpm

import (
	"errors"
	"net/netip"
)

// ErrBadPrefix reports an invalid or zoned prefix
var ErrBadPrefix = errors.New("slotlpm: bad prefix")

// ErrTooManyRoutes reports a table larger than the route-id space
var ErrTooManyRoutes = errors.New("slotlpm: too many routes")

const (
	// denseTag marks a level-one id field as an index into dense rather than a
	// route id, limiting route ids to 2^31-1
	denseTag = uint32(1) << 31

	noBlock = ^uint32(0)

	subEntries = 256 + 1

	// subThreshold is the step count within one slot above which a second cut
	// is built
	subThreshold = 12

	// scanLimit is the step count cheaper to walk than to binary search
	scanLimit = 32
)

// step4 is one run of the IPv4 step function: from bound onward, id wins
type step4 struct {
	bound uint32
	id    uint32
}

// step6 is the IPv6 equivalent
type step6 struct {
	high, low uint64
	id        uint32
}

// slotEntry is one level-one slot: where its steps begin, and the winner at its
// first address - when id has denseTag set it indexes dense instead, which only
// happens for slots carrying a second cut
type slotEntry struct {
	off uint32
	id  uint32
}

// subEntry bounds one second-cut bucket and carries the id winning at its start
type subEntry struct {
	off uint32
	id  uint32
}

// dense holds the extra state a slot with a second cut needs
type dense struct {
	baseID   uint32
	subBase  uint32
	subShift uint8
}

type index4 struct {
	slots   []slotEntry // len (1<<bits)+1; nil when the table is uniform
	shift   uint8
	dense   []dense
	sub     []subEntry
	steps   []step4
	uniform uint32
}

// index6 splits its steps into parallel arrays - a struct of two uint64 words
// and a uint32 id pads to 24 bytes, wasting four per step; three arrays waste
// none, and the search strides only the high words in the common case
type index6 struct {
	slots   []slotEntry
	shift   uint8
	dense   []dense
	sub     []subEntry
	high    []uint64
	low     []uint64
	ids     []uint32
	uniform uint32
}

// Index is an immutable value LPM index mapping an address to a route id
// Route id 0 means no prefix covers the address
type Index struct {
	v4     index4
	v6     index6
	routes int
}

// Lookup returns the route id of the longest prefix covering addr, or 0
// Family split up here, then we hand a decoded key to the per-family search
func (x *Index) Lookup(addr netip.Addr) uint32 {
	if addr.Is4() {
		return x.v4.lookup(be32(addr.As4()))
	}
	if addr.Is4In6() {
		// mapped v4 lives on the v4 index, same as steplpm
		return x.v4.lookup(be32(addr.Unmap().As4()))
	}
	if !addr.IsValid() {
		return 0
	}
	high, low := words16(addr.As16())
	return x.v6.lookup(high, low)
}

// Lookup4 is the decoded IPv4 fast path
func (x *Index) Lookup4(key uint32) uint32 { return x.v4.lookup(key) }

// Lookup6 is the decoded IPv6 fast path
func (x *Index) Lookup6(high, low uint64) uint32 { return x.v6.lookup(high, low) }

// Routes returns the number of distinct stored prefixes
func (x *Index) Routes() int { return x.routes }

// Steps returns the retained step count per family
func (x *Index) Steps() (v4, v6 int) { return len(x.v4.steps), len(x.v6.high) }

// RetainedBytes reports the bytes held by the compiled index
// 8 per slot, 12 per dense, 8 per sub, 8 per v4 step, then the split v6 arrays
func (x *Index) RetainedBytes() int {
	total := 8*len(x.v4.slots) + 12*len(x.v4.dense) + 8*len(x.v4.sub) + 8*len(x.v4.steps)
	total += 8*len(x.v6.slots) + 12*len(x.v6.dense) + 8*len(x.v6.sub)
	total += 8*len(x.v6.high) + 8*len(x.v6.low) + 4*len(x.v6.ids)
	return total
}

// lookup is the IPv4 search: two adjacent slot entries bound the step run,
// uniform slots answer from that one line, otherwise we walk or search
func (x *index4) lookup(key uint32) uint32 {
	slots := x.slots
	// Just bail early if we haven't set up any slots - table's empty or something
	if slots == nil {
		return x.uniform
	}
	// figuring out which top-level slot we're in, using the magic shift amount
	slot := key >> x.shift
	first := slots[slot]
	low, high := first.off, slots[slot+1].off
	// single-value slot, easy case so just hit the fast path
	if low == high {
		// uniform slot: one cache line answered the whole query
		return first.id
	}
	id := first.id
	// denseTag means this slot had way too many little guys and needs its own special lookup
	if id&denseTag != 0 {
		// rare: this /16 was dense enough for a second cut
		d := &x.dense[id&^denseTag]
		id = d.baseID
		// got a sub-block structure to drill into even deeper
		if d.subBase != noBlock {
			base := d.subBase + uint32(key>>d.subShift&0xff)
			firstSub, secondSub := x.sub[base], x.sub[base+1]
			low, high, id = firstSub.off, secondSub.off, firstSub.id
		}
	}
	steps := x.steps
	// if the run of steps is short, don't stuff around with search - just scan
	if high-low <= scanLimit {
		for i := low; i < high; i++ {
			// steps are sorted, so stop as soon as we go too far
			if steps[i].bound > key {
				return id
			}
			id = steps[i].id
		}
		// if nothing tripped that early return, answer with the last id we saw
		return id
	}
	// run's too long for a scan, so do classic binary search
	base := low
	for low < high {
		mid := (low + high) >> 1
		// nudge down the upper bound if we're past range for this mid slot
		if steps[mid].bound > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	// if nothing moved, we're right at the start so use the original id
	if low == base {
		return id
	}
	// otherwise, got to use the winner from the step just before where we landed
	return steps[low-1].id
}

// lookup is the IPv6 search - same slot trick, then we stride the split arrays
func (x *index6) lookup(keyHigh, keyLow uint64) uint32 {
	slots := x.slots
	if slots == nil {
		// nothing set up here, so just go with the default answer
		return x.uniform
	}
	slot := keyHigh >> x.shift                // picking which main slot your address lands in
	first := slots[slot]                      // get the start info for that slot
	low, high := first.off, slots[slot+1].off // this range covers the matching steps
	if low == high {
		// shortcut: this slot only cares about one prefix, no need to look further
		return first.id
	}
	id := first.id // start with the winner at the start of your range
	if id&denseTag != 0 {
		// uh oh, this slot was jam-packed with little prefixes so we need to dig deeper
		d := &x.dense[id&^denseTag]
		id = d.baseID // grab the upper-level winner for starters
		if d.subBase != noBlock {
			// even more fine-grained, jump to the sub-array based on more address bits
			base := d.subBase + uint32(keyHigh>>d.subShift&0xff)
			firstSub, secondSub := x.sub[base], x.sub[base+1]
			low, high, id = firstSub.off, secondSub.off, firstSub.id
		}
	}
	highs, lows := x.high, x.low
	if high-low <= scanLimit {
		if lows == nil {
			// yeah nah, only need high word to figure out what matches
			for i := low; i < high; i++ {
				if highs[i] > keyHigh {
					// found it, stop looking
					return id
				}
				id = x.ids[i] // keep updating id as we go, longest prefix wins
			}
			// none tripped us up, so this id is the go
			return id
		}
		for i := low; i < high; i++ {
			// for tight runs, gotta check both high and low bits to make sure we don't jump the gun
			if h := highs[i]; h > keyHigh || h == keyHigh && lows[i] > keyLow {
				return id
			}
			id = x.ids[i]
		}
		return id
	}
	base := low // mark where we started for binary search
	if lows == nil {
		for low < high {
			mid := (low + high) >> 1 // classic halfway point for search
			if highs[mid] > keyHigh {
				// too high, cut it down and look left
				high = mid
			} else {
				// too low or right on, look further right
				low = mid + 1
			}
		}
	} else {
		for low < high {
			mid := (low + high) >> 1
			// both highs and lows need checking to see if we're over-stepping
			if h := highs[mid]; h > keyHigh || h == keyHigh && lows[mid] > keyLow {
				high = mid
			} else {
				low = mid + 1
			}
		}
	}
	if low == base {
		// we didn't go anywhere, just use that first dude
		return id
	}
	// otherwise, the answer's the one right before we overflowed
	return x.ids[low-1]
}

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
