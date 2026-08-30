// Package steplpm is our fastest value LPM - give it an address, it hands back
// the value of the longest stored prefix covering it
//
// # Leaf pushing to a step function
//
// The answer to an LPM query is a step function of the address - the address
// space divides into maximal runs over which the winning prefix doesn't
// change - we store exactly that: a sorted array of (boundary, route id)
// steps, so a lookup is a search rather than a descent, and the depth of the
// deepest prefix in the table costs nothing - prefixes are either disjoint or
// nested so the steps come out of a single stack sweep over the prefixes in
// address order
//
// Adjacent runs with the same winner get collapsed, which is what keeps the
// array proportional to the table rather than the address space - that's the
// whole difference between this and compiledfib - compiledfib leaf-pushes into
// fixed 256-entry blocks, so every /16 with a longer prefix under it costs a
// kilobyte and every /24 with a longer prefix costs another, which measured at
// 58 MB retained for a 100k table - run-collapsed steps hold the same
// information in roughly a megabyte
//
// # Localisation
//
// Searching the whole step array would cost a logarithmic number of dependent
// cache misses, so we localise first. level1 is indexed by the top 16 bits of
// the address and holds, for each /16, either the route id that wins across
// the whole of it - the common case, answered in one load - or a tag pointing
// at a dense record describing the steps inside it
//
// # The second cut is adaptive
//
// A /16 dense enough to need a further cut is cut again on one octet, but which
// octet is chosen per /16 from the data - this is not a refinement - a fixed
// choice cannot work - measured on the two fixtures we bench against: a
// realistic BGP-shaped IPv6 table varies mostly in its second and third
// octets, so it wants a cut just below the /16, while the synthetic fixture
// puts every IPv6 prefix inside 2001:db8::/32 and varies bits 32 to 55, so a
// cut just below the /16 separates nothing at all and it wants a cut four
// octets down - the builder measures the occupancy each candidate octet would
// produce and keeps the best
//
// Index is immutable and safe for unsynchronised concurrent reads - see Table
// for the managed form with cheap payload updates
package steplpm

import (
	"errors"
	"net/netip"
)

// ErrBadPrefix reports an invalid or zoned prefix
var ErrBadPrefix = errors.New("steplpm: bad prefix")

// ErrTooManyRoutes reports a table larger than the 2^31 route-id space
var ErrTooManyRoutes = errors.New("steplpm: too many routes")

const (
	slotShift = 16
	slotCount = 1 << slotShift

	// denseTag marks a level1 entry as a pointer to a dense record rather than
	// a route id - route ids are therefore limited to 2^31-1, which is within
	// the entry budget this package is designed for
	denseTag = uint32(1) << 31

	noBlock = ^uint32(0)

	// subEntries is the length of one second-cut block: 256 buckets plus a
	// terminating offset so that bucket i is always [sub[i], sub[i+1])
	subEntries = 256 + 1

	// subThreshold is the step count within one /16 above which a second cut
	// is built - below it the steps fit in a couple of cache lines and a linear
	// walk beats the extra dependent load
	subThreshold = 12

	// scanLimit is the step count that is cheaper to walk than to binary
	// search: a walk touches consecutive addresses that the prefetcher covers
	// and mispredicts once, where a search makes unprefetchable probes
	scanLimit = 32
)

// step4 is one run of the IPv4 step function: from bound onward, id wins
type step4 struct {
	bound uint32
	id    uint32
}

// step6 is the IPv6 equivalent - two words because 128 bits
type step6 struct {
	high, low uint64
	id        uint32
}

// subEntry bounds one second-cut bucket and carries the id winning at its start
type subEntry struct {
	off uint32
	id  uint32
}

// dense4 describes the steps inside one non-uniform IPv4 /16
type dense4 struct {
	off, end uint32 // step range
	baseID   uint32 // id winning at the first address of the /16
	subBase  uint32 // index into sub, or noBlock
	subShift uint8  // octet used by the second cut
}

// dense6 is the IPv6 equivalent
type dense6 struct {
	off, end uint32
	baseID   uint32
	subBase  uint32
	subShift uint8
}

type index4 struct {
	level1 []uint32 // 1<<level1Bits entries; nil when the table is uniform
	// level1Shift is the right shift that turns an address into a level1 slot
	level1Shift uint8
	dense       []dense4
	sub         []subEntry
	steps       []step4
	uniform     uint32 // id winning everywhere, when level1 is nil
}

type index6 struct {
	level1      []uint32
	level1Shift uint8
	dense       []dense6
	sub         []subEntry
	steps       []step6
	uniform     uint32
}

// Index is an immutable value LPM index mapping an address to a route id
// Route id 0 means no prefix covers the address
type Index struct {
	v4     index4
	v6     index6
	routes int
}

// Lookup returns the route id of the longest prefix covering addr, or 0
// We peel the family off first, unmap 4-in-6 onto the v4 index, then hand the
// decoded key to the per-family lookup - that's the only branching we do up here
func (x *Index) Lookup(addr netip.Addr) uint32 {
	if addr.Is4() {
		return x.v4.lookup(be32(addr.As4()))
	}
	if addr.Is4In6() {
		// ::ffff:a.b.c.d is just IPv4 wearing a coat, treat it as such
		return x.v4.lookup(be32(addr.Unmap().As4()))
	}
	if !addr.IsValid() {
		return 0
	}
	high, low := words16(addr.As16())
	return x.v6.lookup(high, low)
}

// Lookup4 is the decoded IPv4 fast path - caller already has the uint32
func (x *Index) Lookup4(key uint32) uint32 { return x.v4.lookup(key) }

// Lookup6 is the decoded IPv6 fast path - two network-order words
func (x *Index) Lookup6(high, low uint64) uint32 { return x.v6.lookup(high, low) }

// Routes returns the number of distinct stored prefixes
func (x *Index) Routes() int { return x.routes }

// Steps returns the retained step count per family, for tests and reporting
func (x *Index) Steps() (v4, v6 int) { return len(x.v4.steps), len(x.v6.steps) }

// RetainedBytes reports the bytes held by the compiled index
// Sizes are the struct layouts we actually allocate: 4 per level1, 20 per
// dense record, 8 per sub entry, 8 per v4 step, 24 per v6 step
func (x *Index) RetainedBytes() int {
	total := 4*len(x.v4.level1) + 20*len(x.v4.dense) + 8*len(x.v4.sub) + 8*len(x.v4.steps)
	total += 4*len(x.v6.level1) + 20*len(x.v6.dense) + 8*len(x.v6.sub) + 24*len(x.v6.steps)
	return total
}

// lookup is the IPv4 search: localise via level1, maybe take the second cut,
// then either walk or binary-search the remaining steps
func (x *index4) lookup(key uint32) uint32 {
	level1 := x.level1
	if level1 == nil {
		// empty or one winner everywhere - nothing to search
		return x.uniform
	}
	entry := level1[key>>x.level1Shift]
	if entry&denseTag == 0 {
		// whole /16 (or whatever the window is) has one winner
		return entry
	}
	d := &x.dense[entry&^denseTag]
	low, high, id := d.off, d.end, d.baseID
	if d.subBase != noBlock {
		// second cut: one octet, 256 buckets, adjacent entries bound the run
		base := d.subBase + uint32(key>>d.subShift&0xff)
		first, second := x.sub[base], x.sub[base+1]
		low, high, id = first.off, second.off, first.id
	}
	steps := x.steps
	if high-low <= scanLimit {
		// linear walk wins here - consecutive, prefetchable, one mispredict
		for i := low; i < high; i++ {
			if steps[i].bound > key {
				return id
			}
			id = steps[i].id
		}
		return id
	}
	// binary search for the last step at or below key
	base := low
	for low < high {
		mid := (low + high) >> 1
		if steps[mid].bound > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	if low == base {
		// every remaining step is above the key, so the carried-in id wins
		return id
	}
	return steps[low-1].id
}

// lookup is the IPv6 search, same shape as v4 but the bound is two words
func (x *index6) lookup(keyHigh, keyLow uint64) uint32 {
	level1 := x.level1
	if level1 == nil {
		return x.uniform
	}
	entry := level1[keyHigh>>x.level1Shift]
	if entry&denseTag == 0 {
		return entry
	}
	d := &x.dense[entry&^denseTag]
	low, high, id := d.off, d.end, d.baseID
	if d.subBase != noBlock {
		// second cut still lives in the high word - we only ever cut above /64
		base := d.subBase + uint32(keyHigh>>d.subShift&0xff)
		first, second := x.sub[base], x.sub[base+1]
		low, high, id = first.off, second.off, first.id
	}
	steps := x.steps
	if high-low <= scanLimit {
		for i := low; i < high; i++ {
			s := &steps[i]
			if s.high > keyHigh || s.high == keyHigh && s.low > keyLow {
				return id
			}
			id = s.id
		}
		return id
	}
	base := low
	for low < high {
		mid := (low + high) >> 1
		s := &steps[mid]
		if s.high > keyHigh || s.high == keyHigh && s.low > keyLow {
			high = mid
		} else {
			low = mid + 1
		}
	}
	if low == base {
		return id
	}
	return steps[low-1].id
}

// be32 packs 4 big-endian bytes into a uint32 - network order, same as the wire
func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// words16 splits a 16-byte IPv6 address into two uint64s, high then low
func words16(b [16]byte) (high, low uint64) {
	high = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	low = uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	return high, low
}
