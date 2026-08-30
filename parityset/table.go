package parityset

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
)

// Table is a mutable boolean membership set that publishes immutable Set
// generations behind an atomic pointer - readers perform one atomic load and a
// direct call; they never synchronise with a writer and never block
//
// # Why the authoritative set is not a map
//
// Deletion needs to know which prefixes were actually stored, because removing
// one shorter prefix can expose several longer ones that the compiled index had
// reduced away - a map[netip.Prefix]struct{} would serve, but a netip.Prefix key
// is 32 bytes and Go's map adds control bytes, pointers and load-factor slack
// on top: measured at 100k prefixes that map alone retained 6.3 MB, forty times
// the compiled index it exists to rebuild
//
// The prefixes are therefore held in two sorted, packed slices - 8 bytes per
// IPv4 prefix and 24 per IPv6 prefix - searched by binary search and mutated by
// a splice - insert and delete become O(n) memory moves rather than O(1) hash
// operations, which is the right trade for a structure whose reads outnumber
// its writes by six orders of magnitude in the workloads it targets, and it
// keeps the retained size of the managed form proportional to the input
//
// # No-op mutations
//
// A mutation that cannot change the union publishes nothing: re-adding a prefix
// that is already stored, or adding one that a stored shorter prefix already
// covers, cannot change any answer this type is able to give - that is a
// property of the boolean question rather than a shortcut - a membership set has
// no per-prefix payload to update - and it means such a mutation costs a binary
// search and no rebuild
type Table struct {
	current atomic.Pointer[Set]

	mu sync.Mutex
	// v4 holds key<<8|bits, so the natural uint64 order is (address, length)
	v4 []uint64
	v6 []entry6
}

// entry6 is one stored IPv6 prefix, masked
type entry6 struct {
	high, low uint64
	bits      uint8
}

// NewTable returns a Table holding the given prefixes
func NewTable(prefixes []netip.Prefix) (*Table, error) {
	t := new(Table)
	if err := t.Reset(prefixes); err != nil {
		return nil, err
	}
	return t, nil
}

// Contains reports whether any stored prefix covers addr - it is wait-free
func (t *Table) Contains(addr netip.Addr) bool { return t.current.Load().Contains(addr) }

// Contains4 is the decoded IPv4 fast path
func (t *Table) Contains4(key uint32) bool { return t.current.Load().Contains4(key) }

// Contains6 is the decoded IPv6 fast path
func (t *Table) Contains6(high, low uint64) bool { return t.current.Load().Contains6(high, low) }

// Snapshot returns the currently published immutable set
func (t *Table) Snapshot() *Set { return t.current.Load() }

// Size returns the number of distinct stored prefixes, which is generally
// larger than the number of ranges the compiled index retains
func (t *Table) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.v4) + len(t.v6)
}

// Reset replaces the whole set
// Pack, sort, dedup, then republish under the lock
func (t *Table) Reset(prefixes []netip.Prefix) error {
	v4 := make([]uint64, 0, len(prefixes))
	v6 := make([]entry6, 0, len(prefixes)/8+1)
	for _, prefix := range prefixes {
		key, high, low, bits, is4, ok := decompose(prefix)
		if !ok {
			return ErrBadPrefix
		}
		if is4 {
			v4 = append(v4, pack4(key, bits))
			continue
		}
		v6 = append(v6, entry6{high: high, low: low, bits: bits})
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i] < v4[j] })
	v4 = dedupSorted(v4)
	sort.Slice(v6, func(i, j int) bool { return less6(v6[i], v6[j]) })
	v6 = dedupSorted6(v6)

	t.mu.Lock()
	t.v4, t.v6 = v4, v6
	t.republish()
	t.mu.Unlock()
	return nil
}

// Insert adds a prefix - it reports whether the prefix was newly stored, which
// is independent of whether a new generation had to be published
func (t *Table) Insert(prefix netip.Prefix) bool {
	key, high, low, bits, is4, ok := decompose(prefix)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.store(key, high, low, bits, is4) {
		return false
	}
	// publish only when the union actually changes
	if !t.current.Load().coversRangeOf(key, high, low, bits, is4) {
		t.republish()
	}
	return true
}

// Delete removes a prefix - it reports whether the prefix was present
func (t *Table) Delete(prefix netip.Prefix) bool {
	key, high, low, bits, is4, ok := decompose(prefix)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.remove(key, high, low, bits, is4) {
		return false
	}
	t.republish()
	return true
}

// Mutation is one requested change to the set
type Mutation struct {
	Prefix netip.Prefix
	Delete bool
}

// ApplyBatch applies mutations in order and publishes at most one generation
func (t *Table) ApplyBatch(mutations []Mutation) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for _, mutation := range mutations {
		key, high, low, bits, is4, ok := decompose(mutation.Prefix)
		if !ok {
			return ErrBadPrefix
		}
		if mutation.Delete {
			if t.remove(key, high, low, bits, is4) {
				changed = true
			}
			continue
		}
		if !t.store(key, high, low, bits, is4) {
			continue
		}
		if !t.current.Load().coversRangeOf(key, high, low, bits, is4) {
			changed = true
		}
	}
	if changed {
		t.republish()
	}
	return nil
}

// All calls fn for every stored prefix, IPv4 first, each family in ascending
// (address, length) order - iteration stops early if fn returns false
func (t *Table) All(fn func(netip.Prefix) bool) {
	t.mu.Lock()
	v4 := make([]uint64, len(t.v4))
	copy(v4, t.v4)
	v6 := make([]entry6, len(t.v6))
	copy(v6, t.v6)
	t.mu.Unlock()
	for _, packed := range v4 {
		key, bits := unpack4(packed)
		addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
		if !fn(netip.PrefixFrom(addr, int(bits))) {
			return
		}
	}
	for _, e := range v6 {
		var b [16]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(e.high >> (56 - i*8))
			b[8+i] = byte(e.low >> (56 - i*8))
		}
		if !fn(netip.PrefixFrom(netip.AddrFrom16(b), int(e.bits))) {
			return
		}
	}
}

// store inserts into the authoritative set, reporting whether it was new
// The caller holds mu
func (t *Table) store(key uint32, high, low uint64, bits uint8, is4 bool) bool {
	if is4 {
		packed := pack4(key, bits)
		at := sort.Search(len(t.v4), func(i int) bool { return t.v4[i] >= packed })
		if at < len(t.v4) && t.v4[at] == packed {
			return false
		}
		t.v4 = append(t.v4, 0)
		copy(t.v4[at+1:], t.v4[at:])
		t.v4[at] = packed
		return true
	}
	want := entry6{high: high, low: low, bits: bits}
	at := sort.Search(len(t.v6), func(i int) bool { return !less6(t.v6[i], want) })
	if at < len(t.v6) && t.v6[at] == want {
		return false
	}
	t.v6 = append(t.v6, entry6{})
	copy(t.v6[at+1:], t.v6[at:])
	t.v6[at] = want
	return true
}

// remove deletes from the authoritative set, reporting whether it was present
// The caller holds mu
func (t *Table) remove(key uint32, high, low uint64, bits uint8, is4 bool) bool {
	if is4 {
		packed := pack4(key, bits)
		at := sort.Search(len(t.v4), func(i int) bool { return t.v4[i] >= packed })
		if at >= len(t.v4) || t.v4[at] != packed {
			return false
		}
		copy(t.v4[at:], t.v4[at+1:])
		t.v4 = t.v4[:len(t.v4)-1]
		return true
	}
	want := entry6{high: high, low: low, bits: bits}
	at := sort.Search(len(t.v6), func(i int) bool { return !less6(t.v6[i], want) })
	if at >= len(t.v6) || t.v6[at] != want {
		return false
	}
	copy(t.v6[at:], t.v6[at+1:])
	t.v6 = t.v6[:len(t.v6)-1]
	return true
}

// republish recompiles the index from the authoritative set, without going back
// through netip - the caller holds mu
func (t *Table) republish() {
	b := builder{
		v4: make([]range4, 0, len(t.v4)),
		v6: make([]range6, 0, len(t.v6)),
	}
	for _, packed := range t.v4 {
		key, bits := unpack4(packed)
		b.addRange4(key, bits)
	}
	for _, e := range t.v6 {
		b.addRange6(e.high, e.low, e.bits)
	}
	t.current.Store(b.build())
}

// pack4 stuffs an IPv4 key and length into a uint64 so sort order is (addr, bits)
func pack4(key uint32, bits uint8) uint64 { return uint64(key)<<8 | uint64(bits) }

// unpack4 undoes pack4
func unpack4(packed uint64) (uint32, uint8) { return uint32(packed >> 8), uint8(packed & 0xff) }

// less6 orders IPv6 entries by (high, low, bits)
func less6(a, b entry6) bool {
	if a.high != b.high {
		return a.high < b.high
	}
	if a.low != b.low {
		return a.low < b.low
	}
	return a.bits < b.bits
}

// dedupSorted collapses adjacent equal uint64s in an already-sorted slice
func dedupSorted(values []uint64) []uint64 {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// dedupSorted6 is the IPv6 analogue of dedupSorted
func dedupSorted6(values []entry6) []entry6 {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// decompose validates a prefix and returns its masked address and length
func decompose(prefix netip.Prefix) (key uint32, high, low uint64, bits uint8, is4, ok bool) {
	if !prefix.IsValid() {
		return 0, 0, 0, 0, false, false
	}
	addr := prefix.Addr()
	length := prefix.Bits()
	if addr.Is4In6() {
		if length < 96 {
			return 0, 0, 0, 0, false, false
		}
		addr = addr.Unmap()
		length -= 96
	}
	if addr.Zone() != "" {
		return 0, 0, 0, 0, false, false
	}
	if addr.Is4() {
		if length > 32 {
			return 0, 0, 0, 0, false, false
		}
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		return be32(addr.As4()) & mask, 0, 0, uint8(length), true, true
	}
	if length > 128 {
		return 0, 0, 0, 0, false, false
	}
	high, low = words16(addr.As16())
	maskHigh, maskLow := masks128(length)
	return 0, high & maskHigh, low & maskLow, uint8(length), false, true
}

// coversRangeOf reports whether the whole address range of the given prefix is
// already covered, in which case storing it cannot change any answer
func (s *Set) coversRangeOf(key uint32, high, low uint64, bits uint8, is4 bool) bool {
	if is4 {
		var mask uint32
		if bits > 0 {
			mask = ^uint32(0) << (32 - bits)
		}
		return s.v4.coversRange(key&mask, key|^mask)
	}
	lastHigh, lastLow := high, low
	if bits < 64 {
		lastHigh |= ^uint64(0) >> bits
		lastLow = ^uint64(0)
	} else if bits < 128 {
		lastLow |= ^uint64(0) >> (bits - 64)
	}
	return s.v6.coversRange(high, low, lastHigh, lastLow)
}

// coversRange reports whether [first, last] lies wholly inside one stored
// range: first must be covered and no boundary may fall in (first, last]
func (x *index4) coversRange(first, last uint32) bool {
	if x.all {
		return true
	}
	count := x.countAtOrBelow(first)
	if count&1 == 0 {
		return false
	}
	// count indexes the boundary that closes the covering range
	return count >= len(x.bounds) || x.bounds[count] > last
}

// countAtOrBelow is a binary search for how many IPv4 boundaries sit at or below key
func (x *index4) countAtOrBelow(key uint32) int {
	low, high := 0, len(x.bounds)
	for low < high {
		mid := int(uint(low+high) >> 1)
		if x.bounds[mid] > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low
}

// coversRange is the IPv6 analogue - first covered, closer past last
func (x *index6) coversRange(firstHigh, firstLow, lastHigh, lastLow uint64) bool {
	if x.all {
		return true
	}
	count := x.countAtOrBelow(firstHigh, firstLow)
	if count&1 == 0 {
		return false
	}
	if count >= len(x.high) {
		return true
	}
	boundaryLow := uint64(0)
	if x.low != nil {
		boundaryLow = x.low[count]
	}
	return cmp128(x.high[count], boundaryLow, lastHigh, lastLow) > 0
}

// countAtOrBelow is the IPv6 binary search, consulting the low word only on a tie
func (x *index6) countAtOrBelow(keyHigh, keyLow uint64) int {
	low, high := 0, len(x.high)
	for low < high {
		mid := int(uint(low+high) >> 1)
		midLow := uint64(0)
		if x.low != nil {
			midLow = x.low[mid]
		}
		if cmp128(x.high[mid], midLow, keyHigh, keyLow) > 0 {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low
}
