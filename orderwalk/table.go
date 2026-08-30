// Package orderwalk provides an immutable value table with hierarchy traversal,
// holding no trie at all
//
// It is the traversal specialist. flatwalk pairs a trie index with a preorder
// catalogue, and the trie is most of its footprint - this table drops the trie and
// answers every question from the catalogue itself, which a full BGP table makes
// affordable for a reason specific to its shape: only 1.6% of a real table's
// IPv4 prefixes are /16 or shorter, so a direct index over the /16 space narrows
// any search to about thirty entries, and every search is then four or five
// probes into an array that is already resident
//
// The three operations reduce to one primitive - routes are held in preorder -
// by family, then by address, then shortest first - so:
//
//   - The longest-prefix match for an address is an ancestor of the last route
//     whose address is at or below it - that route is found by bisection, and the
//     match is then the first entry on its parent chain that contains the
//     address - once one ancestor contains the address every remaining ancestor
//     does, so the supernet walk continues without further tests
//
//   - An exact prefix is found by the same bisection, comparing length only when
//     addresses tie
//
//   - The descendants of a route are the entries that follow it while their
//     address stays inside its range, so the descendant walk is a forward scan
//     and stores no subtree bound
//
// The cost is raw lookup latency: a bisection plus a parent walk is slower than
// a trie descent - choose flatwalk when longest-prefix matching is the hot path and
// this when traversal and footprint are
package orderwalk

import (
	"encoding/binary"
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
)

// RouteID identifies a route within one immutable table - zero means no route
// IPv4 routes are numbered first so that a scan never has to test which family
// it is walking
type RouteID = routeid.ID

// frontSlots indexes the /16 space, with one extra entry so that the end of the
// last block can be read without a bounds test
const frontSlots = 1<<16 + 1

// Table is an immutable routing table with longest-prefix match, exact match,
// ancestor walks and descendant walks - all reads are allocation-free and safe
// for unsynchronised concurrent use
type Table[V any] struct {
	// front4 and front6 hold, for each /16, the number of routes of that family
	// whose address is below it - a search therefore starts already narrowed to
	// one /16's run of routes
	front4 []uint32
	front6 []uint32

	key4   []uint32
	key6hi []uint64
	key6lo []uint64

	bits   []uint8
	parent []uint32
	values []V
	count4 int
}

// New compiles entries into an immutable table - duplicate normalised prefixes
// use the final value in entries
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	catalog := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		catalog[prefix] = entry.Value // shovelling the value in, squash any dups from earlier in entries
	}

	ordered := make([]netip.Prefix, 0, len(catalog))
	for prefix := range catalog {
		ordered = append(ordered, prefix) // just lining prefixes up for tidy sorting soon
	}
	sortPreorder(ordered) // get 'em sorted preorder so every parent comes before kids

	t := &Table[V]{
		bits:   make([]uint8, len(ordered)+1),  // leave 0 for "no-match" slot
		parent: make([]uint32, len(ordered)+1), // stash parent pointers - flat, not tree shaped
		values: make([]V, len(ordered)+1),      // +1 for default/empty spot
	}
	for _, prefix := range ordered {
		if prefix.Addr().Is4() {
			t.count4++ // bumping the v4 route count - used for key size stuff
		}
	}
	t.key4 = make([]uint32, 0, t.count4)                // v4 keys, tightly packed
	t.key6hi = make([]uint64, 0, len(ordered)-t.count4) // the higher half of v6 keys
	t.key6lo = make([]uint64, 0, len(ordered)-t.count4) // low bits for v6

	// one pass recovers the hierarchy: a route nests inside the deepest route
	// still on the stack whose prefix contains its address
	stack := make([]uint32, 0, 129) // holds a trail of handy ancestors as we walk
	for i, prefix := range ordered {
		route := uint32(i + 1) // just measuring - table index plus one for 1-based ids
		addr := prefix.Addr()
		// if our parent prefix doesn't cover this one, knock it off the stack
		for len(stack) != 0 && !ordered[stack[len(stack)-1]-1].Contains(addr) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) != 0 {
			t.parent[route] = stack[len(stack)-1] // set current guy's parent if one on stack
		}
		stack = append(stack, route) // now you are the new deepest nested

		t.bits[route] = uint8(prefix.Bits()) // store prefix length at each slot for quick checks
		t.values[route] = catalog[prefix]    // lock in value from earlier
		if addr.Is4() {
			t.key4 = append(t.key4, prefixentry.Addr4(addr)) // v4 key is uint32, fast for matching
		} else {
			hi, lo := prefixentry.Addr6(addr)
			t.key6hi = append(t.key6hi, hi)
			t.key6lo = append(t.key6lo, lo)
		}
	}

	t.front4 = buildFront(len(t.key4), func(i int) uint32 { return t.key4[i] >> 16 })             // sets up slot boundaries for v4
	t.front6 = buildFront(len(t.key6hi), func(i int) uint32 { return uint32(t.key6hi[i] >> 48) }) // and for v6, works pretty much the same but wider
	return t, nil                                                                                 // all built and boxed, send it up to caller
}

// buildFront counts routes per /16 and turns the counts into running totals
func buildFront(n int, keyOf func(int) uint32) []uint32 {
	front := make([]uint32, frontSlots)
	for i := 0; i < n; i++ {
		front[keyOf(i)+1]++
	}
	for i := 1; i < frontSlots; i++ {
		front[i] += front[i-1]
	}
	return front
}

// sortPreorder orders prefixes so that every route is immediately followed by
// its descendants
func sortPreorder(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})
}

// Count returns the number of stored routes
func (t *Table[V]) Count() int { return len(t.bits) - 1 }

// Bytes reports the retained size of the compiled table, excluding values
func (t *Table[V]) Bytes() int {
	return 4*(len(t.front4)+len(t.front6)+len(t.key4)+len(t.parent)) +
		16*len(t.key6hi) + len(t.bits)
}

// Lookup returns the value of the longest prefix covering addr
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	route := t.match(addr)
	if route == 0 {
		var zero V
		return zero, false
	}
	return t.values[route], true
}

// LookupRoute returns the matched route together with its value
func (t *Table[V]) LookupRoute(addr netip.Addr) (RouteID, V, bool) {
	route := t.match(addr)
	if route == 0 {
		var zero V
		return 0, zero, false
	}
	return RouteID(route), t.values[route], true
}

// match returns the longest-prefix match for addr, or zero
func (t *Table[V]) match(addr netip.Addr) uint32 {
	if addr.Is4() {
		return t.match4(prefixentry.Addr4(addr))
	}
	if !addr.IsValid() || addr.Zone() != "" {
		return 0
	}
	if addr.Is4In6() {
		return t.match4(prefixentry.Addr4(addr.Unmap()))
	}
	hi, lo := prefixentry.Addr6(addr)
	return t.match6(hi, lo)
}

// match4 walks the parent chain from the IPv4 predecessor until a covering route
func (t *Table[V]) match4(key uint32) uint32 {
	route := t.predecessor4(key)
	for route != 0 && !t.covers4(route, key) {
		route = t.parent[route]
	}
	return route
}

// match6 is the IPv6 analogue of match4
func (t *Table[V]) match6(hi, lo uint64) uint32 {
	route := t.predecessor6(hi, lo)
	for route != 0 && !t.covers6(route, hi, lo) {
		route = t.parent[route]
	}
	return route
}

// predecessor4 returns the last IPv4 route whose address is at or below key
// The front index narrows the bisection to one /16; when every route in that
// /16 is above the key, the answer is the route immediately before it
func (t *Table[V]) predecessor4(key uint32) uint32 {
	block := key >> 16
	low, high := int(t.front4[block]), int(t.front4[block+1])
	for low < high {
		mid := int(uint(low+high) >> 1)
		if t.key4[mid] > key {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return uint32(low) // route ids are one-based, so this is the entry before low
}

// predecessor6 is the IPv6 bisection, then we add count4 because v6 ids follow v4
func (t *Table[V]) predecessor6(hi, lo uint64) uint32 {
	block := uint32(hi >> 48)
	// start by finding the /16 block of the top bits – quick shortcut for narrowing
	low, high := int(t.front6[block]), int(t.front6[block+1])
	for low < high {
		mid := int(uint(low+high) >> 1)
		// this is the tight binary search over the ordered v6 prefixes
		if t.key6hi[mid] > hi || t.key6hi[mid] == hi && t.key6lo[mid] > lo {
			high = mid
			// found a prefix after our search key, so shrink the range from above
		} else {
			low = mid + 1
			// this one's still at or under the search key, so head further right
		}
	}
	if low == 0 {
		return 0
		// nothing found -- we're still at the beginning, so there's no valid predecessor
	}
	return uint32(t.count4 + low)
	// route ids for v6 are offset after all the v4 guys, so always add count4 on
}

// covers4 reports whether route's IPv4 prefix contains key
func (t *Table[V]) covers4(route, key uint32) bool {
	return (key^t.key4[route-1])>>(32-t.bits[route]) == 0
}

// covers6 reports whether route's IPv6 prefix contains (hi, lo)
func (t *Table[V]) covers6(route uint32, hi, lo uint64) bool {
	position := int(route) - t.count4 - 1
	prefixBits := t.bits[route]
	if prefixBits <= 64 {
		return (hi^t.key6hi[position])>>(64-prefixBits) == 0
	}
	return hi == t.key6hi[position] && (lo^t.key6lo[position])>>(128-prefixBits) == 0
}

// Exact returns the route stored for exactly this prefix
func (t *Table[V]) Exact(input netip.Prefix) (RouteID, V, bool) {
	route := t.exact(input)
	if route == 0 {
		var zero V
		return 0, zero, false
	}
	return RouteID(route), t.values[route], true
}

// exact bisects the /16 run looking for an address+length match
func (t *Table[V]) exact(input netip.Prefix) uint32 {
	prefix, ok := prefixentry.NormalizePrefix(input)
	// gotta normalise first so all the weird representations are handled
	if !ok {
		return 0
	}
	addr := prefix.Addr()
	prefixBits := uint8(prefix.Bits())
	if addr.Is4In6() {
		// decode v4-mapped v6 addresses, they're just sneaky
		if prefixBits < 96 {
			return 0
		}
		addr = addr.Unmap()
		// sneaky: true bits length for v4 in v6 is offset by 96
		prefixBits -= 96
	}

	if addr.Is4() {
		key := prefixentry.Addr4(addr)
		// quick split up the address space, /16 at a time
		block := key >> 16
		low, high := int(t.front4[block]), int(t.front4[block+1])
		for low < high {
			mid := int(uint(low+high) >> 1)
			// classic bisection over v4 routes
			// only check bits when addresses match up exactly
			if t.key4[mid] > key || t.key4[mid] == key && t.bits[mid+1] >= prefixBits {
				// found something that's too high or same addr but longer prefix
				high = mid
			} else {
				// not there yet, go right
				low = mid + 1
			}
		}
		// check the found spot matches both address and bits - only then we're good
		if low < int(t.front4[block+1]) && t.key4[low] == key && t.bits[low+1] == prefixBits {
			// spot on, found it, route id is slot plus one, 'cause of 1-based
			return uint32(low + 1)
		}
		return 0
	}

	hi, lo := prefixentry.Addr6(addr)
	// chop up v6 space with a giant block split, just like v4
	block := uint32(hi >> 48)
	low, high := int(t.front6[block]), int(t.front6[block+1])
	for low < high {
		mid := int(uint(low+high) >> 1)
		route := t.count4 + mid + 1
		// proper bisection, need to check hi first then lo, then prefix bits if all else same
		if t.key6hi[mid] > hi || t.key6hi[mid] == hi &&
			(t.key6lo[mid] > lo || t.key6lo[mid] == lo && t.bits[route] >= prefixBits) {
			// this spot (or earlier) could have it, so shrink the range
			high = mid
		} else {
			// look further right
			low = mid + 1
		}
	}
	// last check: make sure everything matches up, especially them bits
	if low < int(t.front6[block+1]) && t.key6hi[low] == hi && t.key6lo[low] == lo &&
		t.bits[t.count4+low+1] == prefixBits {
		// route id for v6 is offset by count4
		return uint32(t.count4 + low + 1)
	}
	return 0
}

// WalkParents visits the longest match for addr and then each of its ancestors,
// most specific first - iteration stops early if yield returns false
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(RouteID, netip.Prefix, V) bool) {
	// once one ancestor covers the address every remaining ancestor does, so
	// the walk below performs no further containment tests
	for route := t.match(addr); route != 0; route = t.parent[route] {
		if !yield(RouteID(route), t.prefixOf(route), t.values[route]) {
			return
		}
	}
}

// WalkDescendants visits an exact route and every route nested inside it, in
// preorder - it reports whether the exact prefix was present
func (t *Table[V]) WalkDescendants(prefix netip.Prefix, yield func(RouteID, netip.Prefix, V) bool) bool {
	route := t.exact(prefix)
	// grab the route id for this prefix, if it exists

	if route == 0 {
		// nah, not found, just bail out early
		return false
	}
	if !yield(RouteID(route), t.prefixOf(route), t.values[route]) {
		// if your yield function says nope right at the start, we're packing it in
		return true
	}

	if int(route) <= t.count4 {
		// this means we're working with IPv4 routes
		last := t.key4[route-1] | ^prefixentry.IPv4Mask(int(t.bits[route]))
		// Last is the highest IPv4 address covered by this prefix, so we know where our block stops

		for next := int(route) + 1; next <= t.count4; next++ {
			if t.key4[next-1] > last {
				// we've wandered outside the boundary, stop right away
				break
			}
			if !yield(RouteID(next), t.prefixOf(uint32(next)), t.values[next]) {
				// your callback function wants us to call it off
				return true
			}
		}
		// finished with all IPv4 descendants, all done
		return true
	}

	// must be IPv6 if we're down here
	position := int(route) - t.count4 - 1
	lastHi, lastLo := lastAddr6(t.key6hi[position], t.key6lo[position], t.bits[route])
	// find the end address this IPv6 prefix will stretch to, so we don't overshoot

	for next := int(route) + 1; next < len(t.bits); next++ {
		at := next - t.count4 - 1
		hi, lo := t.key6hi[at], t.key6lo[at]
		if hi > lastHi || hi == lastHi && lo > lastLo {
			// ok, next prefix steps outside what we care about, time to pull the plug
			break
		}
		if !yield(RouteID(next), t.prefixOf(uint32(next)), t.values[next]) {
			// your yield wants us to quit, so back out now
			return true
		}
	}
	// safe to say we hit every descendant - job done
	return true
}

// prefixOf rebuilds the netip.Prefix for a stored route id
func (t *Table[V]) prefixOf(route uint32) netip.Prefix {
	prefixBits := int(t.bits[route])
	if int(route) <= t.count4 {
		key := t.key4[route-1]
		// grab the IPv4 bits for this route's starting address
		addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
		// rip out all the address bytes for v4, build the addr from them
		return netip.PrefixFrom(addr, prefixBits)
	}
	position := int(route) - t.count4 - 1
	// work out our v6 position, we're past the v4 chunk now
	var octets [16]byte
	binary.BigEndian.PutUint64(octets[0:8], t.key6hi[position])
	// stick the high half of the route in the first 8 bytes for v6
	binary.BigEndian.PutUint64(octets[8:16], t.key6lo[position])
	// now slap the low half in to finish off the v6 address
	return netip.PrefixFrom(netip.AddrFrom16(octets), prefixBits)
}

// lastAddr6 returns the highest address inside an IPv6 prefix
func lastAddr6(hi, lo uint64, prefixBits uint8) (uint64, uint64) {
	switch {
	case prefixBits == 0:
		// all bits are wildcards, so we're just chucking back the max value for both halves
		return ^uint64(0), ^uint64(0)
	case prefixBits < 64:
		// for prefixes shorter than 64 bits, mask the high bits but leave low bits at max
		return hi | ^uint64(0)>>prefixBits, ^uint64(0)
	case prefixBits == 64:
		// right, bang-on 64 bits, so high stays the same, low is all ones
		return hi, ^uint64(0)
	case prefixBits < 128:
		// anything between 65 and 127, mask just the low half past our length
		return hi, lo | ^uint64(0)>>(prefixBits-64)
	default:
		// at 128 bits, so that's the exact address as is, nothing wild
		return hi, lo
	}
}
