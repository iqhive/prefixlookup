// Package flatwalk is our immutable value table with hierarchy traversal,
// built on the flatart arena core
//
// traversal member of the lookup1 family, replacing fiborderwalk and
// splitribfib - two things dominate traversal cost in those implementations,
// and both are removed here
//
// Exact-prefix lookup is a trie descent, not a hash - fiborderwalk and
// preorder2 answer WalkDescendants by hashing a netip.Prefix - a 24-byte
// address plus a length - in a map keyed by that type, and the hash is most
// of their subnet walk - here the same question is answered by descending
// the flatart index to the prefix's own stride and testing one bit, which
// costs the same handful of loads as a lookup
//
// descendants are a contiguous run - routes are held in preorder, so the
// descendants of a route are the entries that follow it while their key
// stays inside its range - no subtree-end index is stored, the range test
// that the scan must perform anyway is what terminates it
//
// ancestors are a short index chain - a parent index per route costs four
// bytes and turns a supernet walk into the longest-prefix match plus one
// dependent load per level, against the trie descent and per-level bitset
// enumeration that bart's Supernets iterator performs
package flatwalk

import (
	"encoding/binary"
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/flatart"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
)

// RouteID identifies a route within one immutable table - zero means no route
type RouteID = routeid.ID

// Table is an immutable routing table with longest-prefix match, exact
// match, ancestor walks and descendant walks
// all reads are allocation-free and safe for unsynchronised concurrent use
type Table[V any] struct {
	index flatart.Index

	// routeOf maps an index value slot to a route - the index chooses its own
	// value order to keep resolution to base+rank, so this is the one place
	// the two numbering schemes meet
	routeOf []uint32

	// routes are numbered in preorder: 1..count4 are IPv4, the rest IPv6
	// the key arrays are split by family so a descendant scan never has to
	// test which family it is walking
	key4   []uint32
	key6hi []uint64
	key6lo []uint64
	bits   []uint8
	parent []uint32
	values []V
	count4 int
}

// New compiles entries into an immutable table
// last duplicate after we normalise wins
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	// making a map to hold just one value per prefix here, dedupe as we go
	catalog := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		// gotta make sure the prefix is normalized (sanity-check and cleanup)
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			// wow, something's wrong with this prefix so we bail
			return nil, prefixentry.ErrBadIP
		}
		// if this prefix was in there before, oh well, clobber it (last one wins)
		catalog[prefix] = entry.Value
	}

	// time to arrange our prefixes in preorder for the next steps
	ordered := preorderPrefixes(catalog)
	// set up our table and preallocate all our slices
	t := &Table[V]{
		bits:   make([]uint8, len(ordered)+1), // slot 0 isn't used
		parent: make([]uint32, len(ordered)+1),
		values: make([]V, len(ordered)+1),
	}
	// figure out how many v4 routes we have
	for _, prefix := range ordered {
		if prefix.Addr().Is4() {
			t.count4++
		}
	}
	// make space for ipv4 and ipv6 keys based on the count
	t.key4 = make([]uint32, 0, t.count4)
	t.key6hi = make([]uint64, 0, len(ordered)-t.count4)
	t.key6lo = make([]uint64, 0, len(ordered)-t.count4)

	// builder for the arena index, we want "exact" mapping here
	builder := flatart.NewBuilder(flatart.Options{Exact: true})
	// stack for tracking ancestors as we walk through the tree in preorder
	stack := make([]uint32, 0, 129) // this is usually plenty deep
	for i, prefix := range ordered {
		// route id is 1-based: matches the builder convention
		route := uint32(i + 1)
		addr := prefix.Addr()
		// pop from the stack until we find an ancestor that can contain this guy
		for len(stack) != 0 && !ordered[stack[len(stack)-1]-1].Contains(addr) {
			stack = stack[:len(stack)-1]
		}
		// if there's anything on the stack, that's the parent for this route
		if len(stack) != 0 {
			t.parent[route] = stack[len(stack)-1]
		}
		// push this route on for later
		stack = append(stack, route)

		// note down the mask length for this route
		t.bits[route] = uint8(prefix.Bits())
		// stash the value where we'll grab it during lookups
		t.values[route] = catalog[prefix]
		// toss addresses into the right array by family
		if addr.Is4() {
			t.key4 = append(t.key4, prefixentry.Addr4(addr))
		} else {
			hi, lo := prefixentry.Addr6(addr)
			t.key6hi = append(t.key6hi, hi)
			t.key6lo = append(t.key6lo, lo)
		}
		// push prefix (and its route id) into the builder, scream if it fails
		if !builder.Insert(prefix, route) {
			return nil, prefixentry.ErrBadIP
		}
	}

	// hand-off: get the actual index and map from slot to route id out of the builder
	index, routeOf, err := builder.Build()
	if err != nil {
		// something's busted, propagate the error back
		return nil, err
	}
	// stash these in our table, that's the core of the lookup dance
	t.index = *index
	t.routeOf = routeOf
	// wow, we did it, here's your table
	return t, nil
}

// preorderPrefixes orders prefixes so that every route is immediately
// followed by its descendants: by family, then by address, then by
// increasing length
func preorderPrefixes[V any](catalog map[netip.Prefix]V) []netip.Prefix {
	ordered := make([]netip.Prefix, 0, len(catalog))
	for prefix := range catalog {
		ordered = append(ordered, prefix)
	}
	sortPrefixes(ordered)
	return ordered
}

// Lookup returns the value of the longest prefix covering addr
// arena slot then routeOf then values - three loads, no extra best-so-far
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	if slot := t.index.Lookup(addr); slot != 0 {
		route := t.routeOf[slot]
		return t.values[route], true
	}
	var zero V
	return zero, false
}

// LookupRoute returns the matched route together with its value
// same path as Lookup, we just also hand back the RouteID
func (t *Table[V]) LookupRoute(addr netip.Addr) (RouteID, V, bool) {
	if slot := t.index.Lookup(addr); slot != 0 {
		route := t.routeOf[slot]
		return RouteID(route), t.values[route], true
	}
	var zero V
	return 0, zero, false
}

// Exact returns the route stored for exactly this prefix, not a covering one
func (t *Table[V]) Exact(prefix netip.Prefix) (RouteID, V, bool) {
	if slot := t.index.Exact(prefix); slot != 0 {
		route := t.routeOf[slot]
		return RouteID(route), t.values[route], true
	}
	var zero V
	return 0, zero, false
}

// Count is the number of stored routes - slot 0 is reserved, so len-1
func (t *Table[V]) Count() int { return len(t.bits) - 1 }

// Bytes reports the retained size of the compiled table, excluding values
func (t *Table[V]) Bytes() int {
	return t.index.Bytes() + 4*len(t.routeOf) + 4*len(t.key4) +
		16*len(t.key6hi) + len(t.bits) + 4*len(t.parent)
}

// WalkParents visits the longest match for addr and then each of its
// ancestors, most specific first
// we just follow the parent chain - iteration stops early if yield returns false
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(RouteID, netip.Prefix, V) bool) {
	slot := t.index.Lookup(addr)
	if slot == 0 {
		return
	}
	for route := t.routeOf[slot]; route != 0; route = t.parent[route] {
		if !yield(RouteID(route), t.prefixOf(route), t.values[route]) {
			return
		}
	}
}

// WalkDescendants visits an exact route and every route nested inside it,
// in preorder - it reports whether the exact prefix was present
//
// descendants are a contiguous run after the route while the key stays
// inside the range - we don't store a subtree-end index, the range test
// that the scan must perform anyway is what terminates it
func (t *Table[V]) WalkDescendants(prefix netip.Prefix, yield func(RouteID, netip.Prefix, V) bool) bool {
	// try to find this exact prefix in the index, slot 0 means it ain't here
	slot := t.index.Exact(prefix)
	if slot == 0 {
		// nope, not present, nothing to do
		return false
	}
	// found it! grab the route id for this slot
	route := t.routeOf[slot]
	// okay, hit the yield callback for this exact route
	if !yield(RouteID(route), t.prefixOf(route), t.values[route]) {
		// if yield says to bail out, we're done
		return true
	}

	// if this is an IPv4 route
	if int(route) <= t.count4 {
		// figure out the last address for this prefix-bit of a mask magic here
		last := t.key4[route-1] | ^prefixentry.IPv4Mask(int(t.bits[route]))
		// now walk through the following ipv4 routes, looking for descendants
		for next := int(route) + 1; next <= t.count4; next++ {
			// as soon as we see a key out of range, we stop
			if t.key4[next-1] > last {
				break
			}
			// hit the yield callback for each descendant, bail out if told
			if !yield(RouteID(next), t.prefixOf(uint32(next)), t.values[next]) {
				return true
			}
		}
		// did the walk, job done
		return true
	}

	// otherwise we've got IPv6, and things are a bit more chunky
	// these keys use two slices for hi and lo bits, so build cursor for them
	position := int(route) - t.count4 - 1
	// grab last address in this prefix, in split uint64 land
	lastHi, lastLo := lastAddr6(t.key6hi[position], t.key6lo[position], t.bits[route])
	// now walk through all v6 descendants that are still in range
	for next := int(route) + 1; next < len(t.bits); next++ {
		at := next - t.count4 - 1
		hi, lo := t.key6hi[at], t.key6lo[at]
		// as soon as hi is out of range, or both are, we call it
		if hi > lastHi || (hi == lastHi && lo > lastLo) {
			break
		}
		// call the yield for each descendant, stop if asked to
		if !yield(RouteID(next), t.prefixOf(uint32(next)), t.values[next]) {
			return true
		}
	}
	// that's the whole subtree, we're out
	return true
}

// builds a netip.Prefix back from our weird packed key arrays
// mainly for walking, not the hot path where speed matters a lot
func (t *Table[V]) prefixOf(route uint32) netip.Prefix {
	// fetch length for mask
	prefixBits := int(t.bits[route])
	// if this is IPv4, reconstruct a 4-byte address
	if int(route) <= t.count4 {
		key := t.key4[route-1]
		addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
		return netip.PrefixFrom(addr, prefixBits)
	}
	// okay, v6 time, rebuild 16 bytes piece by piece
	position := int(route) - t.count4 - 1
	var octets [16]byte
	binary.BigEndian.PutUint64(octets[0:8], t.key6hi[position])
	binary.BigEndian.PutUint64(octets[8:16], t.key6lo[position])
	return netip.PrefixFrom(netip.AddrFrom16(octets), prefixBits)
}

// lastAddr6 returns the highest address inside an IPv6 prefix
// split at 64 because that's where our key is split
func lastAddr6(hi, lo uint64, prefixBits uint8) (uint64, uint64) {
	switch {
	case prefixBits == 0:
		return ^uint64(0), ^uint64(0)
	case prefixBits < 64:
		return hi | ^uint64(0)>>prefixBits, ^uint64(0)
	case prefixBits == 64:
		return hi, ^uint64(0)
	case prefixBits < 128:
		return hi, lo | ^uint64(0)>>(prefixBits-64)
	default:
		return hi, lo
	}
}
