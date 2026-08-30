// Package fibbitwalk is the naive RIB/FIB split: compiledfib for lookups,
// bitwalk for hierarchy, plus a payload catalogue. Two full indexes for
// one snapshot. We kept it as the "do both jobs independently" analogue;
// fiborderwalk is the tighter version and we still didn't ship that
package fibbitwalk

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/old/bitwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// RouteID identifies a route within one immutable snapshot
type RouteID = routeid.ID

type routeEntry[V any] struct {
	prefix netip.Prefix
	value  V
}

// Table is a conventional RIB/FIB split. A compiled table serves lookups while
// a walk trie independently retains hierarchy. Both are built as one generation
// Honest about the cost: we store every prefix twice
type Table[V any] struct {
	fib    *compiledfib.Table[routeid.ID]
	rib    *bitwalk.Table[routeid.ID]
	routes []routeEntry[V]
}

// New builds separate immutable forwarding and hierarchy indexes. Dedup
// into a 1-based catalogue, then feed the same ID slice to both builders
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	routes, indexed, err := prepareRoutes(entries)
	if err != nil {
		return nil, err
	}
	fib, err := compiledfib.New(indexed, routeupdate.Options{})
	if err != nil {
		return nil, err
	}
	rib, err := bitwalk.New(indexed)
	if err != nil {
		return nil, err
	}
	return &Table[V]{fib: fib, rib: rib, routes: routes}, nil
}

// Lookup returns the matched route ID and value. FIB does LPM; we unpack
func (t *Table[V]) Lookup(addr netip.Addr) (routeid.ID, V, bool) {
	id, ok := t.fib.Lookup(addr)
	return t.result(id, ok)
}

// Lookup4 is the decoded IPv4 fast path. Same unpack as Lookup
func (t *Table[V]) Lookup4(addr uint32) (routeid.ID, V, bool) {
	id, ok := t.fib.Lookup4(addr)
	return t.result(id, ok)
}

// Lookup6 is the decoded IPv6 fast path
func (t *Table[V]) Lookup6(hi, lo uint64) (routeid.ID, V, bool) {
	id, ok := t.fib.Lookup6(hi, lo)
	return t.result(id, ok)
}

// result maps a FIB hit onto the catalogue payload. Misses stay (0, zero, false)
func (t *Table[V]) result(id routeid.ID, ok bool) (routeid.ID, V, bool) {
	if ok {
		return id, t.routes[id].value, true
	}
	var zero V
	return 0, zero, false
}

// WalkParents visits matching routes from most-specific to least-specific
// We ignore bitwalk's reconstructed prefix and serve our own catalogue copy
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(routeid.ID, netip.Prefix, V) bool) {
	t.rib.WalkParents(addr, func(_ netip.Prefix, id routeid.ID) bool {
		route := &t.routes[id]
		return yield(id, route.prefix, route.value)
	})
}

// WalkDescendants visits an exact route and all recursively contained routes
// Same catalogue remap as WalkParents; the rib does the topology walk
func (t *Table[V]) WalkDescendants(prefix netip.Prefix, yield func(routeid.ID, netip.Prefix, V) bool) bool {
	return t.rib.WalkDescendants(prefix, func(_ netip.Prefix, id routeid.ID) bool {
		route := &t.routes[id]
		return yield(id, route.prefix, route.value)
	})
}

// prepareRoutes normalises, last-wins-dedups, sorts into preorder, and
// stamps 1-based IDs. Unlike fiborderwalk we don't compute parent/end -
// bitwalk owns hierarchy, we just need a stable catalogue
func prepareRoutes[V any](entries []prefixentry.Entry[V]) ([]routeEntry[V], []prefixentry.Entry[routeid.ID], error) {
	dedup := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, nil, prefixentry.ErrBadIP
		}
		dedup[prefix] = entry.Value
	}
	prefixes := make([]netip.Prefix, 0, len(dedup))
	for prefix := range dedup {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixPreorderLess(prefixes[i], prefixes[j]) })
	routes := make([]routeEntry[V], len(prefixes)+1)
	indexed := make([]prefixentry.Entry[routeid.ID], len(prefixes))
	for i, prefix := range prefixes {
		id := routeid.ID(i + 1)
		routes[id] = routeEntry[V]{prefix: prefix, value: dedup[prefix]}
		indexed[i] = prefixentry.Entry[routeid.ID]{Prefix: prefix, Value: id}
	}
	return routes, indexed, nil
}

// prefixPreorderLess is v4-before-v6, shorter-first on the same address,
// else numeric. Matches the other snapshot builders so IDs line up in tests
func prefixPreorderLess(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if a.Addr() == b.Addr() {
		return a.Bits() < b.Bits()
	}
	return a.Addr().Less(b.Addr())
}
