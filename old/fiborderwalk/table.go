// Package fiborderwalk is the "one snapshot, two jobs" experiment: compiledfib
// for LPM plus a preorder route catalogue so WalkDescendants is a slice scan
// We kept it for equivalence tests; we don't ship it because the parent/end
// bookkeeping is more fiddly than it's worth versus walking a proper ART
package fiborderwalk

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// RouteID identifies a route within one immutable snapshot
type RouteID = routeid.ID

type routeEntry[V any] struct {
	prefix netip.Prefix
	value  V
	parent routeid.ID
	end    routeid.ID
}

// Table combines a compiled FIB with an immutable exact-prefix map and a
// preorder route catalogue. Parent walks chase compact indexes; every
// descendant subtree is one contiguous slice. Cute idea, lots of glue
type Table[V any] struct {
	fib    *compiledfib.Table[routeid.ID]
	routes []routeEntry[V]
	exact  map[netip.Prefix]routeid.ID
}

// New builds the read-mostly combined index. We normalise, last-wins-dedup,
// sort into preorder, then stamp parent/end on a stack walk and hand the IDs
// to compiledfib. Fail the whole build on a bad prefix; no half-tables
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	routes, indexed, err := prepareRoutes(entries)
	if err != nil {
		return nil, err
	}
	fib, err := compiledfib.New(indexed, routeupdate.Options{})
	if err != nil {
		return nil, err
	}
	exact := make(map[netip.Prefix]routeid.ID, len(routes)-1)
	for id := routeid.ID(1); int(id) < len(routes); id++ {
		exact[routes[id].prefix] = id
	}
	return &Table[V]{fib: fib, routes: routes, exact: exact}, nil
}

// Lookup returns the matched route ID and value. Thin wrapper: compiledfib
// does the LPM, we just unpack the payload from the catalogue
func (t *Table[V]) Lookup(addr netip.Addr) (routeid.ID, V, bool) {
	id, ok := t.fib.Lookup(addr)
	return t.result(id, ok)
}

// Lookup4 is the decoded IPv4 fast path. Same as Lookup but we skip netip
func (t *Table[V]) Lookup4(addr uint32) (routeid.ID, V, bool) {
	id, ok := t.fib.Lookup4(addr)
	return t.result(id, ok)
}

// Lookup6 is the decoded IPv6 fast path. Same unpack as Lookup4
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

// Exact returns the route ID and value for an exact canonical prefix. Hash
// lookup after we normalise; not LPM, so a covering ancestor doesn't count
func (t *Table[V]) Exact(input netip.Prefix) (routeid.ID, V, bool) {
	prefix, ok := prefixentry.NormalizePrefix(input)
	if ok {
		if id, found := t.exact[prefix]; found {
			return id, t.routes[id].value, true
		}
	}
	var zero V
	return 0, zero, false
}

// WalkParents visits the matched route and its stored ancestors. LPM once,
// then chase parent IDs until we hit the dummy root. yield false bails early
func (t *Table[V]) WalkParents(addr netip.Addr, yield func(routeid.ID, netip.Prefix, V) bool) {
	id, _, ok := t.Lookup(addr)
	for ok && id != 0 {
		route := &t.routes[id]
		if !yield(id, route.prefix, route.value) {
			return
		}
		id = route.parent
	}
}

// WalkDescendants visits an exact route and all descendants by scanning its
// contiguous preorder interval. That's the whole trick: [id, end) is the
// subtree. False if the exact prefix isn't stored
func (t *Table[V]) WalkDescendants(prefix netip.Prefix, yield func(routeid.ID, netip.Prefix, V) bool) bool {
	id, _, ok := t.Exact(prefix)
	if !ok {
		return false
	}
	end := t.routes[id].end
	for current := id; current < end; current++ {
		route := &t.routes[current]
		if !yield(current, route.prefix, route.value) {
			break
		}
	}
	return true
}

// prepareRoutes normalises, last-wins-dedups, then sorts into preorder and
// stamps parent/end with an ancestor stack. Dummy slot 0 keeps IDs 1-based
// so a zero parent is "no parent" without a sentinel type. This is the bit
// we got tired of maintaining
func prepareRoutes[V any](entries []prefixentry.Entry[V]) ([]routeEntry[V], []prefixentry.Entry[routeid.ID], error) {
	dedup := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, nil, prefixentry.ErrBadIP
		}
		// last-wins; we don't care about insert order
		dedup[prefix] = entry.Value
	}
	prefixes := make([]netip.Prefix, 0, len(dedup))
	for prefix := range dedup {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixPreorderLess(prefixes[i], prefixes[j]) })
	routes := make([]routeEntry[V], len(prefixes)+1)
	indexed := make([]prefixentry.Entry[routeid.ID], len(prefixes))
	stack := make([]routeid.ID, 0, 129)
	for i, prefix := range prefixes {
		id := routeid.ID(i + 1)
		// pop ancestors that don't contain this prefix; their subtree just ended
		for len(stack) > 0 && !routes[stack[len(stack)-1]].prefix.Contains(prefix.Addr()) {
			finished := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			routes[finished].end = id
		}
		var parent routeid.ID
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		routes[id] = routeEntry[V]{prefix: prefix, value: dedup[prefix], parent: parent}
		indexed[i] = prefixentry.Entry[routeid.ID]{Prefix: prefix, Value: id}
		stack = append(stack, id)
	}
	end := routeid.ID(len(routes))
	// leftover ancestors run through to the end of the catalogue
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		routes[id].end = end
	}
	return routes, indexed, nil
}

// prefixPreorderLess is v4-before-v6, then shorter-first on the same address,
// else numeric. That's the order the ancestor stack in prepareRoutes needs
func prefixPreorderLess(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if a.Addr() == b.Addr() {
		return a.Bits() < b.Bits()
	}
	return a.Addr().Less(b.Addr())
}
