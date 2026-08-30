package flatwalk

import (
	"net/netip"
	"sort"
)

// sortPrefixes orders prefixes into the preorder sequence the descendant
// scan relies on: IPv4 before IPv6, then by address, then shortest first
// so a route precedes everything nested inside it - don't reorder the
// keys, WalkDescendants assumes this
func sortPrefixes(prefixes []netip.Prefix) {
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
