package tests_test

import (
	"net/netip"
	"sort"
	"testing"

	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/old/bitwalk"
	"github.com/iqhive/prefixlookup/old/fiborderwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
	"github.com/iqhive/prefixlookup/splitribfib"
)

// hierarchyEntries is the tiny nested v4 chain plus a v6 chain we reuse
// whenever we want a known Supernets/Subnets/Parent answer - values are the
// prefix lengths (or 1000+length for v6) so a wrong hop is obvious in the dump
func hierarchyEntries() []prefixentry.Entry[int] {
	return []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 0},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 8},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 16},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 24},
		{Prefix: netip.MustParsePrefix("10.1.2.3/32"), Value: 32},
		{Prefix: netip.MustParsePrefix("10.1.3.0/24"), Value: 124},
		{Prefix: netip.MustParsePrefix("::/0"), Value: 1000},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 1032},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Value: 1048},
	}
}

// TestRIBTraversalAgainstOracle loads hierarchyEntries into artwalk and
// checks Supernets order (longest first), Subnets vs the oracle descendants,
// and Parent of a /25 sitting under the /24
func TestRIBTraversalAgainstOracle(t *testing.T) {
	rib := artwalk.New[int]()
	o := newOracle()
	for _, entry := range hierarchyEntries() {
		rib.Insert(entry.Prefix, entry.Value)
		o.insert(entry.Prefix, entry.Value)
	}
	addr := netip.MustParseAddr("10.1.2.3")
	var got []netip.Prefix
	rib.Supernets(addr, func(prefix netip.Prefix, _ int) bool { got = append(got, prefix); return true })
	want := covering(o, addr)
	if !samePrefixes(got, want) {
		t.Fatalf("Supernets = %v, want %v", got, want)
	}
	if len(got) != 5 || got[0].Bits() != 32 || got[4].Bits() != 0 {
		t.Fatalf("Supernets order = %v", got)
	}

	query := netip.MustParsePrefix("10.1.0.0/16")
	got = nil
	rib.Subnets(query, func(prefix netip.Prefix, _ int) bool { got = append(got, prefix); return true })
	want = descendants(o, query)
	sortPrefixSlice(got)
	sortPrefixSlice(want)
	if !samePrefixes(got, want) {
		t.Fatalf("Subnets = %v, want %v", got, want)
	}
	parent, value, ok := rib.Parent(netip.MustParsePrefix("10.1.2.128/25"))
	if !ok || parent != netip.MustParsePrefix("10.1.2.0/24") || value != 24 {
		t.Fatalf("Parent = (%v,%d,%v)", parent, value, ok)
	}
}

// TestImmutableTraversalAndExact is the same hierarchy against bitwalk /
// fiborderwalk / splitribfib - WalkParents payloads, Exact on a non-canonical
// /24, WalkDescendants of 10.1/16
func TestImmutableTraversalAndExact(t *testing.T) {
	entries := hierarchyEntries()
	wt, err := bitwalk.New(entries)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := fiborderwalk.New(entries)
	if err != nil {
		t.Fatal(err)
	}
	split, err := splitribfib.New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("10.1.2.3")
	want := []int{32, 24, 16, 8, 0}

	var got []int
	wt.WalkParents(addr, func(_ netip.Prefix, value int) bool { got = append(got, value); return true })
	if !sameInts(got, want) {
		t.Fatalf("bitwalk parents = %v", got)
	}
	got = nil
	pre.WalkParents(addr, func(_ fiborderwalk.RouteID, _ netip.Prefix, value int) bool { got = append(got, value); return true })
	if !sameInts(got, want) {
		t.Fatalf("fiborderwalk parents = %v", got)
	}
	got = nil
	split.WalkParents(addr, func(_ routeid.ID, _ netip.Prefix, value int) bool { got = append(got, value); return true })
	if !sameInts(got, want) {
		t.Fatalf("split parents = %v", got)
	}
	if _, value, ok := pre.Exact(netip.MustParsePrefix("10.1.2.99/24")); !ok || value != 24 {
		t.Fatalf("Exact = (%d,%v)", value, ok)
	}

	query := netip.MustParsePrefix("10.1.0.0/16")
	for name, walk := range map[string]func(func(netip.Prefix, int) bool) bool{
		"bitwalk": func(y func(netip.Prefix, int) bool) bool {
			return wt.WalkDescendants(query, y)
		},
		"fiborderwalk": func(y func(netip.Prefix, int) bool) bool {
			return pre.WalkDescendants(query, func(_ fiborderwalk.RouteID, p netip.Prefix, v int) bool { return y(p, v) })
		},
		"splitribfib": func(y func(netip.Prefix, int) bool) bool {
			return split.WalkDescendants(query, func(_ routeid.ID, p netip.Prefix, v int) bool { return y(p, v) })
		},
	} {
		gotPrefixes := []netip.Prefix{}
		if !walk(func(prefix netip.Prefix, _ int) bool { gotPrefixes = append(gotPrefixes, prefix); return true }) {
			t.Fatalf("%s query absent", name)
		}
		wantPrefixes := []netip.Prefix{query, netip.MustParsePrefix("10.1.2.0/24"), netip.MustParsePrefix("10.1.2.3/32"), netip.MustParsePrefix("10.1.3.0/24")}
		sortPrefixSlice(gotPrefixes)
		sortPrefixSlice(wantPrefixes)
		if !samePrefixes(gotPrefixes, wantPrefixes) {
			t.Fatalf("%s descendants = %v", name, gotPrefixes)
		}
	}
}

// covering is the oracle Supernets - every stored prefix that Contains addr,
// longest first
func covering(o *oracle, addr netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for prefix := range o.values {
		if prefix.Contains(addr) {
			out = append(out, prefix)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bits() > out[j].Bits() })
	return out
}

// descendants is the oracle Subnets - prefixes at least as long as query
// whose addr sits inside query (so we pick up the query itself too)
func descendants(o *oracle, query netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for prefix := range o.values {
		if prefix.Bits() >= query.Bits() && query.Contains(prefix.Addr()) {
			out = append(out, prefix)
		}
	}
	return out
}

// sortPrefixSlice orders by bits then addr so we can compare Subnets dumps
// without caring about walk order
func sortPrefixSlice(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
}

// samePrefixes is elementwise prefix equality - lengths first so we don't
// walk off the end
func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameInts is the payload-chain comparator we use for WalkParents dumps
func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
