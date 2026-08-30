package fibbitwalk

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
)

// TestTableLookupAndTopology checks the split: FIB LPM, RIB parent walk,
// RIB descendant walk on a v6 subtree. Catalogue IDs have to line up
func TestTableLookupAndTopology(t *testing.T) {
	table, err := New(testEntries())
	if err != nil {
		t.Fatal(err)
	}
	if _, got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 4 {
		t.Fatalf("Lookup() = %d, %v; want 4, true", got, ok)
	}
	var parents []string
	table.WalkParents(netip.MustParseAddr("10.1.2.3"), func(_ routeid.ID, prefix netip.Prefix, _ uint32) bool {
		parents = append(parents, prefix.String())
		return true
	})
	wantParents := []string{"10.1.2.0/24", "10.1.0.0/16", "10.0.0.0/8", "0.0.0.0/0"}
	if !slices.Equal(parents, wantParents) {
		t.Fatalf("parents = %v; want %v", parents, wantParents)
	}
	var descendants []string
	ok := table.WalkDescendants(netip.MustParsePrefix("2001:db8::/32"), func(_ routeid.ID, prefix netip.Prefix, _ uint32) bool {
		descendants = append(descendants, prefix.String())
		return true
	})
	wantDescendants := []string{"2001:db8::/32", "2001:db8:1::/48"}
	if !ok || !slices.Equal(descendants, wantDescendants) {
		t.Fatalf("descendants = %v, %v; want %v, true", descendants, ok, wantDescendants)
	}
}

// TestDuplicatePrefixLastWins checks the catalogue last-wins on a repeated
// prefix. FIB and RIB both see the later ID
func TestDuplicatePrefixLastWins(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	table, err := New([]prefixentry.Entry[int]{{Prefix: prefix, Value: 1}, {Prefix: prefix, Value: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 2 {
		t.Fatalf("Lookup() = %d, %v; want 2, true", got, ok)
	}
}

// testEntries is the mixed nested fixture the topology test walks
func testEntries() []prefixentry.Entry[uint32] {
	return []prefixentry.Entry[uint32]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 3},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 4},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 5},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Value: 6},
	}
}
