package fiborderwalk_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/iqhive/prefixlookup/old/fiborderwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
)

// TestTableLookupAndTopology checks the three things this snapshot is
// supposed to do: LPM, parent walk via the preorder parent IDs, and
// descendant walk via the [id, end) slice. Tiny nested v4 tree
func TestTableLookupAndTopology(t *testing.T) {
	entries := []prefixentry.Entry[uint32]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 3},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 4},
	}
	table, err := fiborderwalk.New(entries)
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
	ok := table.WalkDescendants(netip.MustParsePrefix("10.0.0.1/8"), func(_ routeid.ID, prefix netip.Prefix, _ uint32) bool {
		descendants = append(descendants, prefix.String())
		return true
	})
	wantDescendants := []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"}
	if !ok || !slices.Equal(descendants, wantDescendants) {
		t.Fatalf("descendants = %v, %v; want %v, true", descendants, ok, wantDescendants)
	}
	if _, got, ok := table.Exact(netip.MustParsePrefix("10.1.2.99/24")); !ok || got != 4 {
		t.Fatalf("Exact() = %d, %v; want 4, true", got, ok)
	}
}

// TestDuplicatePrefixLastWins checks the catalogue map overwrites on a
// repeated prefix. We insert 1 then 2 and expect Lookup to serve 2
func TestDuplicatePrefixLastWins(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	table, err := fiborderwalk.New([]prefixentry.Entry[int]{{Prefix: prefix, Value: 1}, {Prefix: prefix, Value: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 2 {
		t.Fatalf("Lookup() = %d, %v; want 2, true", got, ok)
	}
}
