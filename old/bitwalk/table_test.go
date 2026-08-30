package bitwalk_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/iqhive/prefixlookup/old/bitwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// TestLookupParentsAndDescendants checks LPM plus both walk directions on
// a nested v4 tree. Parents most-specific-first; descendants preorder
func TestLookupParentsAndDescendants(t *testing.T) {
	entries := []prefixentry.Entry[uint32]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 3},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 4},
	}
	table, err := bitwalk.New(entries)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(netip.MustParseAddr("10.1.2.9")); !ok || got != 4 {
		t.Fatalf("Lookup() = %d, %v; want 4, true", got, ok)
	}
	var parents []string
	table.WalkParents(netip.MustParseAddr("10.1.2.9"), func(prefix netip.Prefix, _ uint32) bool {
		parents = append(parents, prefix.String())
		return true
	})
	wantParents := []string{"10.1.2.0/24", "10.1.0.0/16", "10.0.0.0/8", "0.0.0.0/0"}
	if !slices.Equal(parents, wantParents) {
		t.Fatalf("parents = %v; want %v", parents, wantParents)
	}
	var descendants []string
	ok := table.WalkDescendants(netip.MustParsePrefix("10.0.0.0/8"), func(prefix netip.Prefix, _ uint32) bool {
		descendants = append(descendants, prefix.String())
		return true
	})
	wantDescendants := []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"}
	if !ok || !slices.Equal(descendants, wantDescendants) {
		t.Fatalf("descendants = %v, %v; want %v, true", descendants, ok, wantDescendants)
	}
}

// TestRejectsInvalidPrefix checks New fails on the zero prefix
func TestRejectsInvalidPrefix(t *testing.T) {
	_, err := bitwalk.New([]prefixentry.Entry[int]{{Prefix: netip.Prefix{}, Value: 1}})
	if err != prefixentry.ErrBadIP {
		t.Fatalf("New error = %v, want %v", err, prefixentry.ErrBadIP)
	}
}
