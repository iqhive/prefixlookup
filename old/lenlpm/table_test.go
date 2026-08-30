package lenlpm_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/old/lenlpm"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// TestLookup checks longest-first binary search across populated lengths
// Nested v4 plus a couple of v6 rows
func TestLookup(t *testing.T) {
	entries := []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 3},
		{Prefix: netip.MustParsePrefix("::/0"), Value: 4},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 5},
	}
	table, err := lenlpm.New(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		address string
		want    int
	}{{"192.0.2.1", 1}, {"10.2.3.4", 2}, {"10.1.2.3", 3}, {"2001:4860::1", 4}, {"2001:db8::1", 5}} {
		got, ok := table.Lookup(netip.MustParseAddr(tc.address))
		if !ok || got != tc.want {
			t.Errorf("Lookup(%s) = %d, %v; want %d, true", tc.address, got, ok, tc.want)
		}
	}
}

// TestDuplicatePrefixLastWins checks dedupe keeps the later payload index
// and Prefixes() reports the collapsed count
func TestDuplicatePrefixLastWins(t *testing.T) {
	entries := []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 3},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 4},
	}
	table, err := lenlpm.New(entries)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 2 {
		t.Errorf("Lookup(10.1.2.3) = %d, %v; want 2, true", got, ok)
	}
	if got, ok := table.Lookup(netip.MustParseAddr("2001:db8::1")); !ok || got != 4 {
		t.Errorf("Lookup(2001:db8::1) = %d, %v; want 4, true", got, ok)
	}
	if n := table.Prefixes(); n != 2 {
		t.Errorf("Prefixes() = %d; want 2", n)
	}
}

// TestRejectsInvalidPrefix checks New fails on the zero prefix
func TestRejectsInvalidPrefix(t *testing.T) {
	_, err := lenlpm.New([]prefixentry.Entry[int]{{Prefix: netip.Prefix{}, Value: 1}})
	if err != prefixentry.ErrBadIP {
		t.Fatalf("New error = %v, want %v", err, prefixentry.ErrBadIP)
	}
}
