package bitlpm_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/old/bitlpm"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// TestLookup builds the usual nested v4+v6 fixture and checks LPM hits
func TestLookup(t *testing.T) {
	table, err := bitlpm.New(testEntries())
	if err != nil {
		t.Fatal(err)
	}
	assertLookups(t, table.Lookup)
}

// TestRejectsInvalidPrefix checks New fails on the zero prefix rather
// than stuffing a nonsense node into the arena
func TestRejectsInvalidPrefix(t *testing.T) {
	_, err := bitlpm.New([]prefixentry.Entry[int]{{Prefix: netip.Prefix{}, Value: 1}})
	if err != prefixentry.ErrBadIP {
		t.Fatalf("New error = %v, want %v", err, prefixentry.ErrBadIP)
	}
}

// testEntries is the shared nested-prefix fixture. Default plus a few
// nested routes in each family
func testEntries() []prefixentry.Entry[uint32] {
	return []prefixentry.Entry[uint32]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 3},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 4},
		{Prefix: netip.MustParsePrefix("::/0"), Value: 5},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 6},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Value: 7},
	}
}

// assertLookups probes one address per stored prefix, plus a couple of
// "covered by default" misses-that-hit-shorter. Helper so we can reuse
// the table against Lookup
func assertLookups(t *testing.T, lookup func(netip.Addr) (uint32, bool)) {
	t.Helper()
	for _, tc := range []struct {
		address string
		want    uint32
	}{
		{"192.0.2.1", 1}, {"10.2.3.4", 2}, {"10.1.9.1", 3}, {"10.1.2.99", 4},
		{"2001:4860::1", 5}, {"2001:db8:2::1", 6}, {"2001:db8:1::1", 7},
	} {
		got, ok := lookup(netip.MustParseAddr(tc.address))
		if !ok || got != tc.want {
			t.Errorf("Lookup(%s) = %d, %v; want %d, true", tc.address, got, ok, tc.want)
		}
	}
}
