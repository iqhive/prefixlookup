package bitfrontlpm_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/old/bitfrontlpm"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// TestTableLookupAndInvalidInput checks the hybrid path: /24 hit (front
// plus resume), /8 hit (front value, no deeper node needed), default, v6
// full walk, then New rejects the zero prefix
func TestTableLookupAndInvalidInput(t *testing.T) {
	table, err := bitfrontlpm.New([]prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 3},
		{Prefix: netip.MustParsePrefix("::/0"), Value: 4},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		addr string
		want int
	}{
		{"10.1.2.3", 3},
		{"10.2.3.4", 2},
		{"192.0.2.1", 1},
		{"2001:db8::1", 5},
		{"2001:db9::1", 4},
	} {
		if got, ok := table.Lookup(netip.MustParseAddr(test.addr)); !ok || got != test.want {
			t.Errorf("Lookup(%s) = %d, %v; want %d, true", test.addr, got, ok, test.want)
		}
	}
	if _, err := bitfrontlpm.New([]prefixentry.Entry[int]{{Prefix: netip.Prefix{}, Value: 1}}); err != prefixentry.ErrBadIP {
		t.Fatalf("New() error = %v, want %v", err, prefixentry.ErrBadIP)
	}
}
