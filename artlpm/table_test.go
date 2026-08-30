package artlpm

import (
	"net/netip"
	"testing"
)

// prefix parses s or panics, just so the tests aren't full of MustParsePrefix
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr parses s or panics, same idea as prefix
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// TestTableLookup is the smoke test: insert a handful of v4/v6 routes, check
// LPM, mapped addrs, LookupPrefix, then delete and make sure we fall back
func TestTableLookup(t *testing.T) {
	table := New[string]()
	for p, v := range map[string]string{
		"0.0.0.0/0": "default4", "10.0.0.0/8": "private", "10.1.2.0/24": "lan",
		"::/0": "default6", "2001:db8::/32": "documentation",
	} {
		if !table.Insert(prefix(p), v) {
			t.Fatalf("Insert(%s) = false", p)
		}
	}
	for a, want := range map[string]string{
		"10.1.2.9": "lan", "10.9.0.1": "private", "192.0.2.1": "default4",
		"::ffff:10.1.2.9": "lan", "2001:db8::1": "documentation", "2001:4860::1": "default6",
	} {
		got, ok := table.Lookup(addr(a))
		if !ok || got != want {
			t.Errorf("Lookup(%s) = (%q, %v), want (%q, true)", a, got, ok, want)
		}
	}
	if got, ok := table.LookupPrefix(prefix("10.1.2.128/25")); !ok || got != "lan" {
		t.Fatalf("LookupPrefix = (%q, %v), want (lan, true)", got, ok)
	}
	if !table.Delete(prefix("10.1.2.0/24")) {
		t.Fatal("Delete = false")
	}
	if got, _ := table.Lookup(addr("10.1.2.9")); got != "private" {
		t.Fatalf("post-delete Lookup = %q", got)
	}
}
