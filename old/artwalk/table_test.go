package artwalk

import (
	"net/netip"
	"slices"
	"testing"
)

// prefix is a test helper that panics on a bad CIDR string
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr is a test helper that panics on a bad address string
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestTableTraversal checks the walk API this type exists for: Supernets
// longest-first, Subnets including self, Parent one hop up. Nested v4
func TestTableTraversal(t *testing.T) {
	table := New[string]()
	for _, e := range []struct{ p, v string }{{"0.0.0.0/0", "default"}, {"10.0.0.0/8", "a"}, {"10.1.0.0/16", "b"}, {"10.1.2.0/24", "c"}, {"10.1.2.3/32", "d"}} {
		table.Insert(prefix(e.p), e.v)
	}
	var super []string
	table.Supernets(addr("10.1.2.3"), func(_ netip.Prefix, v string) bool { super = append(super, v); return true })
	if want := []string{"d", "c", "b", "a", "default"}; !slices.Equal(super, want) {
		t.Fatalf("Supernets = %v, want %v", super, want)
	}
	var sub []string
	table.Subnets(prefix("10.1.0.0/16"), func(_ netip.Prefix, v string) bool { sub = append(sub, v); return true })
	if want := []string{"b", "c", "d"}; !slices.Equal(sub, want) {
		t.Fatalf("Subnets = %v, want %v", sub, want)
	}
	if p, v, ok := table.Parent(prefix("10.1.2.0/24")); !ok || p != prefix("10.1.0.0/16") || v != "b" {
		t.Fatalf("Parent = (%v, %q, %v)", p, v, ok)
	}
}
