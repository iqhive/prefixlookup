package latticeartset

import (
	"net/netip"
	"testing"
)

// prefix is a test helper that panics on a bad CIDR string
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr is a test helper that panics on a bad address string
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestSetMembershipAndEnumeration is the smoke test we reuse as the
// equivalence reference: insert, Contains hits/misses, All, Delete
func TestSetMembershipAndEnumeration(t *testing.T) {
	set := New()
	for _, p := range []string{"10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"} {
		set.Insert(prefix(p))
	}
	for _, a := range []string{"10.255.0.1", "192.168.1.99", "2001:db8::7"} {
		if !set.Contains(addr(a)) {
			t.Errorf("Contains(%s) = false", a)
		}
	}
	for _, a := range []string{"11.0.0.1", "192.168.2.1", "2001:db9::1"} {
		if set.Contains(addr(a)) {
			t.Errorf("Contains(%s) = true", a)
		}
	}
	seen := map[netip.Prefix]bool{}
	set.All(func(p netip.Prefix) bool { seen[p] = true; return true })
	if len(seen) != 3 {
		t.Fatalf("All returned %d prefixes", len(seen))
	}
	if !set.Delete(prefix("10.0.0.0/8")) || set.Contains(addr("10.1.1.1")) {
		t.Fatal("set deletion failed")
	}
}
