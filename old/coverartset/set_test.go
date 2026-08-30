package coverartset

import (
	"net/netip"
	"testing"
)

// prefix is a test helper that panics on a bad CIDR string
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr is a test helper that panics on a bad address string
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestSetMembershipAndEnumeration is the smoke test: insert a few prefixes,
// Contains hits/misses, All enumerates them, Delete actually removes
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

// TestSetCoverBitsAfterDelete is the coverBits-specific check: two prefixes
// whose coverage overlaps, so deleting one must not clear the other's bits
func TestSetCoverBitsAfterDelete(t *testing.T) {
	set := New()
	// two prefixes whose coverage overlaps, so deleting one must not clear the
	// other's coverage in coverBits
	set.Insert(prefix("10.0.0.0/8"))
	set.Insert(prefix("10.1.0.0/16"))
	if !set.Delete(prefix("10.0.0.0/8")) {
		t.Fatal("delete failed")
	}
	if !set.Contains(addr("10.1.2.3")) {
		t.Fatal("10.1.0.0/16 should still be covered after deleting /8")
	}
	if set.Contains(addr("10.2.0.1")) {
		t.Fatal("10.2.0.1 should no longer be covered")
	}
}

// TestSetPartialCoverage forces frontDeeper: two disjoint /24s in the same
// /16, so the classifier can't answer All/None and we actually descend
func TestSetPartialCoverage(t *testing.T) {
	set := New()
	set.Insert(prefix("192.168.0.0/24"))
	// same /16, disjoint /24: forces frontDeeper and a trie descent
	set.Insert(prefix("192.168.1.0/24"))
	for _, a := range []string{"192.168.0.1", "192.168.1.1"} {
		if !set.Contains(addr(a)) {
			t.Errorf("Contains(%s) = false", a)
		}
	}
	if set.Contains(addr("192.168.2.1")) {
		t.Error("Contains(192.168.2.1) = true")
	}
}
