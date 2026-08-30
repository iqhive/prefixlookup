package artset

import (
	"net/netip"
	"testing"
)

// TestSet is the membership smoke test: insert a mix of v4/v6, check hits and
// misses, then delete everything and assert Size is zero
func TestSet(t *testing.T) {
	s := New()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("2001:db8:2:3::/64"),
	}
	for _, prefix := range prefixes {
		if !s.Insert(prefix) {
			t.Fatalf("Insert(%v) = false", prefix)
		}
	}
	for _, address := range []string{"10.1.2.3", "192.0.2.200", "2001:db8:1::1", "2001:db8:2:3::1"} {
		if !s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = false", address)
		}
	}
	for _, address := range []string{"11.1.2.3", "192.0.2.100", "2001:db8:2::1", "2001:db8:2:4::1"} {
		if s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = true", address)
		}
	}
	for _, prefix := range prefixes {
		if !s.Delete(prefix) {
			t.Fatalf("Delete(%v) = false", prefix)
		}
	}
	if s.Size() != 0 {
		t.Fatalf("Size() = %d", s.Size())
	}
}
