package soarangeset

import (
	"net/netip"
	"testing"
)

// TestDisjointRangesKeepGaps is the central check on the range encoding:
// space between two disjoint ranges must not get absorbed into either
// Hits inside, misses in the gaps, both families
func TestDisjointRangesKeepGaps(t *testing.T) {
	set, err := New([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("2001:db8:3::/48"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.1.2.3", "192.0.2.10", "2001:db8:1::1", "2001:db8:3::1"} {
		if !set.Match(netip.MustParseAddr(address)) {
			t.Fatalf("Match(%s) = false", address)
		}
	}
	for _, address := range []string{"11.0.0.0", "192.0.3.1", "2001:db8:2::1", "2001:db8:4::1"} {
		if set.Match(netip.MustParseAddr(address)) {
			t.Fatalf("Match(%s) = true", address)
		}
	}
}

// TestIPv6Only checks a v6-only set doesn't accidentally match v4 (no
// front table, empty v4 arrays) and still hits its own prefix
func TestIPv6Only(t *testing.T) {
	set, err := New([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")})
	if err != nil {
		t.Fatal(err)
	}
	if set.Match(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("IPv6-only set matched IPv4")
	}
	if !set.Match(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 prefix did not match")
	}
}
