package thinrangeset

import (
	"net/netip"
	"testing"
)

// prefixes parses CIDR strings into a slice. Helper so the tests stay
// readable
func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(values))
	for i, value := range values {
		out[i] = netip.MustParsePrefix(value)
	}
	return out
}

// build compiles a set from CIDR strings and fatals on a bad prefix
func build(t *testing.T, values ...string) *Set {
	t.Helper()
	set, err := New(prefixes(t, values...))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// assertMatches checks Match against each address. want is the same for
// the whole batch because that's how these tests are written
func assertMatches(t *testing.T, set *Set, want bool, addresses ...string) {
	t.Helper()
	for _, address := range addresses {
		if got := set.Match(netip.MustParseAddr(address)); got != want {
			t.Fatalf("Match(%s) = %v, want %v", address, got, want)
		}
	}
}

// TestDisjointRangesKeepGaps is the central check on the boundary encoding:
// the space between two disjoint ranges must not be absorbed into either
func TestDisjointRangesKeepGaps(t *testing.T) {
	set := build(t, "10.0.0.0/8", "192.0.2.0/24", "2001:db8:1::/48", "2001:db8:3::/48")
	assertMatches(t, set, true, "10.1.2.3", "192.0.2.10", "2001:db8:1::1", "2001:db8:3::1")
	assertMatches(t, set, false, "11.0.0.0", "192.0.3.1", "2001:db8:2::1", "2001:db8:4::1")
}

// TestNarrowGapBetweenRanges checks a one-address hole, the tightest case
// the encoding has to represent
func TestNarrowGapBetweenRanges(t *testing.T) {
	set := build(t, "10.0.0.0/31", "10.0.0.3/32")
	assertMatches(t, set, true, "10.0.0.0", "10.0.0.1", "10.0.0.3")
	assertMatches(t, set, false, "10.0.0.2", "10.0.0.4")
}

// TestAdjacentPrefixesMerge checks that touching prefixes collapse into
// one range, so the encoding emits no transition between them
func TestAdjacentPrefixesMerge(t *testing.T) {
	set := build(t, "10.0.0.0/25", "10.0.0.128/25")
	if set.Ranges() != 1 {
		t.Fatalf("Ranges() = %d, want 1", set.Ranges())
	}
	assertMatches(t, set, true, "10.0.0.0", "10.0.0.127", "10.0.0.128", "10.0.0.255")
	assertMatches(t, set, false, "10.0.1.0")
}

// TestBoundaryEdgesOfAddressSpace covers ranges that touch the very bottom
// and very top of each family, where wrapping would lie
func TestBoundaryEdgesOfAddressSpace(t *testing.T) {
	set := build(t, "0.0.0.0/8", "255.255.255.255/32")
	assertMatches(t, set, true, "0.0.0.0", "0.255.255.255", "255.255.255.255")
	assertMatches(t, set, false, "1.0.0.0", "255.255.255.254")

	v6 := build(t, "::/16", "ffff::/16")
	assertMatches(t, v6, true, "::", "::1", "ffff::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	assertMatches(t, v6, false, "1::", "fffe::1")
}

// TestDefaultRoutesCoverEverything checks /0 in both families still
// match everything, and we didn't accidentally merge across families
func TestDefaultRoutesCoverEverything(t *testing.T) {
	set := build(t, "0.0.0.0/0", "::/0")
	assertMatches(t, set, true, "0.0.0.0", "8.8.8.8", "255.255.255.255", "::", "2001:db8::1")
	if set.Ranges() != 2 {
		t.Fatalf("Ranges() = %d, want 2", set.Ranges())
	}
}

// TestIPv6LowWordBoundaries exercises prefixes longer than /64, which force
// the low-word array to be materialised and consulted on high-word ties
func TestIPv6LowWordBoundaries(t *testing.T) {
	set := build(t, "2001:db8::/128", "2001:db8::2/127", "2001:db8::8/125")
	assertMatches(t, set, true, "2001:db8::", "2001:db8::2", "2001:db8::3", "2001:db8::8", "2001:db8::f")
	assertMatches(t, set, false, "2001:db8::1", "2001:db8::4", "2001:db8::7", "2001:db8::10")
}

// TestIPv6CarryAcrossWords checks a range ending at the maximum low word,
// whose next address carries into the high word
func TestIPv6CarryAcrossWords(t *testing.T) {
	set := build(t, "2001:db8::/64")
	assertMatches(t, set, true, "2001:db8::", "2001:db8::ffff:ffff:ffff:ffff")
	assertMatches(t, set, false, "2001:db8:0:1::", "2001:db7:ffff:ffff::1")
}

// TestSingleFamilySets checks a v6-only set doesn't match v4 and vice versa
func TestSingleFamilySets(t *testing.T) {
	v6 := build(t, "2001:db8::/32")
	assertMatches(t, v6, false, "192.0.2.1", "0.0.0.0")
	assertMatches(t, v6, true, "2001:db8::1")

	v4 := build(t, "192.0.2.0/24")
	assertMatches(t, v4, false, "2001:db8::1", "::")
	assertMatches(t, v4, true, "192.0.2.1")
}

// TestEmptySetMatchesNothing checks the zero-range path, including no
// classifier
func TestEmptySetMatchesNothing(t *testing.T) {
	set := build(t)
	assertMatches(t, set, false, "0.0.0.0", "8.8.8.8", "::", "2001:db8::1")
	if set.Ranges() != 0 {
		t.Fatalf("Ranges() = %d, want 0", set.Ranges())
	}
}

// TestClassifierThreshold builds a set on both sides of the point at which
// the /16 classifier is materialised, so both lookup paths are covered
func TestClassifierThreshold(t *testing.T) {
	for _, count := range []int{frontThreshold - 1, frontThreshold + 1} {
		values := make([]netip.Prefix, 0, count)
		for i := 0; i < count; i++ {
			// spaced two /16s apart so no two ranges merge
			addr := netip.AddrFrom4([4]byte{10, byte(i * 2), 0, 0})
			values = append(values, netip.PrefixFrom(addr, 16))
		}
		set, err := New(values)
		if err != nil {
			t.Fatal(err)
		}
		if set.Ranges() != count {
			t.Fatalf("count=%d: Ranges() = %d", count, set.Ranges())
		}
		if hasFront := set.v4Front != nil; hasFront != (count >= frontThreshold) {
			t.Fatalf("count=%d: classifier present = %v", count, hasFront)
		}
		for i := 0; i < count; i++ {
			hit := netip.AddrFrom4([4]byte{10, byte(i * 2), 3, 4})
			if !set.Match(hit) {
				t.Fatalf("count=%d: Match(%v) = false", count, hit)
			}
			miss := netip.AddrFrom4([4]byte{10, byte(i*2 + 1), 3, 4})
			if set.Match(miss) {
				t.Fatalf("count=%d: Match(%v) = true", count, miss)
			}
		}
	}
}

// TestMappedAddressesUnmap checks that IPv4-mapped IPv6 addresses resolve
// against the IPv4 ranges
func TestMappedAddressesUnmap(t *testing.T) {
	set := build(t, "192.0.2.0/24")
	assertMatches(t, set, true, "::ffff:192.0.2.1")
	assertMatches(t, set, false, "::ffff:192.0.3.1")
}

// TestRejectsInvalidPrefix checks New fails on the zero prefix and Match
// rejects the zero address
func TestRejectsInvalidPrefix(t *testing.T) {
	if _, err := New([]netip.Prefix{{}}); err == nil {
		t.Fatal("New accepted the zero prefix")
	}
	set := build(t, "10.0.0.0/8")
	if set.Match(netip.Addr{}) {
		t.Fatal("Match accepted the zero address")
	}
}

// TestUnsortedAndDuplicateInput checks that construction is independent of
// input order and of repeated prefixes
func TestUnsortedAndDuplicateInput(t *testing.T) {
	set := build(t, "192.0.2.0/24", "10.0.0.0/8", "192.0.2.0/24", "10.1.0.0/16")
	if set.Ranges() != 2 {
		t.Fatalf("Ranges() = %d, want 2", set.Ranges())
	}
	assertMatches(t, set, true, "10.1.2.3", "192.0.2.5")
	assertMatches(t, set, false, "11.1.2.3", "192.0.3.5")
}
