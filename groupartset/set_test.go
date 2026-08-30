package groupartset

import (
	"net/netip"
	"testing"
)

// TestSet is the membership smoke test: insert a mix of v4/v6, check Size,
// hits and misses, delete everything, then confirm Contains is false
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
	if s.Size() != len(prefixes) {
		t.Fatalf("Size() = %d, want %d", s.Size(), len(prefixes))
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
		t.Fatalf("Size() = %d, want 0", s.Size())
	}
	for _, address := range []string{"10.1.2.3", "192.0.2.200", "2001:db8:1::1"} {
		if s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = true after delete", address)
		}
	}
}

// TestDefaultRoutes covers the zero-length prefixes, which decompose to depth 0
// with a residual length of 0 and so exercise the root coverage path. we also
// check that deleting v4 /0 doesn't take v6 /0 with it
func TestDefaultRoutes(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("0.0.0.0/0"))
	s.Insert(netip.MustParsePrefix("::/0"))
	for _, address := range []string{"0.0.0.0", "8.8.8.8", "255.255.255.255", "::", "2001:db8::1"} {
		if !s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = false", address)
		}
	}
	if !s.Delete(netip.MustParsePrefix("0.0.0.0/0")) {
		t.Fatal("Delete(0.0.0.0/0) = false")
	}
	if s.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("IPv4 default route still matched after delete")
	}
	if !s.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 default route removed by IPv4 delete")
	}
}

// TestShortPrefixSpansFrontSlots checks a prefix shorter than /16, which must
// mark every /16 slot it spans in the classifier. 10/8 should hit 10.0 and
// 10.255 but not 9.x or 11.x
func TestShortPrefixSpansFrontSlots(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	for _, address := range []string{"10.0.0.0", "10.128.0.1", "10.255.255.255"} {
		if !s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = false", address)
		}
	}
	for _, address := range []string{"9.255.255.255", "11.0.0.0"} {
		if s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = true", address)
		}
	}
}

// TestDeeperPrefixUnderCoveredSlot checks that a /16-or-shorter prefix keeps
// its slot marked as wholly covered even when longer prefixes are added under
// it. after we delete the /16, only the leftover /24 should still match
func TestDeeperPrefixUnderCoveredSlot(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("172.16.0.0/16"))
	s.Insert(netip.MustParsePrefix("172.16.5.0/24"))
	for _, address := range []string{"172.16.0.1", "172.16.5.1", "172.16.255.255"} {
		if !s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = false", address)
		}
	}
	if !s.Delete(netip.MustParsePrefix("172.16.0.0/16")) {
		t.Fatal("Delete(172.16.0.0/16) = false")
	}
	if !s.Contains(netip.MustParseAddr("172.16.5.1")) {
		t.Fatal("Contains(172.16.5.1) = false after removing the covering /16")
	}
	if s.Contains(netip.MustParseAddr("172.16.0.1")) {
		t.Fatal("Contains(172.16.0.1) = true after removing the covering /16")
	}
}

// TestLeafSplitOnOverlap forces a path-compressed leaf to be split by a longer
// prefix sharing its leading octets. also checks duplicate Insert returns false
func TestLeafSplitOnOverlap(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("203.0.113.0/24"))
	s.Insert(netip.MustParsePrefix("203.0.113.128/25"))
	s.Insert(netip.MustParsePrefix("203.0.114.0/24"))
	for _, address := range []string{"203.0.113.1", "203.0.113.200", "203.0.114.7"} {
		if !s.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("Contains(%s) = false", address)
		}
	}
	if s.Contains(netip.MustParseAddr("203.0.115.1")) {
		t.Fatal("Contains(203.0.115.1) = true")
	}
	if s.Insert(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatal("duplicate Insert reported a new prefix")
	}
}

// TestHostPrefixes covers the maximum prefix lengths in both families, which
// reach the deepest trie level (/32 and /128)
func TestHostPrefixes(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("198.51.100.7/32"))
	s.Insert(netip.MustParsePrefix("2001:db8::dead:beef/128"))
	if !s.Contains(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("Contains(198.51.100.7) = false")
	}
	if s.Contains(netip.MustParseAddr("198.51.100.8")) {
		t.Fatal("Contains(198.51.100.8) = true")
	}
	if !s.Contains(netip.MustParseAddr("2001:db8::dead:beef")) {
		t.Fatal("Contains(2001:db8::dead:beef) = false")
	}
	if s.Contains(netip.MustParseAddr("2001:db8::dead:bee0")) {
		t.Fatal("Contains(2001:db8::dead:bee0) = true")
	}
}

// TestMappedAddressesUnmap checks that an IPv4-mapped IPv6 address is treated
// as the IPv4 address it encodes. we also insert a mapped /120 and look it up
// as plain v4
func TestMappedAddressesUnmap(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("192.0.2.0/24"))
	if !s.Contains(netip.MustParseAddr("::ffff:192.0.2.1")) {
		t.Fatal("mapped address did not match its IPv4 prefix")
	}
	if !s.Insert(netip.MustParsePrefix("::ffff:198.51.100.0/120")) {
		t.Fatal("mapped prefix insert failed")
	}
	if !s.Contains(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("mapped prefix did not match the plain IPv4 address")
	}
}

// TestAllEnumeratesEveryPrefix inserts a mixed bag, walks All, checks we saw
// each prefix once, then checks that returning false from fn stops the walk
func TestAllEnumeratesEveryPrefix(t *testing.T) {
	s := New()
	want := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.2.0/24"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:1:2::/64"),
	}
	for _, prefix := range want {
		s.Insert(prefix)
	}
	seen := map[netip.Prefix]bool{}
	s.All(func(prefix netip.Prefix) bool {
		if seen[prefix] {
			t.Fatalf("All yielded %v twice", prefix)
		}
		seen[prefix] = true
		return true
	})
	if len(seen) != len(want) {
		t.Fatalf("All yielded %d prefixes, want %d", len(seen), len(want))
	}
	for _, prefix := range want {
		if !seen[prefix] {
			t.Fatalf("All did not yield %v", prefix)
		}
	}
	count := 0
	s.All(func(netip.Prefix) bool { count++; return false })
	if count != 1 {
		t.Fatalf("All continued after fn returned false: %d calls", count)
	}
}

// TestInvalidInputsRejected checks zero Prefix/Addr are ignored by Insert,
// Contains and Delete, and that Size stays 0
func TestInvalidInputsRejected(t *testing.T) {
	s := New()
	if s.Insert(netip.Prefix{}) {
		t.Fatal("Insert accepted the zero prefix")
	}
	if s.Contains(netip.Addr{}) {
		t.Fatal("Contains accepted the zero address")
	}
	if s.Delete(netip.Prefix{}) {
		t.Fatal("Delete accepted the zero prefix")
	}
	if s.Size() != 0 {
		t.Fatalf("Size() = %d, want 0", s.Size())
	}
}

// TestDeleteAbsentPrefixes checks that failed deletions leave the set intact
// we insert 10/8 then try to delete nearby prefixes that aren't there
func TestDeleteAbsentPrefixes(t *testing.T) {
	s := New()
	s.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	for _, prefix := range []string{"10.0.0.0/9", "11.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"} {
		if s.Delete(netip.MustParsePrefix(prefix)) {
			t.Fatalf("Delete(%s) = true", prefix)
		}
	}
	if s.Size() != 1 || !s.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("set was disturbed by failed deletions")
	}
}
