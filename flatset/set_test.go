package flatset

import (
	"math/rand"
	"net/netip"
	"testing"
)

// randomPrefix is a masked random prefix, v6 or v4 depending on the flag
func randomPrefix(rng *rand.Rand, v6 bool) netip.Prefix {
	if v6 {
		var b [16]byte
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), rng.Intn(129)).Masked()
	}
	var b [4]byte
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return netip.PrefixFrom(netip.AddrFrom4(b), rng.Intn(33)).Masked()
}

// oracleContains is a linear scan - first covering prefix wins, we don't care which
func oracleContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() != (addr.Is4() || addr.Is4In6()) {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// TestContainsMatchesOracle throws random sets at Contains and checks them
// against a linear scan - even seeds stick a default route in so we hit
// the all4/all6 short-circuit
func TestContainsMatchesOracle(t *testing.T) {
	for _, size := range []int{0, 1, 9, 200, 3000} {
		for seed := int64(1); seed <= 4; seed++ {
			rng := rand.New(rand.NewSource(seed*100 + int64(size)))
			var prefixes []netip.Prefix
			// even seeds include the default routes, which drive both families
			// down the fully-covered path
			if seed%2 == 0 {
				prefixes = append(prefixes,
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"))
			}
			for i := 0; i < size; i++ {
				prefixes = append(prefixes, randomPrefix(rng, i%3 == 0))
			}
			set, err := New(prefixes)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3000; i++ {
				addr := randomPrefix(rng, i%3 == 0).Addr()
				if got, want := set.Contains(addr), oracleContains(prefixes, addr); got != want {
					t.Fatalf("size=%d seed=%d Contains(%v) = %v, want %v", size, seed, addr, got, want)
				}
			}
		}
	}
}

// TestTilingIsDetected covers full coverage assembled from shorter prefixes
// rather than a literal default route, which is the case a default-route
// test would miss
func TestTilingIsDetected(t *testing.T) {
	set, err := New([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !set.all4 {
		t.Fatal("two /1 prefixes were not recognised as covering IPv4")
	}
	for _, s := range []string{"0.0.0.0", "10.1.2.3", "255.255.255.255"} {
		if !set.Contains(netip.MustParseAddr(s)) {
			t.Fatalf("Contains(%s) = false, want true", s)
		}
	}
	if set.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 reported present in an IPv4-only set")
	}
}

// TestPartialTilingIsNotDetected is a single /1 must not trip all4
func TestPartialTilingIsNotDetected(t *testing.T) {
	set, err := New([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")})
	if err != nil {
		t.Fatal(err)
	}
	if set.all4 {
		t.Fatal("a single /1 was wrongly recognised as covering IPv4")
	}
	if !set.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("Contains(10.1.2.3) = false, want true")
	}
	if set.Contains(netip.MustParseAddr("200.1.2.3")) {
		t.Fatal("Contains(200.1.2.3) = true, want false")
	}
}

// TestEmptySet is nothing-in, nothing-out for both families
func TestEmptySet(t *testing.T) {
	set, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.Contains(netip.MustParseAddr("1.2.3.4")) || set.Contains(netip.MustParseAddr("::1")) {
		t.Fatal("empty set reported a match")
	}
}
