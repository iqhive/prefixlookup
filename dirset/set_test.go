package dirset

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
	for _, size := range []int{0, 1, 11, 300, 4000} {
		for seed := int64(1); seed <= 4; seed++ {
			rng := rand.New(rand.NewSource(seed*100 + int64(size)))
			var prefixes []netip.Prefix
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

// TestLongIPv4Prefixes drives the stateDeeper path, which only prefixes
// longer than /24 create and which a full table populates sparsely
func TestLongIPv4Prefixes(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"),
		netip.MustParsePrefix("10.0.1.64/26"),
		netip.MustParsePrefix("10.0.2.200/32"),
		netip.MustParsePrefix("192.168.5.0/24"),
	}
	set, err := New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.0.0.0", true},
		{"10.0.0.127", true},
		{"10.0.0.128", false},
		{"10.0.1.63", false},
		{"10.0.1.64", true},
		{"10.0.1.127", true},
		{"10.0.1.128", false},
		{"10.0.2.200", true},
		{"10.0.2.201", false},
		{"192.168.5.99", true},
		{"192.168.6.1", false},
	} {
		if got := set.Contains(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// TestTilingByLongPrefixes checks the promotion of a /24 that its own longer
// prefixes tile, and the whole-space detection that follows from it
func TestTilingByLongPrefixes(t *testing.T) {
	set, err := New([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"),
		netip.MustParsePrefix("10.0.0.128/25"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := get(set.front4, 10<<16); got != stateAll {
		t.Fatalf("two /25 prefixes left the /24 in state %d, want stateAll", got)
	}
	for _, s := range []string{"10.0.0.0", "10.0.0.127", "10.0.0.128", "10.0.0.255"} {
		if !set.Contains(netip.MustParseAddr(s)) {
			t.Errorf("Contains(%s) = false, want true", s)
		}
	}
	if set.Contains(netip.MustParseAddr("10.0.1.0")) {
		t.Error("Contains(10.0.1.0) = true, want false")
	}
}

// TestWholeSpaceDetection is two /1s covering IPv4 plus ::/0 covering IPv6
// we should drop the front table entirely and report zero bytes
func TestWholeSpaceDetection(t *testing.T) {
	set, err := New([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !set.all4 {
		t.Fatal("two /1 prefixes were not recognised as covering IPv4")
	}
	if !set.all6 {
		t.Fatal("::/0 was not recognised as covering IPv6")
	}
	if set.front4 != nil {
		t.Fatal("a fully covered family retained its /24 table")
	}
	if got := set.Bytes(); got != 0 {
		t.Fatalf("fully covered set retains %d bytes, want 0", got)
	}
	for _, s := range []string{"0.0.0.0", "10.1.2.3", "255.255.255.255"} {
		if !set.Contains(netip.MustParseAddr(s)) {
			t.Errorf("Contains(%s) = false, want true", s)
		}
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

// TestSingleFamily checks an IPv4-only set doesn't invent IPv6 coverage
func TestSingleFamily(t *testing.T) {
	set, err := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("Contains(10.1.2.3) = false, want true")
	}
	if set.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 reported present in an IPv4-only set")
	}
}
