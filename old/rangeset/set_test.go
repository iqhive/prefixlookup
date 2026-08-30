package rangeset

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/rangematch"
)

// prefix is a test helper that panics on a bad CIDR string
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr is a test helper that panics on a bad address string
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestMergedAdjacentPrefixes checks two halves of 10/8 collapse into one
// range and still cover the endpoints without leaking next door
func TestMergedAdjacentPrefixes(t *testing.T) {
	set, err := New([]netip.Prefix{prefix("10.0.0.0/9"), prefix("10.128.0.0/9")})
	if err != nil {
		t.Fatal(err)
	}
	if set.Ranges() != 1 {
		t.Fatalf("adjacent halves of 10/8 merged into %d ranges, want 1", set.Ranges())
	}
	if !set.Match(addr("10.0.0.1")) || !set.Match(addr("10.255.255.254")) {
		t.Fatal("merged range lost endpoints")
	}
	if set.Match(addr("11.0.0.1")) {
		t.Fatal("address outside merged range matched")
	}
}

// TestPartialCoveragePages checks a /17 that covers half a /16: the
// classifier must say deeper and both halves of the /16 must answer from
// the range search
func TestPartialCoveragePages(t *testing.T) {
	// 10.128.0.0/17 covers half a /16 inside /8 10: the top slot must be
	// deeper, a page must exist, and both halves of the /16 must answer
	// from the page
	set, err := New([]netip.Prefix{prefix("10.128.0.0/17")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a    string
		want bool
	}{
		{"10.128.0.0", true}, {"10.128.127.255", true},
		{"10.128.128.0", false}, {"10.128.255.254", false},
		{"10.127.255.255", false}, {"10.129.0.0", false},
		{"9.255.255.255", false}, {"11.0.0.0", false},
	} {
		if got := set.Match(addr(tc.a)); got != tc.want {
			t.Errorf("Match(%s) = %v, want %v", tc.a, got, tc.want)
		}
	}
}

// TestDefaultRoute checks /0 in each family covers that family only
func TestDefaultRoute(t *testing.T) {
	v4set, err := New([]netip.Prefix{prefix("0.0.0.0/0")})
	if err != nil {
		t.Fatal(err)
	}
	if v4set.Ranges() != 1 {
		t.Fatalf("0.0.0.0/0 produced %d ranges, want 1", v4set.Ranges())
	}
	if !v4set.Match(addr("192.0.2.1")) {
		t.Fatal("v4 default route did not match a v4 address")
	}
	if v4set.Match(addr("2001:db8::1")) {
		t.Fatal("v4 default route matched a v6 address")
	}
	v6set, err := New([]netip.Prefix{prefix("::/0")})
	if err != nil {
		t.Fatal(err)
	}
	if !v6set.Match(addr("2001:db8::1")) {
		t.Fatal("v6 default route did not match a v6 address")
	}
	if v6set.Match(addr("192.0.2.1")) {
		t.Fatal("v6 default route matched a v4 address")
	}
}

// TestRejectsInvalidInput checks empty input is fine and an oversized
// mask is not. netip itself refuses zones, so we reach the validator
// with bits out of range
func TestRejectsInvalidInput(t *testing.T) {
	if _, err := New(nil); err != nil {
		t.Fatal(err)
	}
	// netip itself refuses zones in prefixes, so reach the validator with
	// a mask out of range for the family
	bad := netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 33)
	if _, err := New([]netip.Prefix{bad}); err == nil {
		t.Fatal("oversized mask accepted")
	}
}

// randPrefixes draws from both families with lengths that force overlaps,
// adjacencies, nesting, and defaults. Small v4 pool so they actually collide
func randPrefixes(rng *rand.Rand, n int) []netip.Prefix {
	out := make([]netip.Prefix, n)
	for i := range out {
		switch rng.Intn(12) {
		case 0:
			out[i] = prefix("0.0.0.0/0")
		case 1:
			out[i] = prefix("::/0")
		default:
			if rng.Intn(4) == 0 {
				// small pool of v4 bases so prefixes collide, nest, and touch
				base := [4]byte{10, byte(rng.Intn(4)), byte(rng.Intn(8)), 0}
				out[i] = netip.PrefixFrom(netip.AddrFrom4(base), 8+rng.Intn(25))
			} else if rng.Intn(3) == 0 {
				var b [16]byte
				copy(b[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0})
				b[8] = byte(rng.Intn(4))
				out[i] = netip.PrefixFrom(netip.AddrFrom16(b), 32+rng.Intn(97))
			} else {
				var b [16]byte
				copy(b[:], []byte{0x20, 0x01})
				for j := 2; j < len(b); j++ {
					b[j] = byte(rng.Intn(256))
				}
				out[i] = netip.PrefixFrom(netip.AddrFrom16(b), 16+rng.Intn(113))
			}
		}
	}
	return out
}

// randAddr returns a random v4 or v6 probe. Uniform-ish, not biased toward
// stored prefixes - the differential test adds those separately
func randAddr(rng *rand.Rand) netip.Addr {
	if rng.Intn(2) == 0 {
		return netip.AddrFrom4([4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
	var b [16]byte
	b[0] = 0x20
	for i := 1; i < len(b); i++ {
		b[i] = byte(rng.Intn(256))
	}
	return netip.AddrFrom16(b)
}

// TestDifferentialAgainstRangeMatch is why we kept this: random tables vs
// rangematch, same merged count, same Match at prefix boundaries and
// random probes. Seed 2024 so a failure is reproducible
func TestDifferentialAgainstRangeMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(2024))
	for round := 0; round < 60; round++ {
		prefixes := randPrefixes(rng, 150)
		ref, err := rangematch.New(prefixes)
		if err != nil {
			t.Fatalf("round %d: rangematch rejected input: %v", round, err)
		}
		got, err := New(prefixes)
		if err != nil {
			t.Fatalf("round %d: New rejected input: %v", round, err)
		}
		if got.Ranges() != ref.Ranges() {
			t.Fatalf("round %d: %d merged ranges, rangematch has %d", round, got.Ranges(), ref.Ranges())
		}
		// probe boundary addresses of every stored prefix plus random
		// addresses: first, last, and just outside on both sides
		probes := make([]netip.Addr, 0, 4*len(prefixes)+300)
		for _, p := range prefixes {
			probes = append(probes, p.Addr())
			for _, q := range []netip.Addr{p.Addr().Next(), p.Addr().Prev()} {
				probes = append(probes, q)
			}
		}
		for i := 0; i < 300; i++ {
			probes = append(probes, randAddr(rng))
		}
		for _, a := range probes {
			if got.Match(a) != ref.Match(a) {
				t.Fatalf("round %d: Match(%s) = %v, rangematch says %v", round, a, got.Match(a), ref.Match(a))
			}
		}
	}
}
