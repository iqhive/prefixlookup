package tests_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/rangematch"
)

// TestRangeMatchAgainstOracle compiles a mixed v4/v6 prefix bag (defaults
// plus 1600 randoms) into rangematch and checks Match against the brute-force
// oracle
//
// rangematch is membership-only so we only care about the bool, not the
// payload - we keep the defaults in the slice and also insert them on the
// oracle so a miss-shaped compile can't hide behind "no default"
func TestRangeMatchAgainstOracle(t *testing.T) {
	rng, want := rand.New(rand.NewSource(810)), newOracle()
	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for i := 0; i < 1600; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		prefixes = append(prefixes, prefix)
		want.insert(prefix, i)
	}
	want.insert(prefixes[0], 1)
	want.insert(prefixes[1], 1)
	set, err := rangematch.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		_, expected := want.lookup(addr)
		if set.Match(addr) != expected {
			t.Fatalf("Match(%v) disagreed", addr)
		}
	}
	if set.Ranges() == 0 {
		t.Fatal("no ranges retained")
	}
}
