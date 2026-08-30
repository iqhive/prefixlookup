package tests_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/artset"
	"github.com/iqhive/prefixlookup/old/soarangeset"
	"github.com/iqhive/prefixlookup/rangematch"
)

// TestARTSet4MatchesOracle stuffs 4k random prefixes into artset and the
// brute-force oracle, probes Contains, then deletes every even insert and
// probes again
//
// we don't compare against a sibling set here on purpose - we want ground
// truth, not "two bugs that match"
func TestARTSet4MatchesOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(404))
	set, want := artset.New(), newOracle()
	prefixes := make([]netip.Prefix, 0, 4000)
	for i := 0; i < 4000; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		prefixes = append(prefixes, prefix)
		set.Insert(prefix)
		want.insert(prefix, i)
	}
	assertArtsetMatches(t, rng, set, want, 20000)
	for i, prefix := range prefixes {
		if i%2 == 0 {
			set.Delete(prefix)
			want.delete(prefix)
		}
	}
	assertArtsetMatches(t, rng, set, want, 20000)
}

// assertArtsetMatches fires `probes` random addrs at artset.Contains and the
// oracle lookup - we only compare the bool (membership), payload's irrelevant
func assertArtsetMatches(t *testing.T, rng *rand.Rand, set *artset.Set, want *oracle, probes int) {
	t.Helper()
	for i := 0; i < probes; i++ {
		address := randPrefix(rng, i%2 == 0).Addr()
		_, wantOK := want.lookup(address)
		if got := set.Contains(address); got != wantOK {
			t.Fatalf("Contains(%v) = %v, want %v", address, got, wantOK)
		}
	}
}

// TestRangeMatchLite4MatchesRangeMatch compiles 4k random prefixes through
// rangematch and soarangeset (the SoA lite encoding) and checks Ranges() plus
// 40k Match probes
//
// soarangeset layout is the thing we're actually scared of - if the stride
// tables get out of sync with the boundary list, random probes cop it
func TestRangeMatchLite4MatchesRangeMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(405))
	prefixes := make([]netip.Prefix, 0, 4000)
	for i := 0; i < cap(prefixes); i++ {
		prefixes = append(prefixes, randPrefix(rng, i%2 == 0))
	}
	base, err := rangematch.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := soarangeset.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	if base.Ranges() != lite.Ranges() {
		t.Fatalf("Ranges() base=%d lite=%d", base.Ranges(), lite.Ranges())
	}
	for i := 0; i < 40000; i++ {
		address := randPrefix(rng, i%2 == 0).Addr()
		if got, want := lite.Match(address), base.Match(address); got != want {
			t.Fatalf("Match(%v) = %v, want %v", address, got, want)
		}
	}
}
