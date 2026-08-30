package tests_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/groupartset"
	"github.com/iqhive/prefixlookup/old/latticeartset"
	"github.com/iqhive/prefixlookup/old/thinrangeset"
	"github.com/iqhive/prefixlookup/rangematch"
)

// TestARTSet5MatchesOracle drives groupartset inserts/deletes against the
// brute-force oracle so we check the trie descent AND the classifier rebuild
// against ground truth rather than a sibling that might share a bug
//
// 4k mixed inserts, 20k probes, delete the even ones, 20k more probes
func TestARTSet5MatchesOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(505))
	set, want := groupartset.New(), newOracle()
	prefixes := make([]netip.Prefix, 0, 4000)
	for i := 0; i < 4000; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		prefixes = append(prefixes, prefix)
		set.Insert(prefix)
		want.insert(prefix, i)
	}
	assertGroupartsetMatches(t, rng, set, want, 20000)
	for i, prefix := range prefixes {
		if i%2 == 0 {
			set.Delete(prefix)
			want.delete(prefix)
		}
	}
	assertGroupartsetMatches(t, rng, set, want, 20000)
}

// assertGroupartsetMatches is the Contains vs oracle helper - random addrs,
// membership bool only, t.Helper so failures point at the caller
func assertGroupartsetMatches(t *testing.T, rng *rand.Rand, set *groupartset.Set, want *oracle, probes int) {
	t.Helper()
	for i := 0; i < probes; i++ {
		address := randPrefix(rng, i%2 == 0).Addr()
		_, wantOK := want.lookup(address)
		if got := set.Contains(address); got != wantOK {
			t.Fatalf("Contains(%v) = %v, want %v", address, got, wantOK)
		}
	}
}

// TestARTSet5MatchesARTSet cross-checks groupartset against latticeartset on
// a shared random workload, including All() enumeration
//
// we insert 3k, check Size/Contains/All, delete every third prefix, then
// Contains again - All is the thing that used to drop compressed paths
func TestARTSet5MatchesARTSet(t *testing.T) {
	rng := rand.New(rand.NewSource(506))
	base, next := latticeartset.New(), groupartset.New()
	prefixes := make([]netip.Prefix, 0, 3000)
	for i := 0; i < cap(prefixes); i++ {
		prefix := randPrefix(rng, i%2 == 0)
		prefixes = append(prefixes, prefix)
		if base.Insert(prefix) != next.Insert(prefix) {
			t.Fatalf("Insert(%v) disagreed", prefix)
		}
	}
	if base.Size() != next.Size() {
		t.Fatalf("Size() base=%d next=%d", base.Size(), next.Size())
	}
	for i := 0; i < 20000; i++ {
		address := randPrefix(rng, i%2 == 0).Addr()
		if got, want := next.Contains(address), base.Contains(address); got != want {
			t.Fatalf("Contains(%v) = %v, want %v", address, got, want)
		}
	}
	baseAll := map[netip.Prefix]bool{}
	base.All(func(prefix netip.Prefix) bool { baseAll[prefix] = true; return true })
	nextAll := map[netip.Prefix]bool{}
	next.All(func(prefix netip.Prefix) bool { nextAll[prefix] = true; return true })
	if len(baseAll) != len(nextAll) {
		t.Fatalf("All() yielded base=%d next=%d prefixes", len(baseAll), len(nextAll))
	}
	for prefix := range baseAll {
		if !nextAll[prefix] {
			t.Fatalf("All() omitted %v", prefix)
		}
	}
	for i, prefix := range prefixes {
		if i%3 != 0 {
			continue
		}
		if base.Delete(prefix) != next.Delete(prefix) {
			t.Fatalf("Delete(%v) disagreed", prefix)
		}
	}
	for i := 0; i < 20000; i++ {
		address := randPrefix(rng, i%2 == 0).Addr()
		if got, want := next.Contains(address), base.Contains(address); got != want {
			t.Fatalf("after delete Contains(%v) = %v, want %v", address, got, want)
		}
	}
}

// TestRangeMatchLite5MatchesRangeMatch checks thinrangeset's boundary-parity
// encoding against rangematch at a size that actually materialises the
// classifier (4k prefixes, 40k probes)
func TestRangeMatchLite5MatchesRangeMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(507))
	prefixes := make([]netip.Prefix, 0, 4000)
	for i := 0; i < cap(prefixes); i++ {
		prefixes = append(prefixes, randPrefix(rng, i%2 == 0))
	}
	base, err := rangematch.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := thinrangeset.New(prefixes)
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

// TestRangeMatchLite5SmallSets covers sizes around the classifier threshold
// (including 63/64/65) where the v4 path binary-searches the boundaries
// directly - we don't want the "big set" test to be the only coverage of
// the small-n branch
func TestRangeMatchLite5SmallSets(t *testing.T) {
	rng := rand.New(rand.NewSource(508))
	for _, count := range []int{1, 2, 7, 31, 63, 64, 65, 200} {
		prefixes := make([]netip.Prefix, 0, count)
		for i := 0; i < count; i++ {
			prefixes = append(prefixes, randPrefix(rng, i%2 == 0))
		}
		base, err := rangematch.New(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		lite, err := thinrangeset.New(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5000; i++ {
			address := randPrefix(rng, i%2 == 0).Addr()
			if got, want := lite.Match(address), base.Match(address); got != want {
				t.Fatalf("count=%d Match(%v) = %v, want %v", count, address, got, want)
			}
		}
	}
}

// TestRangeMatchLite5Neighbourhoods probes the addrs immediately either side
// of every range boundary - that's where an off-by-one in the parity encoding
// shows up, and uniformly random probes almost never land there
func TestRangeMatchLite5Neighbourhoods(t *testing.T) {
	rng := rand.New(rand.NewSource(509))
	prefixes := make([]netip.Prefix, 0, 500)
	for i := 0; i < cap(prefixes); i++ {
		prefixes = append(prefixes, randPrefix(rng, i%2 == 0))
	}
	base, err := rangematch.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := thinrangeset.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range prefixes {
		probes := []netip.Addr{prefix.Addr(), prefix.Addr().Prev(), prefix.Addr().Next()}
		if last := lastAddr(prefix); last.IsValid() {
			probes = append(probes, last, last.Next(), last.Prev())
		}
		for _, address := range probes {
			if !address.IsValid() {
				continue
			}
			if got, want := lite.Match(address), base.Match(address); got != want {
				t.Fatalf("Match(%v) = %v, want %v (prefix %v)", address, got, want, prefix)
			}
		}
	}
}

// lastAddr returns the highest host contained in prefix - we OR the host-bit
// mask onto each octet so we don't have to do a 128-bit add
func lastAddr(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		octets := prefix.Addr().As4()
		bits := prefix.Bits()
		for i := 0; i < 4; i++ {
			octets[i] |= hostMask(bits, i)
		}
		return netip.AddrFrom4(octets)
	}
	octets := prefix.Addr().As16()
	bits := prefix.Bits()
	for i := 0; i < 16; i++ {
		octets[i] |= hostMask(bits, i)
	}
	return netip.AddrFrom16(octets)
}

// hostMask returns the host bits of octet i for a prefix of the given length
// - fully network octets get 0, fully host octets get 0xff, the split octet
// gets the low bits
func hostMask(bits, i int) byte {
	switch used := bits - i*8; {
	case used >= 8:
		return 0
	case used <= 0:
		return 0xff
	default:
		return byte(0xff >> used)
	}
}
