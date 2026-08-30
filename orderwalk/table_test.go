package orderwalk

import (
	"math/rand"
	"net/netip"
	"sort"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// randomPrefix draws a masked prefix, v4 or v6
// we fill the whole addr with rng bytes then pick a random length and Mask -
// that's enough entropy for the oracle tests, we don't try to look like BGP
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

// buildRandom compiles a random table plus the catalogue the oracles need
// even seeds also stuff in both default routes so /0 is in the mix. we build
// entries from the map (last write of a colliding prefix wins), New them, and
// return the rng so the caller keeps drawing from the same stream
func buildRandom(t *testing.T, size int, seed int64) (*Table[int], []netip.Prefix, map[netip.Prefix]int, *rand.Rand) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	catalog := make(map[netip.Prefix]int)
	if seed%2 == 0 {
		catalog[netip.MustParsePrefix("0.0.0.0/0")] = 1
		catalog[netip.MustParsePrefix("::/0")] = 2
	}
	for i := 0; i < size; i++ {
		catalog[randomPrefix(rng, i%3 == 0)] = i + 3
	}
	entries := make([]prefixentry.Entry[int], 0, len(catalog))
	unique := make([]netip.Prefix, 0, len(catalog))
	for prefix, value := range catalog {
		entries = append(entries, prefixentry.Entry[int]{Prefix: prefix, Value: value})
		unique = append(unique, prefix)
	}
	table, err := New(entries)
	if err != nil {
		t.Fatal(err)
	}
	return table, unique, catalog, rng
}

// oracleLookup is the naive LPM scan the table has to match
// skip the other family (mapped 4in6 counts as v4), keep the longest cover
// we use > not >= so the first of equal lengths wins - the catalogue is a map
// so "last insert" isn't a thing here, uniqueness is already done
func oracleLookup(prefixes []netip.Prefix, catalog map[netip.Prefix]int, addr netip.Addr) (int, bool) {
	best, bestBits := 0, -1
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() != (addr.Is4() || addr.Is4In6()) {
			continue
		}
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best, bestBits = catalog[prefix], prefix.Bits()
		}
	}
	return best, bestBits >= 0
}

// TestLookupAndExact fuzzes Lookup and Exact against the linear oracles
//
// sizes from empty through 5k, three seeds each. 2500 random addrs for LPM,
// then Exact of every stored prefix, then 500 random prefixes that usually
// miss. that's the front-index + bisection path, including mapped 4in6 via
// oracleLookup treating Is4In6 as v4
func TestLookupAndExact(t *testing.T) {
	for _, size := range []int{0, 1, 6, 70, 900, 5000} {
		for seed := int64(1); seed <= 3; seed++ {
			table, prefixes, catalog, rng := buildRandom(t, size, seed*100+int64(size))
			for i := 0; i < 2500; i++ {
				addr := randomPrefix(rng, i%3 == 0).Addr()
				got, gotOK := table.Lookup(addr)
				want, wantOK := oracleLookup(prefixes, catalog, addr)
				if gotOK != wantOK || (wantOK && got != want) {
					t.Fatalf("size=%d seed=%d Lookup(%v) = (%d,%v), want (%d,%v)", size, seed, addr, got, gotOK, want, wantOK)
				}
			}
			for _, prefix := range prefixes {
				_, got, ok := table.Exact(prefix)
				if !ok || got != catalog[prefix] {
					t.Fatalf("size=%d seed=%d Exact(%v) = (%d,%v), want %d", size, seed, prefix, got, ok, catalog[prefix])
				}
			}
			for i := 0; i < 500; i++ {
				prefix := randomPrefix(rng, i%3 == 0)
				_, got, ok := table.Exact(prefix)
				want, wantOK := catalog[prefix]
				if ok != wantOK || (wantOK && got != want) {
					t.Fatalf("size=%d seed=%d Exact(%v) = (%d,%v), want (%d,%v)", size, seed, prefix, got, ok, want, wantOK)
				}
			}
		}
	}
}

// TestWalkParentsMatchesOracle checks ancestor walks against a linear cover
// scan
//
// for each random addr we collect every stored prefix that contains it, sort
// most-specific-first, then WalkParents and compare both the set and the
// order. we also check the yielded value matches the catalogue, so a parent
// pointer pointing at the wrong route would fail even if the prefix happened
// to match
func TestWalkParentsMatchesOracle(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		table, prefixes, catalog, rng := buildRandom(t, 800, seed)
		for i := 0; i < 1500; i++ {
			addr := randomPrefix(rng, i%3 == 0).Addr()

			var want []netip.Prefix
			for _, prefix := range prefixes {
				if prefix.Addr().Is4() == (addr.Is4() || addr.Is4In6()) && prefix.Contains(addr) {
					want = append(want, prefix)
				}
			}
			sort.Slice(want, func(i, j int) bool { return want[i].Bits() > want[j].Bits() })

			var got []netip.Prefix
			table.WalkParents(addr, func(_ RouteID, prefix netip.Prefix, value int) bool {
				if value != catalog[prefix] {
					t.Fatalf("seed=%d WalkParents(%v) yielded %v with value %d, want %d", seed, addr, prefix, value, catalog[prefix])
				}
				got = append(got, prefix)
				return true
			})
			if len(got) != len(want) {
				t.Fatalf("seed=%d WalkParents(%v) yielded %d %v, want %d %v", seed, addr, len(got), got, len(want), want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("seed=%d WalkParents(%v)[%d] = %v, want %v", seed, addr, i, got[i], want[i])
				}
			}
		}
	}
}

// TestWalkDescendantsMatchesOracle checks descendant walks against a linear
// contained-in scan
//
// we probe every stored prefix plus 100 random ones (those usually miss). if
// Exact says the query isn't stored, WalkDescendants must report false and
// yield nothing - a miss isn't "walk the covering route's kids". hits get
// sorted preorder to match the catalogue scan order
func TestWalkDescendantsMatchesOracle(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		table, prefixes, catalog, rng := buildRandom(t, 800, seed)
		probes := append([]netip.Prefix{}, prefixes...)
		for i := 0; i < 100; i++ {
			probes = append(probes, randomPrefix(rng, i%3 == 0))
		}
		for _, query := range probes {
			_, _, present := table.Exact(query)

			var want []netip.Prefix
			if present {
				for _, prefix := range prefixes {
					if prefix.Addr().Is4() != query.Addr().Is4() {
						continue
					}
					if prefix.Bits() >= query.Bits() && query.Contains(prefix.Addr()) {
						want = append(want, prefix)
					}
				}
				sortPreorder(want)
			}

			var got []netip.Prefix
			ok := table.WalkDescendants(query, func(_ RouteID, prefix netip.Prefix, value int) bool {
				if value != catalog[prefix] {
					t.Fatalf("seed=%d WalkDescendants(%v) yielded %v with value %d, want %d", seed, query, prefix, value, catalog[prefix])
				}
				got = append(got, prefix)
				return true
			})
			if ok != present {
				t.Fatalf("seed=%d WalkDescendants(%v) reported %v, want %v", seed, query, ok, present)
			}
			if len(got) != len(want) {
				t.Fatalf("seed=%d WalkDescendants(%v) yielded %d %v, want %d %v", seed, query, len(got), got, len(want), want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("seed=%d WalkDescendants(%v)[%d] = %v, want %v", seed, query, i, got[i], want[i])
				}
			}
		}
	}
}

// TestPredecessorAcrossBlocks covers the case the front index cannot answer
// directly: the covering route lives in an earlier /16 than the query
//
// 10.0.0.0/8 covers 10.128.7.7 but the /16 front slot for 10.128 is empty of
// more-specifics except 10.255.0.0/16, so Lookup has to walk back to the /8
// 11.0.0.1 and 2001:db9::1 miss. this is the predecessor walk the package
// comment is talking about
func TestPredecessorAcrossBlocks(t *testing.T) {
	entries := []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.255.0.0/16"), Value: 2},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 3},
	}
	table, err := New(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		want int
	}{
		{"10.128.7.7", 1},
		{"10.255.1.1", 2},
		{"11.0.0.1", 0},
		{"2001:db8:1::1", 3},
		{"2001:db9::1", 0},
	} {
		got, ok := table.Lookup(netip.MustParseAddr(tc.addr))
		if tc.want == 0 {
			if ok {
				t.Errorf("Lookup(%s) = (%d,true), want no match", tc.addr, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("Lookup(%s) = (%d,%v), want %d", tc.addr, got, ok, tc.want)
		}
	}
}

// TestEarlyStop checks WalkParents honouring a false yield
// we return false on the first call; if the parent chain kept going we'd see
// count > 1. empty-ish random table is fine, we just need at least one cover
// of 10.20.30.40 or a zero-yield is also a pass as long as we didn't hang
func TestEarlyStop(t *testing.T) {
	table, _, _, _ := buildRandom(t, 500, 2)
	count := 0
	table.WalkParents(netip.MustParseAddr("10.20.30.40"), func(RouteID, netip.Prefix, int) bool {
		count++
		return false
	})
	if count > 1 {
		t.Fatalf("WalkParents ignored the stop request after %d yields", count)
	}
}
