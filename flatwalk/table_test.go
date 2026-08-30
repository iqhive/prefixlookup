package flatwalk

import (
	"math/rand"
	"net/netip"
	"sort"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
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

// buildRandom compiles a random catalogue, even seeds stick a default route
// in so we exercise the inherited-cover path
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

// oracleLookup is a brute-force longest-prefix match
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

// TestLookupAndExact throws random tables at Lookup/Exact and checks them
// against a linear scan
func TestLookupAndExact(t *testing.T) {
	for _, size := range []int{1, 5, 60, 900, 4000} {
		for seed := int64(1); seed <= 3; seed++ {
			table, prefixes, catalog, rng := buildRandom(t, size, seed*100+int64(size))
			for i := 0; i < 2000; i++ {
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

// TestWalkParentsMatchesOracle checks the parent chain against a sort of
// every covering prefix, most specific first
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
			// most specific first
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
				t.Fatalf("seed=%d WalkParents(%v) yielded %d prefixes %v, want %d %v", seed, addr, len(got), got, len(want), want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("seed=%d WalkParents(%v)[%d] = %v, want %v", seed, addr, i, got[i], want[i])
				}
			}
		}
	}
}

// TestWalkDescendantsMatchesOracle checks the preorder scan against every
// nested prefix of the query, including probes that aren't stored
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
					// a descendant is contained in the query and no shorter
					if prefix.Bits() >= query.Bits() && query.Contains(prefix.Addr()) {
						want = append(want, prefix)
					}
				}
				sortPrefixes(want)
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

// TestEarlyStop is yield returning false must stop after one visit
func TestEarlyStop(t *testing.T) {
	table, _, _, _ := buildRandom(t, 500, 2)
	addr := netip.MustParseAddr("10.20.30.40")
	count := 0
	table.WalkParents(addr, func(RouteID, netip.Prefix, int) bool { count++; return false })
	if count > 1 {
		t.Fatalf("WalkParents ignored the stop request after %d yields", count)
	}
}
