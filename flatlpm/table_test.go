package flatlpm

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
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

// oracleLookup is a brute-force longest-prefix match
// we skip the other family, then take the longest Contains
func oracleLookup(catalog map[netip.Prefix]int, addr netip.Addr) (int, bool) {
	best, bestBits := 0, -1
	for prefix, value := range catalog {
		if prefix.Addr().Is4() != (addr.Is4() || addr.Is4In6()) {
			continue
		}
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best, bestBits = value, prefix.Bits()
		}
	}
	return best, bestBits >= 0
}

// build compiles a catalogue into a table and dies on error
func build(t *testing.T, catalog map[netip.Prefix]int) *Table[int] {
	t.Helper()
	entries := make([]prefixentry.Entry[int], 0, len(catalog))
	for prefix, value := range catalog {
		entries = append(entries, prefixentry.Entry[int]{Prefix: prefix, Value: value})
	}
	table, err := New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// TestLookupMatchesOracle throws random tables at Lookup/Exact and checks
// them against a linear scan - even seeds stick a default route in so we
// exercise the inherited-cover path at every stride
func TestLookupMatchesOracle(t *testing.T) {
	for _, size := range []int{0, 1, 4, 50, 800, 5000} {
		for seed := int64(1); seed <= 3; seed++ {
			rng := rand.New(rand.NewSource(seed*100 + int64(size)))
			catalog := make(map[netip.Prefix]int)
			// even seeds carry the default routes, which put an inherited value
			// at every stride in the table
			if seed%2 == 0 {
				catalog[netip.MustParsePrefix("0.0.0.0/0")] = 1
				catalog[netip.MustParsePrefix("::/0")] = 2
			}
			for i := 0; i < size; i++ {
				catalog[randomPrefix(rng, i%3 == 0)] = i + 3
			}
			table := build(t, catalog)

			for i := 0; i < 2500; i++ {
				addr := randomPrefix(rng, i%3 == 0).Addr()
				got, gotOK := table.Lookup(addr)
				want, wantOK := oracleLookup(catalog, addr)
				if gotOK != wantOK || (wantOK && got != want) {
					t.Fatalf("size=%d seed=%d Lookup(%v) = (%d,%v), want (%d,%v)", size, seed, addr, got, gotOK, want, wantOK)
				}
			}
			for prefix, want := range catalog {
				got, ok := table.Exact(prefix)
				if !ok || got != want {
					t.Fatalf("size=%d seed=%d Exact(%v) = (%d,%v), want %d", size, seed, prefix, got, ok, want)
				}
			}
			for i := 0; i < 400; i++ {
				prefix := randomPrefix(rng, i%3 == 0)
				got, ok := table.Exact(prefix)
				want, wantOK := catalog[prefix]
				if ok != wantOK || (wantOK && got != want) {
					t.Fatalf("size=%d seed=%d Exact(%v) = (%d,%v), want (%d,%v)", size, seed, prefix, got, ok, want, wantOK)
				}
			}
			table.Close()
		}
	}
}

// TestDecodedFastPaths hits Lookup4/Lookup6 directly so a netip regression
// doesn't hide a broken decoded path
func TestDecodedFastPaths(t *testing.T) {
	catalog := map[netip.Prefix]int{
		netip.MustParsePrefix("10.0.0.0/8"):    1,
		netip.MustParsePrefix("10.1.2.0/24"):   2,
		netip.MustParsePrefix("2001:db8::/32"): 3,
	}
	table := build(t, catalog)
	defer table.Close()

	if got, ok := table.Lookup4(0x0A010203); !ok || got != 2 {
		t.Fatalf("Lookup4(10.1.2.3) = (%d,%v), want 2", got, ok)
	}
	if got, ok := table.Lookup4(0x0A020203); !ok || got != 1 {
		t.Fatalf("Lookup4(10.2.2.3) = (%d,%v), want 1", got, ok)
	}
	if got, ok := table.Lookup6(0x20010db800000000, 1); !ok || got != 3 {
		t.Fatalf("Lookup6(2001:db8::1) = (%d,%v), want 3", got, ok)
	}
	if _, ok := table.Lookup4(0x0B000001); ok {
		t.Fatal("Lookup4(11.0.0.1) reported a match")
	}
}

// TestPayloadAndStructuralUpdates checks that a value change is published
// without rebuilding the index, and that a rebuild recovers the whole
// catalogue by enumerating the index rather than from a retained map
func TestPayloadAndStructuralUpdates(t *testing.T) {
	catalog := map[netip.Prefix]int{
		netip.MustParsePrefix("0.0.0.0/0"):     1,
		netip.MustParsePrefix("10.0.0.0/8"):    2,
		netip.MustParsePrefix("10.1.0.0/16"):   3,
		netip.MustParsePrefix("2001:db8::/32"): 4,
		netip.MustParsePrefix("2001:db8::/48"): 5,
	}
	table := build(t, catalog)
	defer table.Close()

	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 33},
		{Prefix: netip.MustParsePrefix("2001:db8::/48"), Value: 55},
	}); err != nil {
		t.Fatal(err)
	}
	if got := table.Stats(); got.PayloadPublications != 1 || got.StructuralPublications != 0 {
		t.Fatalf("expected one payload publication, got %+v", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("10.1.2.3")); got != 33 {
		t.Fatalf("after payload update Lookup = %d, want 33", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("2001:db8::1")); got != 55 {
		t.Fatalf("after payload update v6 Lookup = %d, want 55", got)
	}

	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 99},
	}); err != nil {
		t.Fatal(err)
	}
	if got := table.Stats(); got.StructuralPublications != 1 {
		t.Fatalf("expected one structural publication, got %+v", got)
	}
	// the rebuild must have preserved every other route, in both families
	for _, tc := range []struct {
		addr string
		want int
	}{
		{"10.1.2.3", 99},
		{"10.1.9.9", 33},
		{"10.9.9.9", 2},
		{"1.2.3.4", 1},
		{"2001:db8::1", 55},
		// outside the /48 (its third group differs) but inside the /32
		{"2001:db8:1::1", 4},
	} {
		if got, ok := table.Lookup(netip.MustParseAddr(tc.addr)); !ok || got != tc.want {
			t.Errorf("after rebuild Lookup(%s) = (%d,%v), want %d", tc.addr, got, ok, tc.want)
		}
	}

	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Delete: true},
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("10.1.2.3")); got != 33 {
		t.Fatalf("after delete Lookup = %d, want 33", got)
	}
}

// TestClosedTableRejectsUpdates is Close then ApplyBatch must fail, but
// reads still hit the last published generation
func TestClosedTableRejectsUpdates(t *testing.T) {
	table := build(t, map[netip.Prefix]int{netip.MustParsePrefix("10.0.0.0/8"): 1})
	table.Close()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 2},
	}); err != ErrClosed {
		t.Fatalf("ApplyBatch after Close = %v, want ErrClosed", err)
	}
	// reads must keep working against the last published generation
	if got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 1 {
		t.Fatalf("Lookup after Close = (%d,%v), want 1", got, ok)
	}
	table.Close() // idempotent
}

// TestBadPrefixRejected is New must refuse a zero Prefix
func TestBadPrefixRejected(t *testing.T) {
	if _, err := New([]prefixentry.Entry[int]{{Prefix: netip.Prefix{}, Value: 1}}, routeupdate.Options{}); err == nil {
		t.Fatal("New accepted an invalid prefix")
	}
}
