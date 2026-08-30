package dirlpm

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
// exercise the inherited-cover path
func TestLookupMatchesOracle(t *testing.T) {
	for _, size := range []int{0, 1, 3, 40, 700, 5000} {
		for seed := int64(1); seed <= 3; seed++ {
			rng := rand.New(rand.NewSource(seed*100 + int64(size)))
			catalog := make(map[netip.Prefix]int)
			// even seeds carry the default routes, as a full table does
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

// TestDeepIPv4 exercises the third level, which only prefixes longer than /24
// create and which a full table barely populates - if this breaks we've
// botched level3 tagging
func TestDeepIPv4(t *testing.T) {
	catalog := map[netip.Prefix]int{
		netip.MustParsePrefix("0.0.0.0/0"):        1,
		netip.MustParsePrefix("10.0.0.0/8"):       2,
		netip.MustParsePrefix("10.1.0.0/16"):      3,
		netip.MustParsePrefix("10.1.2.0/24"):      4,
		netip.MustParsePrefix("10.1.2.0/25"):      5,
		netip.MustParsePrefix("10.1.2.128/26"):    6,
		netip.MustParsePrefix("10.1.2.192/32"):    7,
		netip.MustParsePrefix("10.1.3.0/24"):      8,
		netip.MustParsePrefix("192.168.0.0/17"):   9,
		netip.MustParsePrefix("192.168.128.0/24"): 10,
	}
	table := build(t, catalog)
	defer table.Close()

	for _, tc := range []struct {
		addr string
		want int
	}{
		{"1.2.3.4", 1},
		{"10.9.9.9", 2},
		{"10.1.9.9", 3},
		{"10.1.2.5", 5},
		{"10.1.2.130", 6},
		{"10.1.2.192", 7},
		{"10.1.2.250", 4},
		{"10.1.3.7", 8},
		{"192.168.1.1", 9},
		{"192.168.128.5", 10},
		{"192.169.0.1", 1},
	} {
		got, ok := table.Lookup(netip.MustParseAddr(tc.addr))
		if !ok || got != tc.want {
			t.Errorf("Lookup(%s) = (%d,%v), want %d", tc.addr, got, ok, tc.want)
		}
	}
}

// TestPayloadAndStructuralUpdates checks that a value change is a payload
// publication (no rebuild) and that insert/delete are structural and still
// keep the other family's answers
func TestPayloadAndStructuralUpdates(t *testing.T) {
	catalog := map[netip.Prefix]int{
		netip.MustParsePrefix("0.0.0.0/0"):     1,
		netip.MustParsePrefix("10.0.0.0/8"):    2,
		netip.MustParsePrefix("2001:db8::/32"): 3,
	}
	table := build(t, catalog)
	defer table.Close()

	// a value change must not rebuild the forwarding structures
	before := table.Stats()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 42},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 43},
	}); err != nil {
		t.Fatal(err)
	}
	if got := table.Stats(); got.PayloadPublications != before.PayloadPublications+1 {
		t.Fatalf("expected a payload publication, got %+v", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("10.1.2.3")); got != 42 {
		t.Fatalf("after payload update Lookup = %d, want 42", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("2001:db8::1")); got != 43 {
		t.Fatalf("after payload update v6 Lookup = %d, want 43", got)
	}

	// adding a prefix is structural and must rebuild
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 99},
	}); err != nil {
		t.Fatal(err)
	}
	if got := table.Stats(); got.StructuralPublications != 1 {
		t.Fatalf("expected a structural publication, got %+v", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("10.1.2.3")); got != 99 {
		t.Fatalf("after insert Lookup = %d, want 99", got)
	}
	// the rebuild must have preserved everything else, including IPv6
	if got, _ := table.Lookup(netip.MustParseAddr("10.2.2.3")); got != 42 {
		t.Fatalf("after insert Lookup = %d, want 42", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("2001:db8::1")); got != 43 {
		t.Fatalf("after insert v6 Lookup = %d, want 43", got)
	}

	// removing it is structural too
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Delete: true},
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("10.1.2.3")); got != 42 {
		t.Fatalf("after delete Lookup = %d, want 42", got)
	}
}

// TestEmptyTable is the nothing-in, nothing-out case for both families
func TestEmptyTable(t *testing.T) {
	table := build(t, nil)
	defer table.Close()
	if _, ok := table.Lookup(netip.MustParseAddr("1.2.3.4")); ok {
		t.Fatal("empty table reported an IPv4 match")
	}
	if _, ok := table.Lookup(netip.MustParseAddr("::1")); ok {
		t.Fatal("empty table reported an IPv6 match")
	}
}
