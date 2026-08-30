package tests_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/artlpm"
	"github.com/iqhive/prefixlookup/old/arenaartlpm"
	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/old/latticeartset"
)

type mutableTable interface {
	lookupTable
	Insert(netip.Prefix, int) bool
	Delete(netip.Prefix) bool
	Size() int
	All(func(netip.Prefix, int) bool)
}

// TestMutableTablesAgainstOracle is the big insert/delete/All matrix for
// artlpm, artwalk, and arenaartlpm - 2500 random inserts, a last-wins
// duplicate, 10k lookups, delete a random half, 5k more lookups, then All
// must match the oracle map exactly
func TestMutableTablesAgainstOracle(t *testing.T) {
	factories := map[string]func() mutableTable{
		"artlpm":   func() mutableTable { return artlpm.New[int]() },
		"artwalk":     func() mutableTable { return artwalk.New[int]() },
		"arenaartlpm": func() mutableTable { return arenaartlpm.New[int]() },
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(42))
			table, want := factory(), newOracle()
			for i := 0; i < 2500; i++ {
				prefix := randPrefix(rng, i%2 == 0)
				wasNew := want.values[prefix] == 0
				_, existed := want.values[prefix]
				if got := table.Insert(prefix, i+1); got != (!existed && wasNew) {
					t.Fatalf("Insert(%v) new = %v, want %v", prefix, got, !existed)
				}
				want.insert(prefix, i+1)
			}
			duplicate := netip.MustParsePrefix("10.1.0.0/16")
			table.Insert(duplicate, 1)
			table.Insert(duplicate, 2)
			want.insert(duplicate, 2)
			if table.Size() != len(want.values) {
				t.Fatalf("size = %d, want %d", table.Size(), len(want.values))
			}
			verifyLookup(t, name, table, want, 43, 10000)

			prefixes := sortedPrefixes(want.values)
			for i := 0; i < len(prefixes)/2; i++ {
				prefix := prefixes[rng.Intn(len(prefixes))]
				if table.Delete(prefix) != want.delete(prefix) {
					t.Fatalf("Delete(%v) disagreed", prefix)
				}
			}
			verifyLookup(t, name+" after delete", table, want, 44, 5000)
			got := make(map[netip.Prefix]int)
			table.All(func(prefix netip.Prefix, value int) bool { got[prefix] = value; return true })
			if len(got) != len(want.values) {
				t.Fatalf("All returned %d prefixes, want %d", len(got), len(want.values))
			}
			for prefix, value := range want.values {
				if got[prefix] != value {
					t.Fatalf("All[%v] = %d, want %d", prefix, got[prefix], value)
				}
			}
		})
	}
}

// TestARTDefaultsMappedIPv4AndExact is the "defaults + mapped v4 + Get +
// LookupPrefix" cluster we keep hitting in reviews - ::ffff:10.1.2.3 has to
// take the v4 /16, 8.8.8.8 the v4 default, 2001:db8::1 the v6 default
func TestARTDefaultsMappedIPv4AndExact(t *testing.T) {
	table := artlpm.New[string]()
	table.Insert(netip.MustParsePrefix("0.0.0.0/0"), "d4")
	table.Insert(netip.MustParsePrefix("::/0"), "d6")
	table.Insert(netip.MustParsePrefix("10.0.0.0/8"), "v4")
	table.Insert(netip.MustParsePrefix("10.1.0.0/16"), "specific")
	for _, addr := range []string{"10.1.2.3", "::ffff:10.1.2.3"} {
		if got, ok := table.Lookup(netip.MustParseAddr(addr)); !ok || got != "specific" {
			t.Fatalf("Lookup(%s) = (%q,%v)", addr, got, ok)
		}
	}
	if got, _ := table.Lookup(netip.MustParseAddr("8.8.8.8")); got != "d4" {
		t.Fatalf("IPv4 default = %q", got)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("2001:db8::1")); got != "d6" {
		t.Fatalf("IPv6 default = %q", got)
	}
	if got, ok := table.Get(netip.MustParsePrefix("10.1.99.1/16")); !ok || got != "specific" {
		t.Fatalf("Get canonical duplicate = (%q,%v)", got, ok)
	}
	if got, ok := table.LookupPrefix(netip.MustParsePrefix("10.1.2.0/24")); !ok || got != "specific" {
		t.Fatalf("LookupPrefix = (%q,%v)", got, ok)
	}
}

// TestARTDeepIPv6 walks a single v6 chain from /32 down to /128 and probes
// addrs that should stop at each length - if a stride skips a level we'll
// pick the wrong payload
func TestARTDeepIPv6(t *testing.T) {
	table := artlpm.New[int]()
	for i, prefix := range []string{
		"2001:db8::/32", "2001:db8:0:0:1::/80", "2001:db8:0:0:1:2::/96",
		"2001:db8:0:0:1:2:3:0/112", "2001:db8:0:0:1:2:3:4/128",
	} {
		table.Insert(netip.MustParsePrefix(prefix), i)
	}
	for addr, want := range map[string]int{
		"2001:db8:0:0:1:2:3:4": 4,
		"2001:db8:0:0:1:2:3:9": 3,
		"2001:db8:0:0:1:2:9:1": 2,
		"2001:db8:0:0:1:9::":   1,
		"2001:db8:9::1":        0,
	} {
		if got, ok := table.Lookup(netip.MustParseAddr(addr)); !ok || got != want {
			t.Fatalf("Lookup(%s) = (%d,%v), want %d", addr, got, ok, want)
		}
	}
}

// TestSetAgainstOracleAndFrontTable fills latticeartset from randoms plus a
// handful of "front table" shapes (/24, /8, /16, default), checks Contains,
// drops the default, then asserts mapped v4 still hits the /8
func TestSetAgainstOracleAndFrontTable(t *testing.T) {
	rng, set, want := rand.New(rand.NewSource(99)), latticeartset.New(), newOracle()
	for i := 0; i < 2500; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		set.Insert(prefix)
		want.insert(prefix, i)
	}
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("10.1.2.0/24"), netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/16"), netip.MustParsePrefix("0.0.0.0/0"),
	} {
		set.Insert(prefix)
		want.insert(prefix, 1)
	}
	for i := 0; i < 10000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		_, expected := want.lookup(addr)
		if set.Contains(addr) != expected {
			t.Fatalf("Contains(%v) disagreed", addr)
		}
	}
	set.Delete(netip.MustParsePrefix("0.0.0.0/0"))
	want.delete(netip.MustParsePrefix("0.0.0.0/0"))
	if set.Contains(netip.MustParseAddr("::ffff:10.2.3.4")) != true {
		t.Fatal("mapped IPv4 did not match /8")
	}
	got := make(map[netip.Prefix]bool)
	set.All(func(prefix netip.Prefix) bool { got[prefix] = true; return true })
	if len(got) != len(want.values) || set.Size() != len(want.values) {
		t.Fatalf("enumeration/size = %d/%d, want %d", len(got), set.Size(), len(want.values))
	}
}

// TestCompactRebuildAndWideFanout inserts 256 sibling /24s (that's a full
// 8-bit fanout), deletes the first 128, Rebuilds, and checks the survivors
// still lookup plus Dead() went down
func TestCompactRebuildAndWideFanout(t *testing.T) {
	table := arenaartlpm.New[int]()
	for i := 0; i < 256; i++ {
		table.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 24), i)
	}
	for i := 0; i < 128; i++ {
		table.Delete(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 24))
	}
	rebuilt := table.Rebuild()
	if rebuilt.Size() != table.Size() || rebuilt.Dead() > table.Dead() {
		t.Fatalf("rebuild size/dead = %d/%d, source %d/%d", rebuilt.Size(), rebuilt.Dead(), table.Size(), table.Dead())
	}
	for i := 128; i < 256; i++ {
		if value, ok := rebuilt.Lookup(netip.AddrFrom4([4]byte{10, byte(i), 0, 5})); !ok || value != i {
			t.Fatalf("wide fanout lookup %d = (%d,%v)", i, value, ok)
		}
	}
}
