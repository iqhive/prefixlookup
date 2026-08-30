package fibbench

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/iqhive/prefixlookup/dirlpm"
	"github.com/iqhive/prefixlookup/dirset"
	"github.com/iqhive/prefixlookup/flatlpm"
	"github.com/iqhive/prefixlookup/flatset"
	"github.com/iqhive/prefixlookup/flatwalk"
	"github.com/iqhive/prefixlookup/orderwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// this file cross-checks the six new impls against bart and against each
// other - each package has its own oracle test, but agreeing with an
// independent impl on the same inputs is stronger, and it's the only check
// that covers the shared arena core from every direction at once
//
// the prefix sets below deliberately include the shapes that distinguish the
// designs: default routes (whole-space / inherited-default paths), prefixes
// at and either side of every stride boundary, prefixes longer than /24
// (that's the third IPv4 level), and single-prefix subtrees (path-compress)

// equivalencePrefixes builds a mixed bag: optional defaults, a hand-picked
// stride-boundary neighbourhood, then `size` random v4/v6 prefixes with
// de-dupe via a map
//
// we keep the stride neighbours even when size is 0 so the empty-table case
// still exercises those lengths
func equivalencePrefixes(rng *rand.Rand, size int, withDefaults bool) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, size+40)
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		p = p.Masked()
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	if withDefaults {
		add(netip.MustParsePrefix("0.0.0.0/0"))
		add(netip.MustParsePrefix("::/0"))
	}
	// stride boundaries and their neighbours
	for _, s := range []string{
		"10.0.0.0/7", "10.0.0.0/8", "10.0.0.0/9",
		"10.1.0.0/15", "10.1.0.0/16", "10.1.0.0/17",
		"10.1.2.0/23", "10.1.2.0/24", "10.1.2.0/25",
		"10.1.2.0/31", "10.1.2.0/32", "10.1.2.255/32",
		"2001:db8::/15", "2001:db8::/16", "2001:db8::/17",
		"2001:db8::/31", "2001:db8::/32", "2001:db8::/33",
		"2001:db8::/47", "2001:db8::/48", "2001:db8::/49",
		"2001:db8::/64", "2001:db8::/127", "2001:db8::/128",
	} {
		add(netip.MustParsePrefix(s))
	}
	for i := 0; i < size; i++ {
		if i%4 == 0 {
			var b [16]byte
			for j := range b {
				b[j] = byte(rng.Intn(256))
			}
			add(netip.PrefixFrom(netip.AddrFrom16(b), rng.Intn(129)))
			continue
		}
		var b [4]byte
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		add(netip.PrefixFrom(netip.AddrFrom4(b), rng.Intn(33)))
	}
	return out
}

// equivalenceQueries mixes three probe kinds so we don't only hit the happy
// path: an addr inside a stored prefix, the prefix's own base addr, and a
// fully random v4/v6 (likely miss unless defaults are in)
func equivalenceQueries(rng *rand.Rand, prefixes []netip.Prefix, n int) []netip.Addr {
	out := make([]netip.Addr, 0, n)
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			// an address inside a stored prefix
			out = append(out, realAddrIn(prefixes[rng.Intn(len(prefixes))], rng))
		case 1:
			// a stored prefix's own base address
			out = append(out, prefixes[rng.Intn(len(prefixes))].Addr())
		default:
			if rng.Intn(2) == 0 {
				var b [4]byte
				for j := range b {
					b[j] = byte(rng.Intn(256))
				}
				out = append(out, netip.AddrFrom4(b))
			} else {
				var b [16]byte
				for j := range b {
					b[j] = byte(rng.Intn(256))
				}
				out = append(out, netip.AddrFrom16(b))
			}
		}
	}
	return out
}

// TestImplementationsAgree drives every new impl plus bart over the same
// table and query stream and demands identical answers
//
// we sweep size 0/1/50/2000, with and without defaults, three seeds - empty
// and singleton catch "forgot to handle zero routes", 2000 is enough to
// materialise extra stride levels without making this a bench
func TestImplementationsAgree(t *testing.T) {
	for _, size := range []int{0, 1, 50, 2000} {
		for _, withDefaults := range []bool{false, true} {
			for seed := int64(1); seed <= 3; seed++ {
				name := fmt.Sprintf("size=%d/defaults=%v/seed=%d", size, withDefaults, seed)
				t.Run(name, func(t *testing.T) {
					rng := rand.New(rand.NewSource(seed*1000 + int64(size)))
					prefixes := equivalencePrefixes(rng, size, withDefaults)
					entries := make([]prefixentry.Entry[NextHop], len(prefixes))
					for i, prefix := range prefixes {
						entries[i] = prefixentry.Entry[NextHop]{Prefix: prefix, Value: NextHop(i + 1)}
					}

					reference := new(bart.Table[NextHop])
					for i, prefix := range prefixes {
						reference.Insert(prefix, NextHop(i+1))
					}
					membership := new(bart.Lite)
					for _, prefix := range prefixes {
						membership.Insert(prefix)
					}

					value1 := mustBuild(flatlpm.New(entries, routeupdate.Options{}))
					defer value1.Close()
					value3 := mustBuild(dirlpm.New(entries, routeupdate.Options{}))
					defer value3.Close()
					walk1 := mustBuild(flatwalk.New(entries))
					walk3 := mustBuild(orderwalk.New(entries))
					member1 := mustBuild(flatset.New(prefixes))
					member3 := mustBuild(dirset.New(prefixes))

					queries := equivalenceQueries(rng, append(prefixes, netip.MustParsePrefix("0.0.0.0/0")), 4000)
					for _, addr := range queries {
						want, wantOK := reference.Lookup(addr)
						check := func(name string, value NextHop, ok bool) {
							if ok != wantOK || (wantOK && value != want) {
								t.Fatalf("%s.Lookup(%v) = (%d,%v), bart says (%d,%v)",
									name, addr, value, ok, want, wantOK)
							}
						}
						v1, ok1 := value1.Lookup(addr)
						check("flatlpm", v1, ok1)
						v3, ok3 := value3.Lookup(addr)
						check("dirlpm", v3, ok3)
						w1, okw1 := walk1.Lookup(addr)
						check("flatwalk", w1, okw1)
						w3, okw3 := walk3.Lookup(addr)
						check("orderwalk", w3, okw3)

						wantMember := membership.Lookup(addr)
						if got := member1.Contains(addr); got != wantMember {
							t.Fatalf("flatset.Contains(%v) = %v, bart.Lite says %v", addr, got, wantMember)
						}
						if got := member3.Contains(addr); got != wantMember {
							t.Fatalf("dirset.Contains(%v) = %v, bart.Lite says %v", addr, got, wantMember)
						}
					}

					// exact match and both walks, against bart's own iterators -
					// absent prefixes matter as much as present ones: an exact
					// match must not be confused with a covering match
					probes := append([]netip.Prefix{}, prefixes...)
					for i := 0; i < 300; i++ {
						if i%2 == 0 {
							var b [4]byte
							for j := range b {
								b[j] = byte(rng.Intn(256))
							}
							probes = append(probes, netip.PrefixFrom(netip.AddrFrom4(b), rng.Intn(33)).Masked())
							continue
						}
						var b [16]byte
						for j := range b {
							b[j] = byte(rng.Intn(256))
						}
						probes = append(probes, netip.PrefixFrom(netip.AddrFrom16(b), rng.Intn(129)).Masked())
					}
					for _, query := range probes {
						want, wantOK := reference.Get(query)
						if _, got, ok := walk1.Exact(query); ok != wantOK || (wantOK && got != want) {
							t.Fatalf("flatwalk.Exact(%v) = (%d,%v), bart says (%d,%v)", query, got, ok, want, wantOK)
						}
						if _, got, ok := walk3.Exact(query); ok != wantOK || (wantOK && got != want) {
							t.Fatalf("orderwalk.Exact(%v) = (%d,%v), bart says (%d,%v)", query, got, ok, want, wantOK)
						}
						if got, ok := value3.Exact(query); ok != wantOK || (wantOK && got != want) {
							t.Fatalf("dirlpm.Exact(%v) = (%d,%v), bart says (%d,%v)", query, got, ok, want, wantOK)
						}
					}

					// descendant walks must agree with bart's Subnets iterator
					for _, query := range prefixes {
						var want []netip.Prefix
						for got := range reference.Subnets(query) {
							want = append(want, got)
						}
						sort.Slice(want, func(i, j int) bool { return comparePrefix(want[i], want[j]) < 0 })
						assertDescendants(t, "flatwalk", query, want, func(yield func(netip.Prefix)) {
							walk1.WalkDescendants(query, func(_ flatwalk.RouteID, p netip.Prefix, _ NextHop) bool {
								yield(p)
								return true
							})
						})
						assertDescendants(t, "orderwalk", query, want, func(yield func(netip.Prefix)) {
							walk3.WalkDescendants(query, func(_ orderwalk.RouteID, p netip.Prefix, _ NextHop) bool {
								yield(p)
								return true
							})
						})
					}

					// ancestor walks must agree with bart's Supernets iterator
					for _, addr := range queries[:200] {
						host := netip.PrefixFrom(addr, addr.BitLen())
						var want []netip.Prefix
						for got := range reference.Supernets(host) {
							want = append(want, got)
						}
						sort.Slice(want, func(i, j int) bool { return want[i].Bits() > want[j].Bits() })
						assertAncestors(t, "flatwalk", addr, want, func(yield func(netip.Prefix)) {
							walk1.WalkParents(addr, func(_ flatwalk.RouteID, p netip.Prefix, _ NextHop) bool {
								yield(p)
								return true
							})
						})
						assertAncestors(t, "orderwalk", addr, want, func(yield func(netip.Prefix)) {
							walk3.WalkParents(addr, func(_ orderwalk.RouteID, p netip.Prefix, _ NextHop) bool {
								yield(p)
								return true
							})
						})
					}
				})
			}
		}
	}
}

// comparePrefix is a total order for sorting descendant dumps: v4 before v6,
// then addr, then bits - bart's iterator order isn't something we want to
// depend on
func comparePrefix(a, b netip.Prefix) int {
	if a.Addr().Is4() != b.Addr().Is4() {
		if a.Addr().Is4() {
			return -1
		}
		return 1
	}
	if a.Addr() != b.Addr() {
		if a.Addr().Less(b.Addr()) {
			return -1
		}
		return 1
	}
	return a.Bits() - b.Bits()
}

// assertDescendants walks via `walk`, sorts, and diffs against bart's Subnets
// dump - we sort both sides because walk order isn't part of the contract
func assertDescendants(t *testing.T, name string, query netip.Prefix, want []netip.Prefix, walk func(func(netip.Prefix))) {
	t.Helper()
	var got []netip.Prefix
	walk(func(p netip.Prefix) { got = append(got, p) })
	sort.Slice(got, func(i, j int) bool { return comparePrefix(got[i], got[j]) < 0 })
	if len(got) != len(want) {
		t.Fatalf("%s.WalkDescendants(%v) yielded %d prefixes, bart yielded %d\n got=%v\nwant=%v",
			name, query, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s.WalkDescendants(%v)[%d] = %v, bart says %v", name, query, i, got[i], want[i])
		}
	}
}

// assertAncestors walks via `walk` and diffs against bart's Supernets dump -
// we do NOT sort here because longest-first is part of the WalkParents contract
func assertAncestors(t *testing.T, name string, addr netip.Addr, want []netip.Prefix, walk func(func(netip.Prefix))) {
	t.Helper()
	var got []netip.Prefix
	walk(func(p netip.Prefix) { got = append(got, p) })
	if len(got) != len(want) {
		t.Fatalf("%s.WalkParents(%v) yielded %d prefixes, bart yielded %d\n got=%v\nwant=%v",
			name, addr, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s.WalkParents(%v)[%d] = %v, bart says %v", name, addr, i, got[i], want[i])
		}
	}
}
