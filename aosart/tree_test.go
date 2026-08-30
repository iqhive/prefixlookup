package aosart

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

// the reference implementations below are deliberately naive linear scans of
// the original prefix list - everything - LPM, exact match, supernets and
// subnets - is checked against them. if the AoS tree disagrees with a scan of
// the input, the tree is wrong

// refLookup is the naive LPM oracle: scan every entry, keep the longest cover
// we Mask so uncanonical inputs still compare, skip the other family, and
// treat equal lengths as last-wins (same as a later insert overwriting)
func refLookup(entries []Entry[uint32], addr netip.Addr) (uint32, bool) {
	best := -1
	var value uint32
	for _, entry := range entries {
		prefix := entry.Prefix.Masked()
		if prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if prefix.Contains(addr) && prefix.Bits() >= best {
			best, value = prefix.Bits(), entry.Value
		}
	}
	return value, best >= 0
}

// refExact is the naive exact-match oracle: last entry whose Masked form
// equals the query. we keep scanning after a hit so duplicates last-win
func refExact(entries []Entry[uint32], prefix netip.Prefix) (uint32, bool) {
	want := prefix.Masked()
	var value uint32
	found := false
	for _, entry := range entries {
		if entry.Prefix.Masked() == want {
			value, found = entry.Value, true
		}
	}
	return value, found
}

// refSupernets is the naive covering-prefix oracle, most specific first
// we dedup via a map (the input list can repeat), then sort by bits descending
func refSupernets(entries []Entry[uint32], addr netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, entry := range entries {
		prefix := entry.Prefix.Masked()
		if prefix.Addr().Is4() != addr.Is4() || seen[prefix] {
			continue
		}
		if prefix.Contains(addr) {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	// most specific first - same order WalkSupernets claims to yield
	sort.Slice(out, func(i, j int) bool { return out[i].Bits() > out[j].Bits() })
	return out
}

// refSubnets is the naive contained-prefix oracle
// a stored prefix is a subnet of the query when it's at least as long and its
// addr sits inside the query. we sort the result so order doesn't matter
func refSubnets(entries []Entry[uint32], query netip.Prefix) []netip.Prefix {
	want := query.Masked()
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, entry := range entries {
		prefix := entry.Prefix.Masked()
		if prefix.Addr().Is4() != want.Addr().Is4() || seen[prefix] {
			continue
		}
		if prefix.Bits() >= want.Bits() && want.Contains(prefix.Addr()) {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	sortPrefixes(out)
	return out
}

// sortPrefixes orders by addr then bits, so two walks can be compared as slices
// addr first because that's how you'd read a routing table; bits ascending so
// a prefix sits next to its more-specifics
func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr() != prefixes[j].Addr() {
			return prefixes[i].Addr().Less(prefixes[j].Addr())
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
}

// buildIndex compiles entries through Builder and keeps id->value for checks
// last Add of a duplicate prefix keeps the same id and we'd overwrite values
// so this matches "last insert wins" as long as we iterate in order
func buildIndex(t *testing.T, entries []Entry[uint32]) (*Index, map[uint32]uint32) {
	t.Helper()
	builder := NewBuilder()
	values := map[uint32]uint32{}
	for _, entry := range entries {
		id, err := builder.Add(entry.Prefix)
		if err != nil {
			t.Fatalf("Add(%v): %v", entry.Prefix, err)
		}
		values[id] = entry.Value
	}
	return builder.Build(), values
}

// entriesOf parses CIDR strings into Entries numbered from 1
// value is i+1 so a miss (id 0 / value 0) can't be confused with a real hit
func entriesOf(prefixes ...string) []Entry[uint32] {
	out := make([]Entry[uint32], len(prefixes))
	for i, p := range prefixes {
		out[i] = Entry[uint32]{Prefix: netip.MustParsePrefix(p), Value: uint32(i + 1)}
	}
	return out
}

// probeAddrs builds a set of addrs that ought to stress the tree
// for each stored prefix we take its network addr, the prev/next of that, and
// the broadcast/top of the range (key with host bits flipped). then we throw
// in the all-zero and all-one addrs of both families
func probeAddrs(entries []Entry[uint32]) []netip.Addr {
	var out []netip.Addr
	// add records a plus its immediate neighbours if they exist
	add := func(a netip.Addr) {
		if !a.IsValid() {
			return
		}
		out = append(out, a)
		if p := a.Prev(); p.IsValid() {
			out = append(out, p)
		}
		if n := a.Next(); n.IsValid() {
			out = append(out, n)
		}
	}
	for _, entry := range entries {
		prefix := entry.Prefix.Masked()
		add(prefix.Addr())
		_, high, low, bits, is4, ok := decompose(prefix)
		if !ok {
			continue
		}
		maskHigh, maskLow := masks128(int(bits))
		add(addrOf(high|^maskHigh, low|^maskLow, is4))
	}
	out = append(out,
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	return out
}

// checkAll compares Lookup / Exact / WalkSupernets / WalkSubnets against the
// linear oracles for every probe addr and every stored prefix
//
// supernets must also be strictly most-specific-first. subnet walks get
// sorted before compare because walk order isn't required to match the oracle
func checkAll(t *testing.T, name string, entries []Entry[uint32], extra []netip.Addr) {
	t.Helper()
	index, values := buildIndex(t, entries)

	for _, addr := range append(probeAddrs(entries), extra...) {
		// Lookup against the linear scan
		wantValue, wantOK := refLookup(entries, addr)
		id, ok := index.Lookup(addr)
		if ok != wantOK || (wantOK && values[id] != wantValue) {
			t.Fatalf("%s: Lookup(%v) = %d,%v want %d,%v", name, addr, values[id], ok, wantValue, wantOK)
		}

		// supernets: same set, same most-specific-first order
		want := refSupernets(entries, addr)
		var got []netip.Prefix
		index.WalkSupernets(addr, func(_ uint32, prefix netip.Prefix) bool {
			got = append(got, prefix)
			return true
		})
		if len(got) != len(want) {
			t.Fatalf("%s: WalkSupernets(%v) yielded %v, want %v", name, addr, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: WalkSupernets(%v)[%d] = %v, want %v (got %v want %v)",
					name, addr, i, got[i], want[i], got, want)
			}
		}
		// most specific first must hold even if the oracle sort were wrong
		for i := 1; i < len(got); i++ {
			if got[i].Bits() > got[i-1].Bits() {
				t.Fatalf("%s: WalkSupernets(%v) not ordered: %v", name, addr, got)
			}
		}
	}

	for _, entry := range entries {
		prefix := entry.Prefix.Masked()

		// Exact against last-wins on the input list
		wantValue, wantOK := refExact(entries, prefix)
		id, ok := index.Exact(prefix)
		if ok != wantOK || (wantOK && values[id] != wantValue) {
			t.Fatalf("%s: Exact(%v) = %d,%v want %d,%v", name, prefix, values[id], ok, wantValue, wantOK)
		}

		// subnets: sort both sides, we don't pin walk order here
		want := refSubnets(entries, prefix)
		var got []netip.Prefix
		index.WalkSubnets(prefix, func(_ uint32, found netip.Prefix) bool {
			got = append(got, found)
			return true
		})
		sortPrefixes(got)
		if len(got) != len(want) {
			t.Fatalf("%s: WalkSubnets(%v) yielded %d (%v), want %d (%v)",
				name, prefix, len(got), got, len(want), want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: WalkSubnets(%v)[%d] = %v, want %v", name, prefix, i, got[i], want[i])
			}
		}
	}
}

// TestEmpty checks the empty index matches nothing
// freeze sets nodes to nil, so Lookup/Exact are a length check - this pins
// that we didn't leave a root node that accidentally matches
func TestEmpty(t *testing.T) {
	index, _ := buildIndex(t, nil)
	for _, addr := range []string{"0.0.0.0", "10.1.2.3", "::", "2001:db8::1"} {
		if _, ok := index.Lookup(netip.MustParseAddr(addr)); ok {
			t.Fatalf("empty index matched %s", addr)
		}
	}
	if _, ok := index.Exact(netip.MustParsePrefix("10.0.0.0/8")); ok {
		t.Fatal("empty index has an exact match")
	}
}

// TestStrideAlignedNesting covers the fringe-then-split path
// every one of these ends on a stride boundary, so each is first stored as a
// fringe and then split when the next longer one arrives
func TestStrideAlignedNesting(t *testing.T) {
	checkAll(t, "stride-aligned", entriesOf(
		"0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24", "10.0.0.0/32",
	), nil)
}

// TestMixedLengthNesting covers prefixes that don't sit on stride boundaries
// /7 /9 /15 /17 /23 /25 /31 so we hit within-stride ART slots and the
// covering-range walk in walkWithin, not just fringes
func TestMixedLengthNesting(t *testing.T) {
	checkAll(t, "mixed", entriesOf(
		"0.0.0.0/0", "10.0.0.0/7", "10.0.0.0/8", "10.0.0.0/9", "10.128.0.0/9",
		"10.0.0.0/15", "10.0.0.0/17", "10.0.0.0/23", "10.0.0.0/25", "10.0.0.128/25",
		"10.0.0.0/31", "10.0.0.0/32",
	), nil)
}

// TestSiblingsAndDisjoint covers multiple children of one node plus disjoint
// roots. 10.1/2/3 are sibling /16s; 172.16/12 with two /24s underneath
func TestSiblingsAndDisjoint(t *testing.T) {
	checkAll(t, "siblings", entriesOf(
		"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "192.168.0.0/16",
		"172.16.0.0/12", "172.16.5.0/24", "172.31.255.0/24",
	), nil)
}

// TestV6 covers the 16-deep tree, including /3 /10 /56 /96 /128 and a sibling
// /64. v6 is where path-compressed leaves actually earn their keep
func TestV6(t *testing.T) {
	checkAll(t, "v6", entriesOf(
		"::/0", "2000::/3", "2001:db8::/32", "2001:db8::/48", "2001:db8::/56",
		"2001:db8::/64", "2001:db8::/96", "2001:db8::/128", "2001:db8::1/128",
		"2001:db8:0:1::/64", "2001:db8:1::/48", "fe80::/10",
	), nil)
}

// TestExtremes covers the corners: /32 and /128 at all-zero and all-one, plus
// the /1s that split the space in half
func TestExtremes(t *testing.T) {
	checkAll(t, "extremes", entriesOf(
		"0.0.0.0/32", "255.255.255.255/32", "255.255.255.254/31", "128.0.0.0/1",
		"::/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"ffff:ffff:ffff:ffff::/64", "8000::/1",
	), nil)
}

// TestDefaultRouteIsASupernet pins that /0 is yielded after the more-specific
// we walk 10.1.2.3 against {0/0, 10/8} and want [10/8, 0/0] in that order -
// that's the path-buffer walk, not soaart's hits array
func TestDefaultRouteIsASupernet(t *testing.T) {
	index, values := buildIndex(t, entriesOf("0.0.0.0/0", "10.0.0.0/8"))
	var got []netip.Prefix
	index.WalkSupernets(netip.MustParseAddr("10.1.2.3"), func(id uint32, prefix netip.Prefix) bool {
		got = append(got, prefix)
		_ = values[id]
		return true
	})
	if len(got) != 2 || got[0].Bits() != 8 || got[1].Bits() != 0 {
		t.Fatalf("supernets = %v, want [10.0.0.0/8 0.0.0.0/0]", got)
	}
}

// TestSubnetsOfDefaultRoute pins that walking /0 yields every stored v4 prefix
// four entries, four yields - the default route is a subnet of itself too
func TestSubnetsOfDefaultRoute(t *testing.T) {
	entries := entriesOf("0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/16")
	index, _ := buildIndex(t, entries)
	var got []netip.Prefix
	index.WalkSubnets(netip.MustParsePrefix("0.0.0.0/0"), func(_ uint32, prefix netip.Prefix) bool {
		got = append(got, prefix)
		return true
	})
	if len(got) != 4 {
		t.Fatalf("subnets of the default route = %v, want all four", got)
	}
}

// TestWalkStopsEarly checks yield returning false actually stops
// we count two yields then false; if the walk ignored us we'd see more than 2
func TestWalkStopsEarly(t *testing.T) {
	entries := entriesOf("0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24")
	index, _ := buildIndex(t, entries)
	count := 0
	index.WalkSupernets(netip.MustParseAddr("10.1.1.1"), func(uint32, netip.Prefix) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Fatalf("WalkSupernets ignored the stop signal after %d yields", count)
	}
	count = 0
	index.WalkSubnets(netip.MustParsePrefix("0.0.0.0/0"), func(uint32, netip.Prefix) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Fatalf("WalkSubnets ignored the stop signal after %d yields", count)
	}
}

// TestMapped4In6 checks ::ffff:10.1.2.3 hits the v4 tree
// Lookup Unmaps 4in6 before the descent; if that branch is broken we miss
func TestMapped4In6(t *testing.T) {
	index, values := buildIndex(t, entriesOf("10.0.0.0/8"))
	id, ok := index.Lookup(netip.MustParseAddr("::ffff:10.1.2.3"))
	if !ok || values[id] != 1 {
		t.Fatal("mapped address should reach the IPv4 tree")
	}
}

// randomEntries builds n random prefixes with a v6 mix and a fixed seed
// v4 is deliberately a narrow 10.0-3.0-7.x space so nesting and sibling splits
// are common rather than rare. v6 is 2000::/2001:: with realistic lengths
func randomEntries(n int, v6mix float64, seed int64) []Entry[uint32] {
	v4Lengths := []int{8, 12, 16, 17, 18, 20, 21, 22, 23, 24, 24, 24, 25, 28, 31, 32}
	v6Lengths := []int{20, 29, 32, 32, 36, 40, 44, 47, 48, 48, 56, 64, 96, 127, 128}
	rng := rand.New(rand.NewSource(seed))
	out := make([]Entry[uint32], 0, n)
	for len(out) < n {
		if rng.Float64() < v6mix {
			var b [16]byte
			b[0] = 0x20 | byte(rng.Intn(2))
			for i := 1; i < 16; i++ {
				b[i] = byte(rng.Intn(256))
			}
			length := v6Lengths[rng.Intn(len(v6Lengths))]
			out = append(out, Entry[uint32]{
				Prefix: netip.PrefixFrom(netip.AddrFrom16(b), length).Masked(),
				Value:  uint32(len(out) + 1)})
			continue
		}
		// a deliberately narrow address space, so nesting and sibling splits are
		// common rather than rare
		b := [4]byte{10, byte(rng.Intn(4)), byte(rng.Intn(8)), byte(rng.Intn(256))}
		length := v4Lengths[rng.Intn(len(v4Lengths))]
		out = append(out, Entry[uint32]{
			Prefix: netip.PrefixFrom(netip.AddrFrom4(b), length).Masked(),
			Value:  uint32(len(out) + 1)})
	}
	return out
}

// TestAgainstReference fuzzes checkAll over size × v6mix
// sizes from 1 to 2000, mix 0 / 0.3 / 1, seed derived from size and mix so
// failures reproduce. this is the test that actually catches insert bugs
func TestAgainstReference(t *testing.T) {
	for _, size := range []int{1, 2, 5, 40, 400, 2000} {
		for _, mix := range []float64{0, 0.3, 1} {
			name := fmt.Sprintf("size=%d/v6mix=%g", size, mix)
			t.Run(name, func(t *testing.T) {
				entries := randomEntries(size, mix, int64(size)*13+int64(mix*100))
				checkAll(t, name, entries, nil)
			})
		}
	}
}

// TestTableTraversalAndUpdates mutates a managed Table and checks Lookup /
// WalkSupernets against a live map oracle
//
// 200 random insert/delete steps, every 17th we probe. this also exercises
// the packed-slice ApplyBatch path (structural vs value-only) which soaart
// does with a map instead
func TestTableTraversalAndUpdates(t *testing.T) {
	entries := randomEntries(300, 0.3, 99)
	table, err := New(entries)
	if err != nil {
		t.Fatal(err)
	}
	live := map[netip.Prefix]uint32{}
	for _, entry := range entries {
		live[entry.Prefix.Masked()] = entry.Value
	}
	// asEntries dumps the live map into the slice the linear oracles want
	asEntries := func() []Entry[uint32] {
		out := make([]Entry[uint32], 0, len(live))
		for p, v := range live {
			out = append(out, Entry[uint32]{Prefix: p, Value: v})
		}
		return out
	}

	rng := rand.New(rand.NewSource(3))
	for step := 0; step < 200; step++ {
		candidate := entries[rng.Intn(len(entries))].Prefix.Masked()
		if rng.Intn(3) == 0 {
			table.Delete(candidate)
			delete(live, candidate)
		} else {
			value := uint32(rng.Intn(1 << 20))
			if err := table.Insert(candidate, value); err != nil {
				t.Fatal(err)
			}
			live[candidate] = value
		}
		if step%17 != 0 {
			continue
		}
		current := asEntries()
		for _, addr := range probeAddrs(current)[:min(60, len(probeAddrs(current)))] {
			wantValue, wantOK := refLookup(current, addr)
			gotValue, gotOK := table.Lookup(addr)
			if gotOK != wantOK || (wantOK && gotValue != wantValue) {
				t.Fatalf("step %d: Lookup(%v) = %d,%v want %d,%v",
					step, addr, gotValue, gotOK, wantValue, wantOK)
			}
			var got []netip.Prefix
			table.WalkSupernets(addr, func(prefix netip.Prefix, _ uint32) bool {
				got = append(got, prefix)
				return true
			})
			want := refSupernets(current, addr)
			if len(got) != len(want) {
				t.Fatalf("step %d: WalkSupernets(%v) = %v want %v", step, addr, got, want)
			}
		}
	}
}

// TestValueUpdateKeepsIndex pins that a value-only change does not recompile
// Insert of an existing prefix is the cheap ApplyBatch path: same Index
// pointer, new value vector. /16 must still win for 10.0.0.1. this is the
// packed-slice version of the same pin soaart has against its map
func TestValueUpdateKeepsIndex(t *testing.T) {
	table, err := New([]Entry[uint32]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/16"), Value: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := table.Index()
	if err := table.Insert(netip.MustParsePrefix("10.0.0.0/8"), 42); err != nil {
		t.Fatal(err)
	}
	if table.Index() != before {
		t.Fatal("value-only update must reuse the index")
	}
	if v, _ := table.Lookup(netip.MustParseAddr("10.1.0.1")); v != 42 {
		t.Fatalf("updated /8 = %d, want 42", v)
	}
	if v, _ := table.Lookup(netip.MustParseAddr("10.0.0.1")); v != 2 {
		t.Fatalf("/16 changed to %d, want 2", v)
	}
}
