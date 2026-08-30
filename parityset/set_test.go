package parityset

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

// naive is the reference implementation: a linear scan of the original
// prefixes - every test compares against it, so the canonical reduction is
// checked against the semantics it claims to preserve rather than against
// another compiled form
type naive []netip.Prefix

// contains is the linear-scan membership test - first covering prefix wins
func (n naive) contains(addr netip.Addr) bool {
	for _, prefix := range n {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// mustSet compiles prefixes or fails the test
func mustSet(t *testing.T, prefixes []netip.Prefix) *Set {
	t.Helper()
	set, err := New(prefixes)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return set
}

// probeAddrs returns the addresses at which a prefix set can change answer:
// every range boundary and its neighbours, plus the extremes of each family
func probeAddrs(prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	add := func(a netip.Addr) {
		if !a.IsValid() {
			return
		}
		out = append(out, a)
		if prev := a.Prev(); prev.IsValid() {
			out = append(out, prev)
		}
		if next := a.Next(); next.IsValid() {
			out = append(out, next)
		}
	}
	for _, prefix := range prefixes {
		add(prefix.Addr())
		last := lastAddr(prefix)
		add(last)
	}
	out = append(out,
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	)
	return out
}

// lastAddr returns the highest address inside prefix, by setting the host bits
func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	length := prefix.Bits()
	if addr.Is4() {
		first := be32(addr.As4())
		var mask uint32
		if length > 0 {
			mask = ^uint32(0) << (32 - length)
		}
		last := first | ^mask
		return netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
	}
	high, low := words16(addr.As16())
	if length < 64 {
		high |= ^uint64(0) >> length
		low = ^uint64(0)
	} else if length < 128 {
		low |= ^uint64(0) >> (length - 64)
	}
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(high >> (56 - i*8))
		b[8+i] = byte(low >> (56 - i*8))
	}
	return netip.AddrFrom16(b)
}

// checkAgainstNaive compiles the set and compares Contains against the linear
// scan on every probe plus extras
func checkAgainstNaive(t *testing.T, name string, prefixes []netip.Prefix, extra []netip.Addr) {
	t.Helper()
	set := mustSet(t, prefixes)
	reference := naive(prefixes)
	queries := append(probeAddrs(prefixes), extra...)
	for _, addr := range queries {
		want := reference.contains(addr)
		if got := set.Contains(addr); got != want {
			t.Fatalf("%s: Contains(%v) = %v, want %v", name, addr, got, want)
		}
	}
}

// TestEmpty checks that a set with nothing in it contains nothing
func TestEmpty(t *testing.T) {
	set := mustSet(t, nil)
	for _, addr := range []string{"0.0.0.0", "10.1.2.3", "255.255.255.255", "::", "2001:db8::1"} {
		if set.Contains(netip.MustParseAddr(addr)) {
			t.Fatalf("empty set contains %s", addr)
		}
	}
	if v4, v6 := set.Ranges(); v4 != 0 || v6 != 0 {
		t.Fatalf("Ranges = %d,%d want 0,0", v4, v6)
	}
}

// TestDefaultRouteCollapses pins that a /0 eats every more-specific and leaves
// no boundaries at all
func TestDefaultRouteCollapses(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.2.0/24"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	set := mustSet(t, prefixes)
	v4, v6 := set.Ranges()
	if v4 != 0 || v6 != 0 {
		t.Fatalf("Ranges = %d,%d; a default route should leave no boundaries at all", v4, v6)
	}
	if bytes := set.RetainedBytes(); bytes != 0 {
		t.Fatalf("RetainedBytes = %d, want 0", bytes)
	}
	for _, addr := range []string{"0.0.0.0", "1.2.3.4", "255.255.255.255", "::", "2001:db8::1", "ffff::1"} {
		if !set.Contains(netip.MustParseAddr(addr)) {
			t.Fatalf("default route present but %s not contained", addr)
		}
	}
}

// TestSiblingCoalescing checks that two /25s covering a /24, plus the adjacent
// /24, merge into one range
func TestSiblingCoalescing(t *testing.T) {
	// two /25s that together cover their /24 must reduce to one range, and two
	// /24s that are adjacent must merge as well
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.1.2.0/25"),
		netip.MustParsePrefix("10.1.2.128/25"),
		netip.MustParsePrefix("10.1.3.0/24"),
	}
	set := mustSet(t, prefixes)
	if v4, _ := set.Ranges(); v4 != 1 {
		t.Fatalf("Ranges = %d, want 1 (10.1.2.0/23 equivalent)", v4)
	}
	checkAgainstNaive(t, "siblings", prefixes, nil)
}

// TestRedundantMoreSpecificsDropped dumps 500 /24s under a /8 and expects one range
func TestRedundantMoreSpecificsDropped(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for i := 0; i < 500; i++ {
		prefixes = append(prefixes, netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24))
	}
	set := mustSet(t, prefixes)
	if v4, _ := set.Ranges(); v4 != 1 {
		t.Fatalf("Ranges = %d, want 1: every /24 is covered by 10.0.0.0/8", v4)
	}
	checkAgainstNaive(t, "redundant", prefixes, nil)
}

// TestExtremes hits the first and last addresses of each family
func TestExtremes(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
		netip.MustParsePrefix("ffff:ffff:ffff:ffff::/64"),
	}
	checkAgainstNaive(t, "extremes", prefixes, nil)
}

// TestFullSpaceViaHalves checks that 0/1 plus 128/1 cover the whole IPv4 space
func TestFullSpaceViaHalves(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	set := mustSet(t, prefixes)
	if v4, _ := set.Ranges(); v4 != 0 {
		t.Fatalf("Ranges = %d, want 0: the two halves cover the whole space", v4)
	}
	if !set.Contains(netip.MustParseAddr("200.1.2.3")) {
		t.Fatal("whole IPv4 space should be covered")
	}
}

// TestBadPrefixes rejects the zero prefix and a zoned one
func TestBadPrefixes(t *testing.T) {
	if _, err := New([]netip.Prefix{{}}); err != ErrBadPrefix {
		t.Fatalf("invalid prefix: err = %v, want ErrBadPrefix", err)
	}
	zoned, err := netip.ParsePrefix("fe80::1%eth0/64")
	if err == nil {
		if _, err := New([]netip.Prefix{zoned}); err != ErrBadPrefix {
			t.Fatalf("zoned prefix: err = %v, want ErrBadPrefix", err)
		}
	}
}

// TestUnmaskedInputIsMasked checks that 10.1.2.3/24 is treated as 10.1.2.0/24
func TestUnmaskedInputIsMasked(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.1.2.3/24")}
	set := mustSet(t, prefixes)
	if !set.Contains(netip.MustParseAddr("10.1.2.0")) {
		t.Fatal("10.1.2.3/24 should cover 10.1.2.0")
	}
	if set.Contains(netip.MustParseAddr("10.1.3.0")) {
		t.Fatal("10.1.2.3/24 should not cover 10.1.3.0")
	}
}

// TestMapped4In6 checks that ::ffff:10.1.2.3 hits the IPv4 index
func TestMapped4In6(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	set := mustSet(t, prefixes)
	mapped := netip.MustParseAddr("::ffff:10.1.2.3")
	if !set.Contains(mapped) {
		t.Fatal("IPv4-mapped address should be answered by the IPv4 index")
	}
}

// randomPrefixes generates a BGP-shaped mixture, the same shape the benchmark
// fixture uses, so that both the small and the slot-table code paths are hit
func randomPrefixes(n int, v6mix float64, seed int64) []netip.Prefix {
	v4Lengths := []int{8, 12, 16, 16, 18, 19, 20, 21, 22, 23, 24, 24, 24, 25, 28, 32}
	v6Lengths := []int{20, 28, 32, 32, 36, 40, 44, 48, 48, 56, 64, 96, 128}
	rng := rand.New(rand.NewSource(seed))
	out := make([]netip.Prefix, 0, n)
	for len(out) < n {
		if rng.Float64() < v6mix {
			var b [16]byte
			b[0] = 0x20 | byte(rng.Intn(2))
			for i := 1; i < 16; i++ {
				b[i] = byte(rng.Intn(256))
			}
			length := v6Lengths[rng.Intn(len(v6Lengths))]
			out = append(out, netip.PrefixFrom(netip.AddrFrom16(b), length).Masked())
			continue
		}
		b := [4]byte{byte(1 + rng.Intn(222)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		length := v4Lengths[rng.Intn(len(v4Lengths))]
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), length).Masked())
	}
	return out
}

// TestAgainstNaiveRandom throws random tables at the set, including sizes that
// sit on either side of slotTableLimit
func TestAgainstNaiveRandom(t *testing.T) {
	for _, size := range []int{1, 2, 7, 40, 95, 96, 97, 300, 5000} {
		for _, mix := range []float64{0, 0.15, 1} {
			name := fmt.Sprintf("size=%d/v6mix=%g", size, mix)
			t.Run(name, func(t *testing.T) {
				prefixes := randomPrefixes(size, mix, int64(size)*100+int64(mix*10))
				rng := rand.New(rand.NewSource(int64(size)))
				extra := make([]netip.Addr, 0, 400)
				for i := 0; i < 200; i++ {
					extra = append(extra, netip.AddrFrom4([4]byte{
						byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}))
					var b [16]byte
					for j := range b {
						b[j] = byte(rng.Intn(256))
					}
					b[0] = 0x20
					extra = append(extra, netip.AddrFrom16(b))
				}
				checkAgainstNaive(t, name, prefixes, extra)
			})
		}
	}
}

// TestSlotTableThreshold checks that both the direct-search and slot-table code
// paths produce identical answers on the same input, by forcing each in turn
func TestSlotTableThreshold(t *testing.T) {
	prefixes := randomPrefixes(2000, 0.2, 7)
	withTable := mustSet(t, prefixes)
	if withTable.v4.slots == nil || withTable.v4.front == nil {
		t.Fatal("expected the IPv4 front and slot tables to be built at this size")
	}
	// rebuild the same boundaries without the slot table
	var b builder
	for _, prefix := range prefixes {
		if !b.add(prefix) {
			t.Fatalf("add(%v) failed", prefix)
		}
	}
	direct := b.build()
	direct.v4.front, direct.v4.slots = nil, nil
	direct.v6.front, direct.v6.slots = nil, nil
	direct.v6.subBlock, direct.v6.sub = nil, nil

	reference := naive(prefixes)
	for _, addr := range probeAddrs(prefixes) {
		want := reference.contains(addr)
		if got := withTable.Contains(addr); got != want {
			t.Fatalf("slot table: Contains(%v) = %v want %v", addr, got, want)
		}
		if got := direct.Contains(addr); got != want {
			t.Fatalf("direct search: Contains(%v) = %v want %v", addr, got, want)
		}
	}
}

// TestTableMutations randomly inserts and deletes against a live Table and
// checks Contains against a map of live prefixes
func TestTableMutations(t *testing.T) {
	table, err := NewTable(nil)
	if err != nil {
		t.Fatal(err)
	}
	live := map[netip.Prefix]struct{}{}
	reference := func(addr netip.Addr) bool {
		for prefix := range live {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}

	rng := rand.New(rand.NewSource(11))
	candidates := randomPrefixes(400, 0.25, 12)
	for step := 0; step < 3000; step++ {
		prefix := candidates[rng.Intn(len(candidates))]
		if rng.Intn(3) == 0 {
			wantExisted := false
			if _, ok := live[prefix]; ok {
				wantExisted = true
			}
			if got := table.Delete(prefix); got != wantExisted {
				t.Fatalf("step %d: Delete(%v) = %v want %v", step, prefix, got, wantExisted)
			}
			delete(live, prefix)
		} else {
			_, existed := live[prefix]
			if got := table.Insert(prefix); got != !existed {
				t.Fatalf("step %d: Insert(%v) = %v want %v", step, prefix, got, !existed)
			}
			live[prefix] = struct{}{}
		}
		if step%37 != 0 {
			continue
		}
		all := make([]netip.Prefix, 0, len(live))
		for prefix := range live {
			all = append(all, prefix)
		}
		for _, addr := range probeAddrs(all) {
			if got, want := table.Contains(addr), reference(addr); got != want {
				t.Fatalf("step %d: Contains(%v) = %v want %v (live=%d)", step, addr, got, want, len(live))
			}
		}
	}
}

// TestNoOpInsertDoesNotRepublish pins the documented behaviour that a mutation
// which cannot change an answer publishes no new generation
func TestNoOpInsertDoesNotRepublish(t *testing.T) {
	table, err := NewTable([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	before := table.Snapshot()
	if !table.Insert(netip.MustParsePrefix("10.1.2.0/24")) {
		t.Fatal("Insert of a new prefix should report true")
	}
	if table.Snapshot() != before {
		t.Fatal("covered prefix should not trigger a republish")
	}
	if table.Insert(netip.MustParsePrefix("10.0.0.0/8")) {
		t.Fatal("Insert of an existing prefix should report false")
	}
	if table.Snapshot() != before {
		t.Fatal("duplicate prefix should not trigger a republish")
	}
	// deleting the covering prefix must bring the covered one back
	if !table.Delete(netip.MustParsePrefix("10.0.0.0/8")) {
		t.Fatal("Delete should report true")
	}
	if table.Contains(netip.MustParseAddr("10.9.9.9")) {
		t.Fatal("10.9.9.9 should no longer be covered")
	}
	if !table.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("10.1.2.0/24 should have survived the delete of its cover")
	}
}

// TestApplyBatch checks insert+insert+delete in one generation
func TestApplyBatch(t *testing.T) {
	table, err := NewTable(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = table.ApplyBatch([]Mutation{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		{Prefix: netip.MustParsePrefix("192.168.0.0/16")},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Delete: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if table.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("10.0.0.0/8 was deleted in the same batch")
	}
	if !table.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("192.168.0.0/16 should be present")
	}
}
