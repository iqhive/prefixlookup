package steplpm

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

// naiveLookup is the reference: the longest prefix covering addr, by linear
// scan of the original entries - every test compares against it, so the leaf
// pushing and the run collapsing are checked against LPM semantics rather than
// against another compiled form
func naiveLookup(entries []Entry[uint32], addr netip.Addr) (uint32, bool) {
	best := -1
	var value uint32
	for _, entry := range entries {
		prefix := entry.Prefix.Masked()
		if prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		// ties use >=, so the last duplicate wins, matching Builder.Add
		if prefix.Contains(addr) && prefix.Bits() >= best {
			best, value = prefix.Bits(), entry.Value
		}
	}
	return value, best >= 0
}

// buildIndex compiles entries through Builder and returns the id->value map
// we keep the map so tests can check values without going through Table
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

// probeAddrs returns the interesting addresses around every prefix: the
// network address, the last address, and each of those plus/minus one, plus
// the family extremes - that's where the step function actually changes
func probeAddrs(entries []Entry[uint32]) []netip.Addr {
	var out []netip.Addr
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
		add(lastAddr(prefix))
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

// checkIndex builds the index and compares Lookup against naiveLookup on every
// probe address plus whatever extras the caller threw in
func checkIndex(t *testing.T, name string, entries []Entry[uint32], extra []netip.Addr) {
	t.Helper()
	index, values := buildIndex(t, entries)
	for _, addr := range append(probeAddrs(entries), extra...) {
		wantValue, wantOK := naiveLookup(entries, addr)
		id := index.Lookup(addr)
		if (id != 0) != wantOK {
			t.Fatalf("%s: Lookup(%v) matched=%v, want %v", name, addr, id != 0, wantOK)
		}
		if wantOK && values[id] != wantValue {
			t.Fatalf("%s: Lookup(%v) = %d, want %d", name, addr, values[id], wantValue)
		}
	}
}

// entriesOf parses prefix strings and stamps each with value i+1
func entriesOf(prefixes ...string) []Entry[uint32] {
	out := make([]Entry[uint32], len(prefixes))
	for i, p := range prefixes {
		out[i] = Entry[uint32]{Prefix: netip.MustParsePrefix(p), Value: uint32(i + 1)}
	}
	return out
}

// TestEmptyIndex checks that a table with nothing in it matches nothing
func TestEmptyIndex(t *testing.T) {
	index, _ := buildIndex(t, nil)
	for _, addr := range []string{"0.0.0.0", "10.1.2.3", "::", "2001:db8::1"} {
		if id := index.Lookup(netip.MustParseAddr(addr)); id != 0 {
			t.Fatalf("empty index matched %s with id %d", addr, id)
		}
	}
}

// TestNesting covers prefixes nested at the same network address - that's the
// case where a prefix's own id cannot be recovered by looking up its network
func TestNesting(t *testing.T) {
	// deliberately nested at the same network address, which is the case where
	// a prefix's own id cannot be recovered by looking up its network address
	checkIndex(t, "nested", entriesOf(
		"0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24", "10.0.0.0/32",
		"10.0.1.0/24", "10.1.0.0/16", "11.0.0.0/8",
	), nil)
}

// TestDefaultRouteOnly checks that a lone /0 covers every address in its family
func TestDefaultRouteOnly(t *testing.T) {
	entries := entriesOf("0.0.0.0/0", "::/0")
	index, values := buildIndex(t, entries)
	if id := index.Lookup(netip.MustParseAddr("8.8.8.8")); values[id] != 1 {
		t.Fatalf("v4 default: got value %d", values[id])
	}
	if id := index.Lookup(netip.MustParseAddr("2001:db8::1")); values[id] != 2 {
		t.Fatalf("v6 default: got value %d", values[id])
	}
	checkIndex(t, "defaults", entries, nil)
}

// TestExtremes hits the first and last addresses of each family, plus /1s
func TestExtremes(t *testing.T) {
	checkIndex(t, "extremes", entriesOf(
		"0.0.0.0/32", "255.255.255.255/32", "255.255.255.254/31", "128.0.0.0/1",
		"::/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"ffff:ffff:ffff:ffff::/64", "8000::/1",
	), nil)
}

// TestV6BeyondSixtyFour forces prefixes past /64 so the low word actually matters
func TestV6BeyondSixtyFour(t *testing.T) {
	checkIndex(t, "long-v6", entriesOf(
		"2001:db8::/32", "2001:db8::/48", "2001:db8::/64",
		"2001:db8::/96", "2001:db8::/112", "2001:db8::/128",
		"2001:db8::1/128", "2001:db8:0:1::/64",
	), nil)
}

// TestMapped4In6 checks that ::ffff:10.1.2.3 hits the IPv4 index
func TestMapped4In6(t *testing.T) {
	entries := entriesOf("10.0.0.0/8")
	index, values := buildIndex(t, entries)
	id := index.Lookup(netip.MustParseAddr("::ffff:10.1.2.3"))
	if values[id] != 1 {
		t.Fatalf("mapped address should reach the IPv4 index, got id %d", id)
	}
}

// TestDuplicatePrefixShareID pins that Add of the same masked prefix reuses the id
func TestDuplicatePrefixShareID(t *testing.T) {
	builder := NewBuilder()
	first, err := builder.Add(netip.MustParsePrefix("10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := builder.Add(netip.MustParsePrefix("10.1.2.3/8"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("the same masked prefix got ids %d and %d", first, second)
	}
	if builder.Routes() != 1 {
		t.Fatalf("Routes = %d, want 1", builder.Routes())
	}
}

// TestBadPrefixes rejects the zero prefix and a zoned one
func TestBadPrefixes(t *testing.T) {
	builder := NewBuilder()
	if _, err := builder.Add(netip.Prefix{}); err != ErrBadPrefix {
		t.Fatalf("invalid prefix: %v", err)
	}
	if zoned, err := netip.ParsePrefix("fe80::1%eth0/64"); err == nil {
		if _, err := builder.Add(zoned); err != ErrBadPrefix {
			t.Fatalf("zoned prefix: %v", err)
		}
	}
}

// randomEntries generates a BGP-shaped mixture with realistic length weights,
// including the rare short prefixes that create deep nesting
func randomEntries(n int, v6mix float64, seed int64) []Entry[uint32] {
	v4Lengths := []int{16, 17, 18, 19, 20, 21, 22, 22, 23, 24, 24, 24, 24, 25, 28, 32}
	v6Lengths := []int{29, 32, 32, 32, 36, 40, 44, 47, 48, 48, 48, 56, 64, 96, 128}
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
				Value:  uint32(len(out) + 1),
			})
			continue
		}
		b := [4]byte{byte(1 + rng.Intn(222)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		length := v4Lengths[rng.Intn(len(v4Lengths))]
		out = append(out, Entry[uint32]{
			Prefix: netip.PrefixFrom(netip.AddrFrom4(b), length).Masked(),
			Value:  uint32(len(out) + 1),
		})
	}
	return out
}

// clusteredEntries reproduces the shape of the benchmark's synthetic fixture:
// every IPv4 prefix inside 10/8 and every IPv6 prefix inside 2001:db8::/32,
// which is what forces the second cut to be chosen adaptively
func clusteredEntries(n int) []Entry[uint32] {
	out := make([]Entry[uint32], 0, n+2)
	out = append(out,
		Entry[uint32]{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		Entry[uint32]{Prefix: netip.MustParsePrefix("::/0"), Value: 2})
	for i := 0; i < n; i++ {
		if i&7 == 0 {
			a := [16]byte{0x20, 1, 0xd, 0xb8, byte(i >> 16), byte(i >> 8), byte(i)}
			out = append(out, Entry[uint32]{
				Prefix: netip.PrefixFrom(netip.AddrFrom16(a), 32+i%97).Masked(),
				Value:  uint32(i + 3)})
			continue
		}
		a := [4]byte{10, byte(i >> 12), byte(i >> 4), byte(i << 4)}
		out = append(out, Entry[uint32]{
			Prefix: netip.PrefixFrom(netip.AddrFrom4(a), 8+i%25).Masked(),
			Value:  uint32(i + 3)})
	}
	return out
}

// TestAgainstNaiveRandom throws random BGP-shaped tables at the index and
// compares every probe plus 400 extra random addrs against the linear scan
func TestAgainstNaiveRandom(t *testing.T) {
	for _, size := range []int{1, 2, 13, 200, 3000} {
		for _, mix := range []float64{0, 0.15, 1} {
			name := fmt.Sprintf("size=%d/v6mix=%g", size, mix)
			t.Run(name, func(t *testing.T) {
				entries := randomEntries(size, mix, int64(size)*31+int64(mix*7))
				rng := rand.New(rand.NewSource(int64(size) + 5))
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
				checkIndex(t, name, entries, extra)
			})
		}
	}
}

// TestAgainstNaiveClustered hits the synthetic clustered shape at a few sizes
func TestAgainstNaiveClustered(t *testing.T) {
	for _, size := range []int{50, 500, 5000} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			entries := clusteredEntries(size)
			checkIndex(t, "clustered", entries, nil)
		})
	}
}

// TestScanAndSearchAgree forces both the linear-walk and the binary-search
// branches over the same data
func TestScanAndSearchAgree(t *testing.T) {
	entries := clusteredEntries(4000)
	index, values := buildIndex(t, entries)
	for _, addr := range probeAddrs(entries) {
		wantValue, wantOK := naiveLookup(entries, addr)
		id := index.Lookup(addr)
		if (id != 0) != wantOK || (wantOK && values[id] != wantValue) {
			t.Fatalf("Lookup(%v) = id %d value %d, want %d (ok=%v)",
				addr, id, values[id], wantValue, wantOK)
		}
	}
	v4, v6 := index.Steps()
	if v4 == 0 || v6 == 0 {
		t.Fatalf("expected steps in both families, got %d and %d", v4, v6)
	}
}

// TestTableValueUpdateKeepsIndex pins that a value-only Insert reuses the index
func TestTableValueUpdateKeepsIndex(t *testing.T) {
	entries := []Entry[uint32]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/16"), Value: 2},
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Value: 3},
	}
	table, err := New(entries)
	if err != nil {
		t.Fatal(err)
	}
	before := table.Index()

	// update the /8, whose network address resolves to the /24. A naive
	// prefix-to-id recovery would write this value onto the /24
	if err := table.Insert(netip.MustParsePrefix("10.0.0.0/8"), 99); err != nil {
		t.Fatal(err)
	}
	if table.Index() != before {
		t.Fatal("a value-only update must reuse the index")
	}
	for _, c := range []struct {
		addr string
		want uint32
	}{
		{"10.0.0.1", 3},  // /24 unchanged
		{"10.0.1.1", 2},  // /16 unchanged
		{"10.1.1.1", 99}, // /8 updated
	} {
		got, ok := table.Lookup(netip.MustParseAddr(c.addr))
		if !ok || got != c.want {
			t.Fatalf("Lookup(%s) = %d,%v want %d", c.addr, got, ok, c.want)
		}
	}
}

// TestTableMutations randomly inserts and deletes against a live Table and
// checks Lookup against a naive scan of the live set, every 23 steps
func TestTableMutations(t *testing.T) {
	table, err := New[uint32](nil)
	if err != nil {
		t.Fatal(err)
	}
	live := map[netip.Prefix]uint32{}
	candidates := randomEntries(300, 0.25, 77)

	rng := rand.New(rand.NewSource(4))
	for step := 0; step < 1500; step++ {
		candidate := candidates[rng.Intn(len(candidates))]
		prefix := candidate.Prefix.Masked()
		switch rng.Intn(4) {
		case 0:
			wasPresent := false
			if _, ok := live[prefix]; ok {
				wasPresent = true
			}
			if got := table.Delete(prefix); got != wasPresent {
				t.Fatalf("step %d: Delete(%v) = %v want %v", step, prefix, got, wasPresent)
			}
			delete(live, prefix)
		default:
			value := uint32(rng.Intn(1 << 20))
			if err := table.Insert(prefix, value); err != nil {
				t.Fatal(err)
			}
			live[prefix] = value
		}
		if step%23 != 0 {
			continue
		}
		entries := make([]Entry[uint32], 0, len(live))
		for p, v := range live {
			entries = append(entries, Entry[uint32]{Prefix: p, Value: v})
		}
		for _, addr := range probeAddrs(entries) {
			wantValue, wantOK := naiveLookup(entries, addr)
			gotValue, gotOK := table.Lookup(addr)
			if gotOK != wantOK || (wantOK && gotValue != wantValue) {
				t.Fatalf("step %d: Lookup(%v) = %d,%v want %d,%v (live=%d)",
					step, addr, gotValue, gotOK, wantValue, wantOK, len(live))
			}
		}
	}
}
