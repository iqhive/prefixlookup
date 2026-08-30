package flatart

import (
	"math/rand"
	"net/netip"
	"testing"
)

// oracle is a brute-force longest-prefix matcher used to validate the index
type oracle struct {
	prefixes []netip.Prefix
	refs     []uint32
}

// add records a prefix, replacing the ref if we've already got it
func (o *oracle) add(prefix netip.Prefix, ref uint32) {
	prefix = prefix.Masked()
	for i, have := range o.prefixes {
		if have == prefix {
			o.refs[i] = ref
			return
		}
	}
	o.prefixes = append(o.prefixes, prefix)
	o.refs = append(o.refs, ref)
}

// lookup is the linear-scan LPM, skipping the other family
func (o *oracle) lookup(addr netip.Addr) uint32 {
	best, bestBits := uint32(0), -1
	for i, prefix := range o.prefixes {
		if prefix.Addr().Is4() != (addr.Is4() || addr.Is4In6()) {
			continue
		}
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best, bestBits = o.refs[i], prefix.Bits()
		}
	}
	return best
}

// exact is a linear scan for an exact prefix
func (o *oracle) exact(prefix netip.Prefix) uint32 {
	prefix = prefix.Masked()
	for i, have := range o.prefixes {
		if have == prefix {
			return o.refs[i]
		}
	}
	return 0
}

// probe resolves an index result back to the caller reference it stands
// for, so results can be compared against the oracle
type probe struct {
	ix    *Index
	refOf []uint32
}

// lookup is Lookup then through refOf
func (p probe) lookup(addr netip.Addr) uint32 { return p.refOf[p.ix.Lookup(addr)] }

// exact is Exact then through refOf
func (p probe) exact(prefix netip.Prefix) uint32 {
	return p.refOf[p.ix.Exact(prefix)]
}

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

// randomAddr is an unmasked random address of the requested family
func randomAddr(rng *rand.Rand, v6 bool) netip.Addr {
	if v6 {
		var b [16]byte
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
		return netip.AddrFrom16(b)
	}
	var b [4]byte
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return netip.AddrFrom4(b)
}

// buildRandom returns an index plus the oracle it should agree with
// seeding the default routes on even seeds exercises the inherited-default
// path on every node in the table
func buildRandom(t *testing.T, size int, seed int64) (probe, *oracle, *rand.Rand) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed*1000 + int64(size)))
	o := new(oracle)
	b := NewBuilder(Options{Exact: true})
	if seed%2 == 0 {
		b.Insert(netip.MustParsePrefix("0.0.0.0/0"), 1)
		o.add(netip.MustParsePrefix("0.0.0.0/0"), 1)
		b.Insert(netip.MustParsePrefix("::/0"), 2)
		o.add(netip.MustParsePrefix("::/0"), 2)
	}
	for i := 0; i < size; i++ {
		prefix := randomPrefix(rng, i%4 == 0)
		ref := uint32(i + 3)
		if !b.Insert(prefix, ref) {
			t.Fatalf("insert %v rejected", prefix)
		}
		o.add(prefix, ref)
	}
	ix, refOf, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(refOf) != ix.Values() {
		t.Fatalf("refOf has %d entries, Values reports %d", len(refOf), ix.Values())
	}
	return probe{ix: ix, refOf: refOf}, o, rng
}

// TestLookupMatchesOracle throws random tables at Lookup/Exact/Contains
// and checks them against a linear scan
func TestLookupMatchesOracle(t *testing.T) {
	for _, size := range []int{1, 2, 7, 64, 512, 4000} {
		for seed := int64(1); seed <= 4; seed++ {
			p, o, rng := buildRandom(t, size, seed)
			for i := 0; i < 3000; i++ {
				addr := randomAddr(rng, i%4 == 0)
				if i%3 == 0 && len(o.prefixes) != 0 {
					addr = o.prefixes[rng.Intn(len(o.prefixes))].Addr()
				}
				got, want := p.lookup(addr), o.lookup(addr)
				if got != want {
					t.Fatalf("size=%d seed=%d Lookup(%v) = %d, want %d", size, seed, addr, got, want)
				}
				if gotOK, wantOK := p.ix.Contains(addr), want != 0; gotOK != wantOK {
					t.Fatalf("size=%d seed=%d Contains(%v) = %v, want %v", size, seed, addr, gotOK, wantOK)
				}
			}
			for _, prefix := range o.prefixes {
				if got, want := p.exact(prefix), o.exact(prefix); got != want {
					t.Fatalf("size=%d seed=%d Exact(%v) = %d, want %d", size, seed, prefix, got, want)
				}
			}
			for i := 0; i < 500; i++ {
				prefix := randomPrefix(rng, i%4 == 0)
				if got, want := p.exact(prefix), o.exact(prefix); got != want {
					t.Fatalf("size=%d seed=%d Exact(%v) = %d, want %d", size, seed, prefix, got, want)
				}
			}
		}
	}
}

// TestAllRoundTrips confirms enumeration recovers exactly the stored set,
// which is what a managed table relies on to rebuild without retaining a
// catalogue
func TestAllRoundTrips(t *testing.T) {
	for seed := int64(1); seed <= 6; seed++ {
		p, o, _ := buildRandom(t, 1500, seed)
		seen := make(map[netip.Prefix]uint32, len(o.prefixes))
		p.ix.All(func(prefix netip.Prefix, value uint32) bool {
			if _, dup := seen[prefix]; dup {
				t.Fatalf("seed=%d %v enumerated twice", seed, prefix)
			}
			seen[prefix] = p.refOf[value]
			return true
		})
		if len(seen) != len(o.prefixes) {
			t.Fatalf("seed=%d enumerated %d prefixes, want %d", seed, len(seen), len(o.prefixes))
		}
		for i, prefix := range o.prefixes {
			if got, ok := seen[prefix]; !ok || got != o.refs[i] {
				t.Fatalf("seed=%d %v enumerated as (%d,%v), want %d", seed, prefix, got, ok, o.refs[i])
			}
		}
	}
}

// TestEmptyFamilies confirms a family with no prefixes answers without a
// root array of its own - it should share emptyRootHi/Lo
func TestEmptyFamilies(t *testing.T) {
	b := NewBuilder(Options{Exact: true})
	b.Insert(netip.MustParsePrefix("10.0.0.0/8"), 5)
	ix, refOf, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := ix.Lookup(netip.MustParseAddr("2001:db8::1")); got != 0 {
		t.Fatalf("v6 lookup on v4-only table = %d, want 0", got)
	}
	if got := refOf[ix.Lookup(netip.MustParseAddr("10.1.2.3"))]; got != 5 {
		t.Fatalf("v4 lookup = %d, want 5", got)
	}
	if got := refOf[ix.Exact(netip.MustParsePrefix("10.0.0.0/8"))]; got != 5 {
		t.Fatalf("exact = %d, want 5", got)
	}
}

// TestNodeLayout pins the invariants the descent depends on: the descent
// state for a stride is one cache line, a group is a quarter of it, and
// the resolution set sits in the adjacent line
func TestNodeLayout(t *testing.T) {
	if got := unsafeSizeofNode(); got != 128 {
		t.Fatalf("node size = %d bytes, want 128", got)
	}
	if got := unsafeSizeofGroup(); got != 16 {
		t.Fatalf("group size = %d bytes, want 16", got)
	}
	if got := unsafeOffsetOfHost(); got != 64 {
		t.Fatalf("host set offset = %d bytes, want 64", got)
	}
	if got := unsafeSizeofStop(); got != 80 {
		t.Fatalf("stop size = %d bytes, want 80", got)
	}
}
