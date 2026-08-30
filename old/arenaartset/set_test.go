package arenaartset

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	artset "github.com/iqhive/prefixlookup/old/latticeartset"
)

// prefix is a test helper that panics on a bad CIDR string
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr is a test helper that panics on a bad address string
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestSetMembershipAndEnumeration is the smoke test: insert, Contains,
// All, Delete. Same shape as latticeartset so we can eyeball divergence
func TestSetMembershipAndEnumeration(t *testing.T) {
	set := New()
	for _, p := range []string{"10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"} {
		set.Insert(prefix(p))
	}
	for _, a := range []string{"10.255.0.1", "192.168.1.99", "2001:db8::7"} {
		if !set.Contains(addr(a)) {
			t.Errorf("Contains(%s) = false", a)
		}
	}
	for _, a := range []string{"11.0.0.1", "192.168.2.1", "2001:db9::1"} {
		if set.Contains(addr(a)) {
			t.Errorf("Contains(%s) = true", a)
		}
	}
	seen := map[netip.Prefix]bool{}
	set.All(func(p netip.Prefix) bool { seen[p] = true; return true })
	if len(seen) != 3 {
		t.Fatalf("All returned %d prefixes", len(seen))
	}
	if !set.Delete(prefix("10.0.0.0/8")) || set.Contains(addr("10.1.1.1")) {
		t.Fatal("set deletion failed")
	}
}

// randPrefix returns a random prefix drawn from both families, including
// default routes and IPv4-in-IPv6 spellings. Weighted so we actually hit
// the awkward cases rather than a uniform /32 soup
func randPrefix(rng *rand.Rand) netip.Prefix {
	switch rng.Intn(10) {
	case 0:
		return netip.MustParsePrefix("0.0.0.0/0")
	case 1:
		return netip.MustParsePrefix("::/0")
	}
	if rng.Intn(4) == 0 {
		// IPv4-in-IPv6 spelling; FromPrefix unmasks bits >= 96 to the
		// embedded v4 form, exercising both spellings of the same key
		var b [16]byte
		copy(b[10:], []byte{0xff, 0xff})
		b[12] = byte(rng.Intn(256))
		b[13] = byte(rng.Intn(256))
		b[14] = byte(rng.Intn(256))
		b[15] = byte(rng.Intn(256))
		return netip.PrefixFrom(netip.AddrFrom16(b), 96+rng.Intn(33))
	}
	if rng.Intn(2) == 0 {
		b := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		return netip.PrefixFrom(netip.AddrFrom4(b), rng.Intn(33))
	}
	var b [16]byte
	b[0] = 0x20
	b[1] = byte(rng.Intn(256))
	for i := 2; i < len(b); i++ {
		b[i] = byte(rng.Intn(256))
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), rng.Intn(129))
}

// randAddr returns a probe address: sometimes inside a stored prefix,
// sometimes anywhere in the address space. The "inside" path is how we
// actually exercise hits
func randAddr(rng *rand.Rand, live []netip.Prefix) netip.Addr {
	if len(live) > 0 && rng.Intn(2) == 0 {
		p := live[rng.Intn(len(live))]
		a := p.Addr()
		bits := p.Bits()
		if a.Is4() {
			v := uint32(a.As4()[0])<<24 | uint32(a.As4()[1])<<16 | uint32(a.As4()[2])<<8 | uint32(a.As4()[3])
			if bits < 32 {
				v |= rng.Uint32() & (^uint32(0) >> uint(bits))
			}
			return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		}
		b := a.As16()
		for i := bits; i < 128; i++ {
			if rng.Intn(2) == 1 {
				b[i/8] |= 1 << (7 - uint(i%8))
			}
		}
		return netip.AddrFrom16(b)
	}
	if rng.Intn(8) == 0 {
		return netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
			byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
	if rng.Intn(2) == 0 {
		return netip.AddrFrom4([4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
	var b [16]byte
	b[0] = 0x20
	for i := 1; i < len(b); i++ {
		b[i] = byte(rng.Intn(256))
	}
	return netip.AddrFrom16(b)
}

// collectAll dumps every stored prefix into a set via All. Used to compare
// against the latticeartset reference
func collectAll(s *Set) map[netip.Prefix]bool {
	seen := map[netip.Prefix]bool{}
	s.All(func(p netip.Prefix) bool { seen[p] = true; return true })
	return seen
}

// TestDifferentialAgainstArtSet is the reason we kept latticeartset: random
// insert/delete against the pointer set, probe Contains, periodically
// compare All. Seed 42 so a failure is reproducible
func TestDifferentialAgainstArtSet(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	ref := artset.New()
	set := New()
	var live []netip.Prefix
	// probe samples Contains against the reference; we don't do it every op
	probe := func(op int) {
		for i := 0; i < 40; i++ {
			a := randAddr(rng, live)
			if got, want := set.Contains(a), ref.Contains(a); got != want {
				t.Fatalf("op %d: Contains(%s) = %v, artset says %v", op, a, got, want)
			}
		}
	}
	for op := 0; op < 30000; op++ {
		p := randPrefix(rng)
		switch rng.Intn(5) {
		case 0, 1, 2:
			got, want := set.Insert(p), ref.Insert(p)
			if got != want {
				t.Fatalf("op %d: Insert(%s) = %v, artset says %v", op, p, got, want)
			}
			if got {
				live = append(live, p)
			}
		default:
			var target netip.Prefix
			if len(live) > 0 {
				i := rng.Intn(len(live))
				target = live[i]
				live = append(live[:i], live[i+1:]...)
			} else {
				target = p
			}
			if got, want := set.Delete(target), ref.Delete(target); got != want {
				t.Fatalf("op %d: Delete(%s) = %v, artset says %v", op, target, got, want)
			}
		}
		if op%97 == 0 {
			probe(op)
		}
		if op%1000 == 0 {
			got, want := collectAll(set), collectAll2(ref)
			if len(got) != len(want) {
				t.Fatalf("op %d: All returned %d prefixes, artset has %d", op, len(got), len(want))
			}
			for p := range got {
				if !want[p] {
					t.Fatalf("op %d: All returned %s, which artset does not store", op, p)
				}
			}
			if set.Size() != len(got) {
				t.Fatalf("op %d: Size %d, All %d", op, set.Size(), len(got))
			}
		}
	}
	probe(-1)
}

// collectAll2 is collectAll for the latticeartset reference
func collectAll2(s *artset.Set) map[netip.Prefix]bool {
	seen := map[netip.Prefix]bool{}
	s.All(func(p netip.Prefix) bool { seen[p] = true; return true })
	return seen
}

// TestLoadMatchesIncrementalInsert checks bulk Load against one-at-a-time
// insert on the reference, then Load again shuffled to make sure
// duplicates are idempotent
func TestLoadMatchesIncrementalInsert(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	prefixes := make([]netip.Prefix, 5000)
	for i := range prefixes {
		prefixes[i] = randPrefix(rng)
	}
	ref := artset.New()
	for _, p := range prefixes {
		ref.Insert(p)
	}
	bulk := New()
	bulk.Load(prefixes)
	// load again with a shuffled copy: duplicate handling must be idempotent
	shuffled := make([]netip.Prefix, len(prefixes))
	copy(shuffled, prefixes)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	bulk.Load(shuffled)

	if bulk.Size() != ref.Size() {
		t.Fatalf("Size %d, artset %d", bulk.Size(), ref.Size())
	}
	got, want := collectAll(bulk), collectAll2(ref)
	for p := range want {
		if !got[p] {
			t.Fatalf("Load lost prefix %s", p)
		}
	}
	for i := 0; i < 2000; i++ {
		a := randAddr(rng, prefixes)
		if bulk.Contains(a) != ref.Contains(a) {
			t.Fatalf("Contains(%s) diverges after Load", a)
		}
	}
}

// TestDeleteUntilEmptyThenReinsert drains the set completely then fills it
// again, so we exercise the free-list and an empty classifier. Dedup on
// the normalised key because mapped/unmapped spellings are the same slot
func TestDeleteUntilEmptyThenReinsert(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var prefixes []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for len(prefixes) < 300 {
		p := randPrefix(rng)
		// dedup on the normalised key: distinct spellings (mapped and
		// unmapped, unmasked host bits) denote the same stored prefix, and
		// only one Delete can succeed per key
		pk, ok := addrkey.FromPrefix(p)
		if !ok || seen[pk.Prefix()] {
			continue
		}
		seen[pk.Prefix()] = true
		prefixes = append(prefixes, pk.Prefix())
	}
	set := New()
	for _, p := range prefixes {
		set.Insert(p)
	}
	rng.Shuffle(len(prefixes), func(i, j int) { prefixes[i], prefixes[j] = prefixes[j], prefixes[i] })
	for _, p := range prefixes {
		if !set.Delete(p) {
			t.Fatalf("Delete(%s) = false", p)
		}
	}
	if set.Size() != 0 {
		t.Fatalf("Size after deleting everything = %d", set.Size())
	}
	if set.Contains(addr("10.0.0.1")) || set.Contains(addr("2001:db8::1")) {
		t.Fatal("empty set matched an address")
	}
	if got := collectAll(set); len(got) != 0 {
		t.Fatalf("All returned %d prefixes from an empty set", len(got))
	}
	for _, p := range prefixes {
		if !set.Insert(p) {
			t.Fatalf("re-Insert(%s) = false", p)
		}
	}
	if set.Size() != len(prefixes) {
		t.Fatalf("Size after reinsert = %d, want %d", set.Size(), len(prefixes))
	}
}
