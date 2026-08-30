package tests_test

import (
	"math/rand"
	"testing"

	"github.com/iqhive/prefixlookup/old/coverartset"
	"github.com/iqhive/prefixlookup/old/latticeartset"
)

// TestARTSet2MatchesARTSet drives latticeartset (the old reference) and
// coverartset through the same random insert/delete stream and checks both
// against the oracle on Contains
//
// we insert 4k mixed-family prefixes, probe 12k addrs, delete a random half
// (that's the coverBits rebuild path), probe again, then compare Size - if
// the lite set's classifier is stale after delete we'll cop it here
func TestARTSet2MatchesARTSet(t *testing.T) {
	rng := rand.New(rand.NewSource(2024))
	base, lite, want := latticeartset.New(), coverartset.New(), newOracle()
	for i := 0; i < 4000; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		base.Insert(prefix)
		lite.Insert(prefix)
		want.insert(prefix, i)
	}
	for i := 0; i < 12000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		wantOK := func() bool { _, ok := want.lookup(addr); return ok }()
		if base.Contains(addr) != wantOK || lite.Contains(addr) != wantOK {
			t.Fatalf("Contains(%v): base=%v lite=%v want=%v", addr, base.Contains(addr), lite.Contains(addr), wantOK)
		}
	}
	// delete half and re-verify - this is the coverBits rebuild on delete
	prefixes := sortedPrefixes(want.values)
	for i := 0; i < len(prefixes)/2; i++ {
		prefix := prefixes[rng.Intn(len(prefixes))]
		baseDel := base.Delete(prefix)
		liteDel := lite.Delete(prefix)
		wantDel := want.delete(prefix)
		if baseDel != liteDel || baseDel != wantDel {
			t.Fatalf("Delete(%v) disagreed: base=%v lite=%v want=%v", prefix, baseDel, liteDel, wantDel)
		}
	}
	for i := 0; i < 12000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		wantOK := func() bool { _, ok := want.lookup(addr); return ok }()
		if base.Contains(addr) != wantOK || lite.Contains(addr) != wantOK {
			t.Fatalf("after delete Contains(%v): base=%v lite=%v want=%v", addr, base.Contains(addr), lite.Contains(addr), wantOK)
		}
	}
	if base.Size() != lite.Size() || lite.Size() != len(want.values) {
		t.Fatalf("size base=%d lite=%d want=%d", base.Size(), lite.Size(), len(want.values))
	}
}

// TestRangeMatchLite2MatchesRangeMatch used to compile identical prefix sets
// through rangematch and rangematchlite2 and assert Match agreement - parked
// because lite2 isn't in the live matrix; left here so we remember the shape
// if we revive it
//
// func TestRangeMatchLite2MatchesRangeMatch(t *testing.T) {
// 	rng := rand.New(rand.NewSource(2025))
// 	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
// 	want := newOracle()
// 	want.insert(prefixes[0], 1)
// 	want.insert(prefixes[1], 1)
// 	for i := 0; i < 3000; i++ {
// 		prefix := randPrefix(rng, i%2 == 0)
// 		prefixes = append(prefixes, prefix)
// 		want.insert(prefix, i)
// 	}
// 	base, err := rangematch.New(prefixes)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	lite, err := rangematchlite2.New(prefixes)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if base.Ranges() != lite.Ranges() {
// 		t.Fatalf("Ranges() base=%d lite=%d", base.Ranges(), lite.Ranges())
// 	}
// 	for i := 0; i < 20000; i++ {
// 		addr := randPrefix(rng, i%2 == 0).Addr()
// 		_, wantOK := want.lookup(addr)
// 		if base.Match(addr) != wantOK || lite.Match(addr) != wantOK {
// 			t.Fatalf("Match(%v): base=%v lite=%v want=%v", addr, base.Match(addr), lite.Match(addr), wantOK)
// 		}
// 	}
// }
