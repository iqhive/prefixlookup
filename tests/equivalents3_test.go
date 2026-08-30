package tests_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/old/arenaartset"
	"github.com/iqhive/prefixlookup/old/latticeartset"
	"github.com/iqhive/prefixlookup/old/rangeset"
	"github.com/iqhive/prefixlookup/rangematch"
)

// TestARTSet3MatchesARTSet is the arenaartset vs latticeartset agreement
// test - same random insert/delete stream, oracle on Contains, plus a bulk
// Load into a fresh arena set so we don't only check the incremental path
//
// we insert 4k, probe, Load the same slice into a new set and probe that,
// then delete a random half (coverage rebuild + deferred classifier) and
// probe again
func TestARTSet3MatchesARTSet(t *testing.T) {
	rng := rand.New(rand.NewSource(3030))
	base, lite, want := latticeartset.New(), arenaartset.New(), newOracle()
	var inserted []netip.Prefix
	for i := 0; i < 4000; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		base.Insert(prefix)
		lite.Insert(prefix)
		want.insert(prefix, i)
		inserted = append(inserted, prefix)
	}
	probe := func(stage string) {
		t.Helper()
		for i := 0; i < 12000; i++ {
			addr := randPrefix(rng, i%2 == 0).Addr()
			_, wantOK := want.lookup(addr)
			if base.Contains(addr) != wantOK || lite.Contains(addr) != wantOK {
				t.Fatalf("%s: Contains(%v): base=%v lite=%v want=%v", stage, addr, base.Contains(addr), lite.Contains(addr), wantOK)
			}
		}
	}
	probe("after inserts")

	// bulk Load into a fresh set has to match the incremental result
	bulk := arenaartset.New()
	bulk.Load(inserted)
	if bulk.Size() != lite.Size() {
		t.Fatalf("Load size=%d, incremental=%d", bulk.Size(), lite.Size())
	}
	for i := 0; i < 12000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		if bulk.Contains(addr) != lite.Contains(addr) {
			t.Fatalf("Load Contains(%v): bulk=%v incremental=%v", addr, bulk.Contains(addr), lite.Contains(addr))
		}
	}

	// delete half - coverage rebuild and the deferred classifier rebuild
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
	probe("after deletes")
	if base.Size() != lite.Size() || lite.Size() != len(want.values) {
		t.Fatalf("size base=%d lite=%d want=%d", base.Size(), lite.Size(), len(want.values))
	}
}

// TestRangeMatchLite3MatchesRangeMatch compiles the same prefix bag through
// rangematch and rangeset (the lite3 encoding) and checks Match plus Ranges()
//
// defaults go in first so the whole-space range is present, then 3k randoms,
// then 20k probes - if the boundary list length diverges the encodings aren't
// even talking about the same intervals
func TestRangeMatchLite3MatchesRangeMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(3031))
	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	want := newOracle()
	want.insert(prefixes[0], 1)
	want.insert(prefixes[1], 1)
	for i := 0; i < 3000; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		prefixes = append(prefixes, prefix)
		want.insert(prefix, i)
	}
	base, err := rangematch.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := rangeset.New(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	if base.Ranges() != lite.Ranges() {
		t.Fatalf("Ranges() base=%d lite=%d", base.Ranges(), lite.Ranges())
	}
	for i := 0; i < 20000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		_, wantOK := want.lookup(addr)
		if base.Match(addr) != wantOK || lite.Match(addr) != wantOK {
			t.Fatalf("Match(%v): base=%v lite=%v want=%v", addr, base.Match(addr), lite.Match(addr), wantOK)
		}
	}
}
