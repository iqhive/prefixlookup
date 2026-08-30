package tests_test

import (
	"math/rand"
	"net/netip"
	"testing"

	legacy "github.com/iqhive/nradix"
	"github.com/iqhive/prefixlookup/artlpm"
	"github.com/iqhive/prefixlookup/old/artwalk"
)

// TestExternalLegacyConsistency keeps the "we still match nradix" intent
// without dragging LegacyAdapter back from the dead - we insert 1800 random
// prefixes into the old tree, artlpm, and artwalk, probe 8k lookups, delete
// 400, then probe again
//
// legacy uses SetCIDRNetIPPrefix / FindCIDRNetIPAddr so a nil find is a miss;
// we treat that as the oracle and fail if current or RIB disagree
func TestExternalLegacyConsistency(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	tree := legacy.NewTree(0)
	table := artlpm.New[int]()
	rib := artwalk.New[int]()
	inserted := make([]netip.Prefix, 0, 1800)
	for i := 0; i < 1800; i++ {
		prefix := randPrefix(rng, i%2 == 0)
		if err := tree.SetCIDRNetIPPrefix(prefix, i+1, true); err != nil {
			t.Fatalf("legacy insert %v: %v", prefix, err)
		}
		table.Insert(prefix, i+1)
		rib.Insert(prefix, i+1)
		inserted = append(inserted, prefix)
	}
	for i := 0; i < 8000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		legacyValue, err := tree.FindCIDRNetIPAddr(addr)
		if err != nil {
			t.Fatalf("legacy lookup %v: %v", addr, err)
		}
		got, ok := table.Lookup(addr)
		if legacyValue == nil {
			if ok {
				t.Fatalf("current hit %v = %d, legacy miss", addr, got)
			}
		} else if !ok || got != legacyValue.(int) {
			t.Fatalf("lookup %v current=(%d,%v), legacy=%v", addr, got, ok, legacyValue)
		}
		if ribValue, ribOK := rib.Lookup(addr); ribOK != ok || ribOK && ribValue != got {
			t.Fatalf("RIB lookup %v disagreed", addr)
		}
	}
	for i := 0; i < 400; i++ {
		prefix := inserted[rng.Intn(len(inserted))]
		legacyErr := tree.DeleteCIDRNetIPAddr(prefix.Addr(), prefix)
		currentDeleted := table.Delete(prefix)
		ribDeleted := rib.Delete(prefix)
		if (legacyErr == nil) != currentDeleted || currentDeleted != ribDeleted {
			t.Fatalf("delete %v legacy=%v current=%v rib=%v", prefix, legacyErr, currentDeleted, ribDeleted)
		}
	}
	for i := 0; i < 5000; i++ {
		addr := randPrefix(rng, i%2 == 0).Addr()
		legacyValue, _ := tree.FindCIDRNetIPAddr(addr)
		got, ok := table.Lookup(addr)
		if legacyValue == nil && ok || legacyValue != nil && (!ok || got != legacyValue.(int)) {
			t.Fatalf("post-delete lookup %v current=(%d,%v), legacy=%v", addr, got, ok, legacyValue)
		}
	}
}

// TestCurrentDuplicateAndWalkContracts is the insert-overwrite + All() walk
// check we used to hang off LegacyAdapter - first Insert of 10/8 must report
// new, second must report overwrite, lookup must see 2, then we walk a tiny
// mixed v4/v6 table and count families
func TestCurrentDuplicateAndWalkContracts(t *testing.T) {
	table := artlpm.New[int]()
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if !table.Insert(prefix, 1) || table.Insert(prefix, 2) {
		t.Fatal("Insert new/overwrite contract failed")
	}
	if value, _ := table.Lookup(netip.MustParseAddr("10.1.1.1")); value != 2 {
		t.Fatalf("overwrite = %d", value)
	}
	table.Insert(netip.MustParsePrefix("192.168.0.0/16"), 3)
	table.Insert(netip.MustParsePrefix("2001:db8::/32"), 4)
	v4, v6 := 0, 0
	table.All(func(prefix netip.Prefix, _ int) bool {
		if prefix.Addr().Is4() {
			v4++
		} else {
			v6++
		}
		return true
	})
	if v4 != 2 || v6 != 1 {
		t.Fatalf("walk counts = v4:%d v6:%d", v4, v6)
	}
}
