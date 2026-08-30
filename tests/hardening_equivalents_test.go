package tests_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/artlpm"
	"github.com/iqhive/prefixlookup/old/arenaartlpm"
	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/old/latticeartset"
	"github.com/iqhive/prefixlookup/versioned"
)

// these source-named tests keep every public nradix hardening test visible -
// broader matrices live in the centralised checks, focused contracts stay
// here under their original intent names so a skipped nradix analogue shows
// up in review

// TestTableAgainstOracle is the nradix-named alias for the mutable matrix -
// we just call through so the old name still fails in CI if the impl drifts
func TestTableAgainstOracle(t *testing.T) {
	TestMutableTablesAgainstOracle(t)
}

// TestTableGetAndAll fills artlpm from a 1000-prefix oracle and checks Get
// plus All against the map - this is the exact-match / enumeration contract
// the nradix suite used to own
func TestTableGetAndAll(t *testing.T) {
	table := artlpm.New[int]()
	want := randomOracle(7, 1000)
	for prefix, value := range want.values {
		table.Insert(prefix, value)
	}
	got := make(map[netip.Prefix]int)
	table.All(func(prefix netip.Prefix, value int) bool {
		got[prefix] = value
		return true
	})
	if len(got) != len(want.values) {
		t.Fatalf("All returned %d prefixes, want %d", len(got), len(want.values))
	}
	for prefix, value := range want.values {
		if exact, ok := table.Get(prefix); !ok || exact != value || got[prefix] != value {
			t.Fatalf("Get/All(%v) = (%d,%v)/%d, want %d", prefix, exact, ok, got[prefix], value)
		}
	}
}

// TestTableMappedV4 keeps the nradix mapped-v4 name - behaviour lives in
// TestARTDefaultsMappedIPv4AndExact
func TestTableMappedV4(t *testing.T) {
	TestARTDefaultsMappedIPv4AndExact(t)
}

// TestTableDefaultRoutes is the nradix default-route name pointing at the
// same defaults+mapped cluster
func TestTableDefaultRoutes(t *testing.T) {
	TestARTDefaultsMappedIPv4AndExact(t)
}

// TestTableLookupPrefix is the nradix LookupPrefix name - same cluster,
// LookupPrefix is the interesting call
func TestTableLookupPrefix(t *testing.T) {
	TestARTDefaultsMappedIPv4AndExact(t)
}

// TestTableDeepIPv6 is the nradix deep-v6 name - calls TestARTDeepIPv6
func TestTableDeepIPv6(t *testing.T) {
	TestARTDeepIPv6(t)
}

// TestSetAgainstOracle is the nradix set-vs-oracle name - latticeartset
// coverage lives in TestSetAgainstOracleAndFrontTable
func TestSetAgainstOracle(t *testing.T) {
	TestSetAgainstOracleAndFrontTable(t)
}

// TestSetFrontTableCoverage plants three disjoint v4 prefixes and probes
// the last host of each (must hit) plus the next network (must miss) -
// that's the old "front table" edge coverage
func TestSetFrontTableCoverage(t *testing.T) {
	set := latticeartset.New()
	for _, prefix := range []string{"10.0.0.0/8", "172.16.0.0/16", "192.168.1.0/24"} {
		set.Insert(netip.MustParsePrefix(prefix))
	}
	for _, addr := range []string{"10.255.255.255", "172.16.255.255", "192.168.1.255"} {
		if !set.Contains(netip.MustParseAddr(addr)) {
			t.Fatalf("Contains(%s) = false", addr)
		}
	}
	for _, addr := range []string{"11.0.0.0", "172.17.0.0", "192.168.2.0"} {
		if set.Contains(netip.MustParseAddr(addr)) {
			t.Fatalf("Contains(%s) = true", addr)
		}
	}
}

// TestSetShortPrefixOverlapsDeeper is the "insert /24, then covering /8,
// then delete the /8" dance - a neighbour of the /24 must miss until the /8
// lands, then hit, then miss again after delete while the /24 itself still
// hits
func TestSetShortPrefixOverlapsDeeper(t *testing.T) {
	set := latticeartset.New()
	deeper := netip.MustParsePrefix("10.1.2.0/24")
	shorter := netip.MustParsePrefix("10.0.0.0/8")
	probe := netip.MustParseAddr("10.1.3.1")
	set.Insert(deeper)
	if set.Contains(probe) {
		t.Fatal("deeper prefix matched an adjacent address")
	}
	set.Insert(shorter)
	if !set.Contains(probe) {
		t.Fatal("short covering prefix did not supersede deeper descent")
	}
	set.Delete(shorter)
	if set.Contains(probe) || !set.Contains(netip.MustParseAddr("10.1.2.5")) {
		t.Fatal("deleting short prefix did not restore deeper-only coverage")
	}
}

// TestSetAll is the nradix enumeration name - All is already checked inside
// TestSetAgainstOracleAndFrontTable
func TestSetAll(t *testing.T) {
	TestSetAgainstOracleAndFrontTable(t)
}

// TestCompactAgainstOracle is the nradix compact-table name - arenaartlpm
// rides along in TestMutableTablesAgainstOracle
func TestCompactAgainstOracle(t *testing.T) {
	TestMutableTablesAgainstOracle(t)
}

// TestCompactWideFanout is the nradix wide-fanout name - 256 sibling /24s
// live in TestCompactRebuildAndWideFanout
func TestCompactWideFanout(t *testing.T) {
	TestCompactRebuildAndWideFanout(t)
}

// TestCompactAll enumerates arenaartlpm after a 1000-prefix fill - we don't
// fold this into the mutable matrix because All on the compact table is the
// thing that used to skip dead slots
func TestCompactAll(t *testing.T) {
	table := arenaartlpm.New[int]()
	want := randomOracle(77, 1000)
	for prefix, value := range want.values {
		table.Insert(prefix, value)
	}
	got := make(map[netip.Prefix]int)
	table.All(func(prefix netip.Prefix, value int) bool {
		got[prefix] = value
		return true
	})
	if len(got) != len(want.values) {
		t.Fatalf("All returned %d prefixes, want %d", len(got), len(want.values))
	}
	for prefix, value := range want.values {
		if got[prefix] != value {
			t.Fatalf("All[%v] = %d, want %d", prefix, got[prefix], value)
		}
	}
}

// TestRIBAgainstOracle loads a 1500-prefix oracle into artwalk and runs
// verifyLookup - nradix called this the RIB table check
func TestRIBAgainstOracle(t *testing.T) {
	rib := artwalk.New[int]()
	want := randomOracle(11, 1500)
	for prefix, value := range want.values {
		rib.Insert(prefix, value)
	}
	verifyLookup(t, "artwalk", rib, want, 12, 5000)
}

// TestRIBSupernets is the nradix supernets name - real walk lives in
// TestRIBTraversalAgainstOracle
func TestRIBSupernets(t *testing.T) {
	TestRIBTraversalAgainstOracle(t)
}

// TestRIBSubnets is the nradix subnets name - same traversal test
func TestRIBSubnets(t *testing.T) {
	TestRIBTraversalAgainstOracle(t)
}

// TestRIBParent is the nradix parent name - Parent of the /25 is in
// TestRIBTraversalAgainstOracle
func TestRIBParent(t *testing.T) {
	TestRIBTraversalAgainstOracle(t)
}

// TestRIBSupernetsChain checks longest-first order on 10.1.2.3 and that
// returning false from the callback actually stops after two hops
func TestRIBSupernetsChain(t *testing.T) {
	rib := artwalk.New[int]()
	for _, entry := range hierarchyEntries() {
		rib.Insert(entry.Prefix, entry.Value)
	}
	var got []int
	rib.Supernets(netip.MustParseAddr("10.1.2.3"), func(_ netip.Prefix, value int) bool {
		got = append(got, value)
		return true
	})
	want := []int{32, 24, 16, 8, 0}
	if !sameInts(got, want) {
		t.Fatalf("Supernets chain = %v, want %v", got, want)
	}
	count := 0
	rib.Supernets(netip.MustParseAddr("10.1.2.3"), func(netip.Prefix, int) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Fatalf("early stop yielded %d entries, want 2", count)
	}
}

// TestSnapshotModes is the nradix snapshot-mode name - FIB/RIB/Hybrid live
// in TestVersionedModesAndBatches
func TestSnapshotModes(t *testing.T) {
	TestVersionedModesAndBatches(t)
}

// TestSnapshotUpdateCoalescing is the "two Updates, delete+overwrite in the
// second" check - published size must be 1, 192.168.1.1 sees 1000, 10.5 is
// gone, and deleting an absent prefix inside the writer must return false
func TestSnapshotUpdateCoalescing(t *testing.T) {
	table := versioned.New[int](versioned.ModeHybrid)
	old := netip.MustParsePrefix("10.5.0.0/16")
	added := netip.MustParsePrefix("192.168.0.0/16")
	table.Update(func(writer *versioned.Writer[int]) {
		writer.Insert(old, 5)
	})
	table.Update(func(writer *versioned.Writer[int]) {
		writer.Insert(added, 999)
		if !writer.Delete(old) {
			t.Error("delete of existing prefix returned false")
		}
		if writer.Delete(netip.MustParsePrefix("172.31.0.0/16")) {
			t.Error("delete of absent prefix returned true")
		}
		writer.Insert(added, 1000)
	})
	if table.Size() != 1 {
		t.Fatalf("coalesced size = %d, want 1", table.Size())
	}
	if value, ok := table.Lookup(netip.MustParseAddr("192.168.1.1")); !ok || value != 1000 {
		t.Fatalf("coalesced overwrite = (%d,%v), want (1000,true)", value, ok)
	}
	if _, ok := table.Lookup(netip.MustParseAddr("10.5.0.1")); ok {
		t.Fatal("deleted prefix remained published")
	}
}

// TestSnapshotConcurrentReadersDuringWrites is the nradix concurrent-snapshot
// name - real goroutine test is TestVersionedConcurrentReadersAndWriters
func TestSnapshotConcurrentReadersDuringWrites(t *testing.T) {
	TestVersionedConcurrentReadersAndWriters(t)
}

// TestLegacyAdapterMatchesTree is the nradix adapter-vs-tree name - we now
// compare artlpm/artwalk to nradix directly in TestExternalLegacyConsistency
func TestLegacyAdapterMatchesTree(t *testing.T) {
	TestExternalLegacyConsistency(t)
}

// TestLegacyAdapterErrors keeps the nradix error-path name - overwrite/walk
// contracts plus delete-miss and lookup-miss on an empty artlpm
func TestLegacyAdapterErrors(t *testing.T) {
	TestCurrentDuplicateAndWalkContracts(t)
	table := artlpm.New[int]()
	missing := netip.MustParsePrefix("192.168.0.0/16")
	if table.Delete(missing) {
		t.Fatal("deleting an absent prefix returned true")
	}
	if _, ok := table.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("lookup miss returned present")
	}
}

// TestLegacyAdapterNetIP is the nradix net.IP-shaped lookup name - we just
// parse strings into netip and check mapped v4 still hits 10/8
func TestLegacyAdapterNetIP(t *testing.T) {
	table := artlpm.New[string]()
	table.Insert(netip.MustParsePrefix("10.0.0.0/8"), "v4")
	for _, addr := range []string{"10.1.2.3", "::ffff:10.1.2.3"} {
		if value, ok := table.Lookup(netip.MustParseAddr(addr)); !ok || value != "v4" {
			t.Fatalf("Lookup(%s) = (%q,%v), want (v4,true)", addr, value, ok)
		}
	}
}

// TestLegacyAdapterWalk is the nradix walk name - All() counts live in
// TestCurrentDuplicateAndWalkContracts
func TestLegacyAdapterWalk(t *testing.T) {
	TestCurrentDuplicateAndWalkContracts(t)
}
