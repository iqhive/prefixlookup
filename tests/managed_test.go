package tests_test

import (
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	compiled2 "github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/preorder2"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
	splitribfib2 "github.com/iqhive/prefixlookup/splitribfib"
)

type managedTable interface {
	Lookup(netip.Addr) (int, bool)
	ApplyBatch([]routeupdate.Mutation[int]) error
	Submit([]routeupdate.Mutation[int]) <-chan routeupdate.Result
	Generation() uint64
	Close()
}

type managedAdapter struct {
	lookup     func(netip.Addr) (int, bool)
	apply      func([]routeupdate.Mutation[int]) error
	submit     func([]routeupdate.Mutation[int]) <-chan routeupdate.Result
	generation func() uint64
	close      func()
}

// Lookup is the managedTable shim - we drop the extra id some tables return
func (m managedAdapter) Lookup(addr netip.Addr) (int, bool)             { return m.lookup(addr) }

// ApplyBatch forwards a sync mutation batch to the real table
func (m managedAdapter) ApplyBatch(v []routeupdate.Mutation[int]) error { return m.apply(v) }

// Submit forwards an async batch and hands back the result channel
func (m managedAdapter) Submit(v []routeupdate.Mutation[int]) <-chan routeupdate.Result {
	return m.submit(v)
}

// Generation is the published generation counter passthrough
func (m managedAdapter) Generation() uint64 { return m.generation() }

// Close shuts the worker - we always defer this in the tests
func (m managedAdapter) Close()             { m.close() }

// adaptPreorder2 wraps a preorder2 table so it looks like managedTable -
// Lookup strips the route id, everything else is a straight method bind
func adaptPreorder2(table *preorder2.Table[int]) managedTable {
	return managedAdapter{
		lookup: func(addr netip.Addr) (int, bool) { _, value, ok := table.Lookup(addr); return value, ok },
		apply:  table.ApplyBatch, submit: table.Submit, generation: table.Generation, close: table.Close,
	}
}

// adaptSplitRIBFIB2 is the same shim for splitribfib2 - we keep these
// separate so a signature drift on one package doesn't silently break the
// other factory
func adaptSplitRIBFIB2(table *splitribfib2.Table[int]) managedTable {
	return managedAdapter{
		lookup: func(addr netip.Addr) (int, bool) { _, value, ok := table.Lookup(addr); return value, ok },
		apply:  table.ApplyBatch, submit: table.Submit, generation: table.Generation, close: table.Close,
	}
}

// TestManagedStructuralPayloadAndAsyncPublication is the "payload overwrite
// vs structural insert vs async Submit" check for compiled2 / preorder2 /
// splitribfib2
//
// we start from a 500-prefix oracle, ApplyBatch the same 10.77/16 twice
// (payload 1 then 2), Submit a v6 /48, then delete the v4 prefix - lookups
// have to see 2 then the v6 value, and the async result generation must
// match table.Generation()
func TestManagedStructuralPayloadAndAsyncPublication(t *testing.T) {
	entries := randomOracle(901, 500).entries()
	factories := map[string]func([]prefixentry.Entry[int]) (managedTable, error){
		"compiled2": func(e []prefixentry.Entry[int]) (managedTable, error) {
			return compiled2.New(e, routeupdate.Options{QueueSize: 16, MaxBatchSize: 8})
		},
		"preorder2": func(e []prefixentry.Entry[int]) (managedTable, error) {
			table, err := preorder2.New(e, routeupdate.Options{QueueSize: 16, MaxBatchSize: 8})
			if err != nil {
				return nil, err
			}
			return adaptPreorder2(table), nil
		},
		"splitribfib2": func(e []prefixentry.Entry[int]) (managedTable, error) {
			table, err := splitribfib2.New(e, routeupdate.Options{QueueSize: 16, MaxBatchSize: 8})
			if err != nil {
				return nil, err
			}
			return adaptSplitRIBFIB2(table), nil
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			table, err := factory(entries)
			if err != nil {
				t.Fatal(err)
			}
			defer table.Close()
			prefix := netip.MustParsePrefix("10.77.0.0/16")
			if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: 1}}); err != nil {
				t.Fatal(err)
			}
			if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: 2}}); err != nil {
				t.Fatal(err)
			}
			result := <-table.Submit([]routeupdate.Mutation[int]{{Prefix: netip.MustParsePrefix("2001:db8:77::/48"), Value: 3}})
			if result.Err != nil || result.Generation != table.Generation() {
				t.Fatalf("async result = %+v, generation %d", result, table.Generation())
			}
			if value, ok := table.Lookup(netip.MustParseAddr("10.77.1.1")); !ok || value != 2 {
				t.Fatalf("payload overwrite = (%d,%v)", value, ok)
			}
			if value, ok := table.Lookup(netip.MustParseAddr("2001:db8:77::1")); !ok || value != 3 {
				t.Fatalf("structural insert = (%d,%v)", value, ok)
			}
			if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Delete: true}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestManagedConcurrentReadsAndWrites is the managed-table analogue of the
// versioned reader test - 256 stable /24s, 4 readers looping lookups while
// we ApplyBatch 12 unrelated 192.x/16s
//
// if publication tears the snapshot we'll see a miss; we don't try to read
// the new routes from the reader goroutines
func TestManagedConcurrentReadsAndWrites(t *testing.T) {
	base := make([]prefixentry.Entry[int], 256)
	for i := range base {
		base[i] = prefixentry.Entry[int]{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 0}), 24), Value: i}
	}
	factories := map[string]func() (managedTable, error){
		"compiled2": func() (managedTable, error) { return compiled2.New(base, routeupdate.Options{}) },
		"preorder2": func() (managedTable, error) {
			table, err := preorder2.New(base, routeupdate.Options{})
			if err != nil {
				return nil, err
			}
			return adaptPreorder2(table), nil
		},
		"splitribfib2": func() (managedTable, error) {
			table, err := splitribfib2.New(base, routeupdate.Options{})
			if err != nil {
				return nil, err
			}
			return adaptSplitRIBFIB2(table), nil
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			table, err := factory()
			if err != nil {
				t.Fatal(err)
			}
			defer table.Close()
			var stop atomic.Bool
			var reads atomic.Int64
			var wg sync.WaitGroup
			for reader := 0; reader < 4; reader++ {
				wg.Add(1)
				go func(seed int64) {
					defer wg.Done()
					rng := rand.New(rand.NewSource(seed))
					for !stop.Load() {
						i := rng.Intn(256)
						if value, ok := table.Lookup(netip.AddrFrom4([4]byte{10, 0, byte(i), 9})); !ok || value != i {
							t.Errorf("lookup = (%d,%v), want %d", value, ok, i)
							return
						}
						reads.Add(1)
					}
				}(int64(reader + 1))
			}
			for i := 0; i < 12; i++ {
				prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, byte(i), 0, 0}), 16)
				if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: i}}); err != nil {
					t.Fatal(err)
				}
			}
			stop.Store(true)
			wg.Wait()
			if reads.Load() == 0 {
				t.Fatal("no concurrent reads completed")
			}
		})
	}
}

// TestManagedHierarchyExactAndPublicationKinds checks WalkParents /
// WalkDescendants / Exact on preorder2 and splitribfib2 against the shared
// hierarchyEntries fixture, then pokes publication stats
//
// a payload-only overwrite of 10.1.2.0/24 must bump PayloadPublications,
// a new 10.2/16 must bump StructuralPublications - compiled2 gets the same
// stats check on v4 payload + v6 structural so we don't only cover the RIB
func TestManagedHierarchyExactAndPublicationKinds(t *testing.T) {
	entries := hierarchyEntries()
	pre, err := preorder2.New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer pre.Close()
	split, err := splitribfib2.New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer split.Close()

	query := netip.MustParsePrefix("10.1.0.0/16")
	addr := netip.MustParseAddr("10.1.2.3")
	if _, value, ok := pre.Exact(netip.MustParsePrefix("10.1.99.1/16")); !ok || value != 16 {
		t.Fatalf("preorder2 Exact = (%d,%v)", value, ok)
	}
	for name, parents := range map[string]func(func(int) bool){
		"preorder2": func(yield func(int) bool) {
			pre.WalkParents(addr, func(_ routeid.ID, _ netip.Prefix, value int) bool { return yield(value) })
		},
		"splitribfib2": func(yield func(int) bool) {
			split.WalkParents(addr, func(_ routeid.ID, _ netip.Prefix, value int) bool { return yield(value) })
		},
	} {
		var got []int
		parents(func(value int) bool { got = append(got, value); return true })
		if want := []int{32, 24, 16, 8, 0}; !sameInts(got, want) {
			t.Fatalf("%s parents = %v, want %v", name, got, want)
		}
	}
	for name, descendants := range map[string]func(func(netip.Prefix) bool) bool{
		"preorder2": func(yield func(netip.Prefix) bool) bool {
			return pre.WalkDescendants(query, func(_ routeid.ID, prefix netip.Prefix, _ int) bool { return yield(prefix) })
		},
		"splitribfib2": func(yield func(netip.Prefix) bool) bool {
			return split.WalkDescendants(query, func(_ routeid.ID, prefix netip.Prefix, _ int) bool { return yield(prefix) })
		},
	} {
		var got []netip.Prefix
		if !descendants(func(prefix netip.Prefix) bool { got = append(got, prefix); return true }) {
			t.Fatalf("%s did not find exact descendant root", name)
		}
		if len(got) != 4 {
			t.Fatalf("%s descendants = %v", name, got)
		}
	}

	prefix := netip.MustParsePrefix("10.1.2.0/24")
	if err := pre.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: 240}}); err != nil {
		t.Fatal(err)
	}
	if stats := pre.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 0 {
		t.Fatalf("payload stats = %+v", stats)
	}
	if err := pre.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: netip.MustParsePrefix("10.2.0.0/16"), Value: 216}}); err != nil {
		t.Fatal(err)
	}
	if stats := pre.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 1 {
		t.Fatalf("structural stats = %+v", stats)
	}

	compiled, err := compiled2.New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close()
	if err := compiled.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: 241}}); err != nil {
		t.Fatal(err)
	}
	if err := compiled.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: netip.MustParsePrefix("2001:db8:2::/48"), Value: 2048}}); err != nil {
		t.Fatal(err)
	}
	if stats := compiled.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 1 {
		t.Fatalf("compiled2 stats = %+v", stats)
	}
}
