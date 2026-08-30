package splitribfib

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// TestLookupAndWalks stands up a small hierarchy and checks Lookup/Lookup4/
// Lookup6 plus WalkParents most-specific-first and WalkDescendants of 10/8
func TestLookupAndWalks(t *testing.T) {
	table := newTestTable(t, []prefixentry.Entry[string]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: "default"},
		{Prefix: netip.MustParsePrefix("10.0.0.1/8"), Value: "private"},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: "site"},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: "rack"},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: "v6"},
	})
	defer table.Close()

	if table.Generation() != 1 {
		t.Fatalf("Generation() = %d, want 1", table.Generation())
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.1.2.3"))
	assertLookup(t, id, value, ok, "rack")
	id, value, ok = table.Lookup4(0x0a010203)
	assertLookup(t, id, value, ok, "rack")
	hi, lo := prefixentry.Addr6(netip.MustParseAddr("2001:db8::1"))
	id, value, ok = table.Lookup6(hi, lo)
	assertLookup(t, id, value, ok, "v6")

	var parents []string
	table.WalkParents(netip.MustParseAddr("10.1.2.3"), func(_ routeid.ID, prefix netip.Prefix, value string) bool {
		parents = append(parents, prefix.String()+"="+value)
		return true
	})
	wantParents := []string{"10.1.2.0/24=rack", "10.1.0.0/16=site", "10.0.0.0/8=private", "0.0.0.0/0=default"}
	if !equalStrings(parents, wantParents) {
		t.Fatalf("WalkParents() = %v, want %v", parents, wantParents)
	}

	var descendants []string
	ok = table.WalkDescendants(netip.MustParsePrefix("10.0.9.9/8"), func(_ routeid.ID, prefix netip.Prefix, value string) bool {
		descendants = append(descendants, prefix.String()+"="+value)
		return true
	})
	wantDescendants := []string{"10.0.0.0/8=private", "10.1.0.0/16=site", "10.1.2.0/24=rack"}
	if !ok || !equalStrings(descendants, wantDescendants) {
		t.Fatalf("WalkDescendants() = %v, %v; want true, %v", ok, descendants, wantDescendants)
	}
	if table.WalkDescendants(netip.MustParsePrefix("192.0.2.0/24"), func(routeid.ID, netip.Prefix, string) bool { return true }) {
		t.Fatal("WalkDescendants() found an absent prefix")
	}
}

// TestPayloadOnlyUpdateSharesIndexes replaces a value on an existing prefix
// and checks fib/rib/ids are reused, payloads is a new object, lookup sees it
func TestPayloadOnlyUpdateSharesIndexes(t *testing.T) {
	table := newTestTable(t, []prefixentry.Entry[string]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: "old"},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Value: "other"},
	})
	defer table.Close()

	before := table.current.Load()
	err := table.ApplyBatch([]routeupdate.Mutation[string]{
		{Prefix: netip.MustParsePrefix("10.99.88.77/8"), Value: "new"},
	})
	if err != nil {
		t.Fatalf("ApplyBatch() error = %v", err)
	}
	after := table.current.Load()
	if after.number != before.number+1 {
		t.Fatalf("generation = %d, want %d", after.number, before.number+1)
	}
	if after.fib != before.fib || after.rib != before.rib || reflect.ValueOf(after.ids).Pointer() != reflect.ValueOf(before.ids).Pointer() {
		t.Fatal("payload-only update did not share immutable indexes and ID map")
	}
	if after.payloads == before.payloads {
		t.Fatal("payload-only update reused payload pages object")
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.1.2.3"))
	assertLookup(t, id, value, ok, "new")
}

// TestStructuralAddDelete deletes a /16, adds a /24 and a v6 /32, checks the
// indexes were rebuilt, then deletes the /24 and falls back to 10/8
func TestStructuralAddDelete(t *testing.T) {
	table := newTestTable(t, []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 2},
	})
	defer table.Close()

	before := table.current.Load()
	err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Delete: true},
		{Prefix: netip.MustParsePrefix("10.2.3.99/24"), Value: 3},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 4},
	})
	if err != nil {
		t.Fatalf("ApplyBatch() error = %v", err)
	}
	after := table.current.Load()
	if after.fib == before.fib || after.rib == before.rib {
		t.Fatal("structural update reused an index")
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.2.3.4"))
	assertLookup(t, id, value, ok, 3)
	id, value, ok = table.Lookup(netip.MustParseAddr("2001:db8::1"))
	assertLookup(t, id, value, ok, 4)
	id, value, ok = table.Lookup(netip.MustParseAddr("10.1.2.3"))
	assertLookup(t, id, value, ok, 1)

	err = table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.2.3.0/24"), Delete: true},
	})
	if err != nil {
		t.Fatalf("delete ApplyBatch() error = %v", err)
	}
	id, value, ok = table.Lookup(netip.MustParseAddr("10.2.3.4"))
	assertLookup(t, id, value, ok, 1)
}

// TestInvalidInputIsRejectedAtomically checks New and ApplyBatch reject a
// zero prefix with ErrBadIP and don't bump generation or change lookups
func TestInvalidInputIsRejectedAtomically(t *testing.T) {
	if _, err := New([]prefixentry.Entry[int]{{Value: 1}}, routeupdate.Options{}); !errors.Is(err, prefixentry.ErrBadIP) {
		t.Fatalf("New() error = %v, want ErrBadIP", err)
	}

	table := newTestTable(t, []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
	})
	defer table.Close()
	wantGeneration := table.Generation()
	err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Value: 3},
	})
	if !errors.Is(err, prefixentry.ErrBadIP) {
		t.Fatalf("ApplyBatch() error = %v, want ErrBadIP", err)
	}
	if table.Generation() != wantGeneration {
		t.Fatalf("generation changed after invalid batch: %d", table.Generation())
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.1.1.1"))
	assertLookup(t, id, value, ok, 1)
}

// TestStructuralMutationsRebuildEvenWhenNetTopologyIsUnchanged puts a
// delete+reinsert and an add+delete in one batch. net membership is the same
// but we still rebuild because apply flags any add/delete as structural
func TestStructuralMutationsRebuildEvenWhenNetTopologyIsUnchanged(t *testing.T) {
	table := newTestTable(t, []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
	})
	defer table.Close()

	before := table.current.Load()
	err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Delete: true},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Value: 3},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Delete: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	after := table.current.Load()
	if after.fib == before.fib || after.rib == before.rib {
		t.Fatal("structural mutations did not rebuild indexes")
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.1.1.1"))
	assertLookup(t, id, value, ok, 2)
}

// TestNoOpDeletePublishesPayloadGeneration deletes an absent prefix and
// checks we still bump generation (payload path, nothing to rebuild)
func TestNoOpDeletePublishesPayloadGeneration(t *testing.T) {
	table := newTestTable(t, []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
	})
	defer table.Close()

	wantGeneration := table.Generation() + 1
	result := <-table.Submit([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Delete: true},
	})
	if result.Err != nil || result.Generation != wantGeneration || table.Generation() != wantGeneration {
		t.Fatalf("no-op result = %+v, current generation = %d", result, table.Generation())
	}
}

// TestSubmitCoalescesAndCloseIsIdempotent fires 8 payload Submits, checks they
// share a generation, then Close from 4 goroutines and Submit after close
func TestSubmitCoalescesAndCloseIsIdempotent(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{QueueSize: 1, MaxBatchSize: 16, MaxBatchDelay: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	results := make([]<-chan routeupdate.Result, 8)
	for i := range results {
		results[i] = table.Submit([]routeupdate.Mutation[int]{
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: i + 2},
		})
	}
	var generation uint64
	for i, resultChannel := range results {
		result, ok := <-resultChannel
		if !ok || result.Err != nil {
			t.Fatalf("result %d = %+v, open=%v", i, result, ok)
		}
		if generation == 0 {
			generation = result.Generation
		}
		if result.Generation != generation {
			t.Fatalf("result generation = %d, want coalesced %d", result.Generation, generation)
		}
		if _, open := <-resultChannel; open {
			t.Fatal("result channel was not closed")
		}
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.1.1.1"))
	assertLookup(t, id, value, ok, 9)

	var closes sync.WaitGroup
	closes.Add(4)
	for range 4 {
		go func() {
			defer closes.Done()
			table.Close()
		}()
	}
	closes.Wait()
	result := <-table.Submit(nil)
	if !errors.Is(result.Err, ErrClosed) || result.Generation != table.Generation() {
		t.Fatalf("Submit() after Close = %+v", result)
	}
}

// TestCloseDrainsAcceptedSubmissions Submit's a payload update with a long
// batch delay, Close's immediately, and checks the queued work still landed
func TestCloseDrainsAcceptedSubmissions(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{QueueSize: 8, MaxBatchSize: 8, MaxBatchDelay: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	resultChannel := table.Submit([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 2},
	})
	table.Close()
	result := <-resultChannel
	if result.Err != nil {
		t.Fatalf("accepted submission failed during Close: %v", result.Err)
	}
	id, value, ok := table.Lookup(netip.MustParseAddr("10.1.1.1"))
	assertLookup(t, id, value, ok, 2)
}

// TestConcurrentReadersAndWriter hammers Lookup/Walk from 8 goroutines while
// we Mix payload and structural ApplyBatch. just checking we don't panic
func TestConcurrentReadersAndWriter(t *testing.T) {
	table := newTestTable(t, []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: 2},
	})
	defer table.Close()

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				table.Lookup(netip.MustParseAddr("10.1.2.3"))
				table.Lookup4(0x0a010203)
				table.WalkParents(netip.MustParseAddr("10.1.2.3"), func(routeid.ID, netip.Prefix, int) bool { return true })
				table.WalkDescendants(netip.MustParsePrefix("10.0.0.0/8"), func(routeid.ID, netip.Prefix, int) bool { return true })
			}
		}()
	}
	for i := 0; i < 50; i++ {
		mutations := []routeupdate.Mutation[int]{
			{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Value: i},
		}
		if i%2 == 0 {
			mutations = append(mutations, routeupdate.Mutation[int]{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Value: i})
		} else {
			mutations = append(mutations, routeupdate.Mutation[int]{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Delete: true})
		}
		if err := table.ApplyBatch(mutations); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	readers.Wait()
}

// newTestTable is New + t.Fatal on error, and t.Helper so failures point at the caller
func newTestTable[V any](t *testing.T, entries []prefixentry.Entry[V]) *Table[V] {
	t.Helper()
	table, err := New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// assertLookup fatals unless ok and got==want
// we ignore the id, just checking the payload
func assertLookup[V comparable](t *testing.T, _ routeid.ID, got V, ok bool, want V) {
	t.Helper()
	if !ok || got != want {
		t.Fatalf("lookup = %v, %v; want %v, true", got, ok, want)
	}
}

// equalStrings is slices.Equal for []string, we didn't want to import slices
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
