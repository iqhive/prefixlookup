package preorder2_test

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/preorder2"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// p parses s or panics, keeps the tests readable
func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// a parses s or panics, same as p
func a(s string) netip.Addr   { return netip.MustParseAddr(s) }

// TestLookupExactAndWalks stands up a small hierarchy and checks Lookup,
// Exact (including host bits that should canonicalise), Lookup4/6,
// WalkParents and WalkDescendants
func TestLookupExactAndWalks(t *testing.T) {
	table, err := preorder2.New([]prefixentry.Entry[string]{
		{Prefix: p("0.0.0.0/0"), Value: "default"},
		{Prefix: p("10.0.0.0/8"), Value: "ten"},
		{Prefix: p("10.1.0.0/16"), Value: "site"},
		{Prefix: p("10.1.2.0/24"), Value: "lan"},
		{Prefix: p("2001:db8::/32"), Value: "v6"},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	id, got, ok := table.Lookup(a("10.1.2.3"))
	if !ok || got != "lan" || id == 0 {
		t.Fatalf("Lookup() = (%d, %q, %v)", id, got, ok)
	}
	if exactID, exact, found := table.Exact(p("10.1.2.99/24")); !found || exact != got || exactID != id {
		t.Fatalf("Exact() = (%d, %q, %v); Lookup ID = %d", exactID, exact, found, id)
	}
	if _, got, ok := table.Lookup4(0x0a010203); !ok || got != "lan" {
		t.Fatalf("Lookup4() = (%q, %v)", got, ok)
	}
	hi, lo := prefixentry.Addr6(a("2001:db8::1"))
	if _, got, ok := table.Lookup6(hi, lo); !ok || got != "v6" {
		t.Fatalf("Lookup6() = (%q, %v)", got, ok)
	}

	var parents []string
	table.WalkParents(a("10.1.2.3"), func(_ routeid.ID, prefix netip.Prefix, value string) bool {
		parents = append(parents, prefix.String()+"="+value)
		return true
	})
	wantParents := []string{"10.1.2.0/24=lan", "10.1.0.0/16=site", "10.0.0.0/8=ten", "0.0.0.0/0=default"}
	if !slices.Equal(parents, wantParents) {
		t.Fatalf("parents = %v; want %v", parents, wantParents)
	}

	var descendants []string
	found := table.WalkDescendants(p("10.0.0.7/8"), func(_ routeid.ID, prefix netip.Prefix, value string) bool {
		descendants = append(descendants, prefix.String()+"="+value)
		return true
	})
	wantDescendants := []string{"10.0.0.0/8=ten", "10.1.0.0/16=site", "10.1.2.0/24=lan"}
	if !found || !slices.Equal(descendants, wantDescendants) {
		t.Fatalf("descendants = %v, %v; want %v, true", descendants, found, wantDescendants)
	}
	if table.WalkDescendants(p("192.0.2.0/24"), func(routeid.ID, netip.Prefix, string) bool { return true }) {
		t.Fatal("WalkDescendants reported a missing prefix")
	}
}

// TestPayloadUpdateKeepsIDsAndUpdatesEveryReadPath replaces a value on an
// existing prefix and checks the routeid is stable across Lookup and
// WalkParents, generation bumps
func TestPayloadUpdateKeepsIDsAndUpdatesEveryReadPath(t *testing.T) {
	table, err := preorder2.New([]prefixentry.Entry[int]{
		{Prefix: p("10.0.0.0/8"), Value: 1},
		{Prefix: p("10.1.0.0/16"), Value: 2},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	id, _, _ := table.Exact(p("10.1.0.0/16"))
	before := table.Generation()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: p("10.1.9.9/16"), Value: 20}}); err != nil {
		t.Fatal(err)
	}
	if table.Generation() != before+1 {
		t.Fatalf("generation = %d; want %d", table.Generation(), before+1)
	}
	newID, got, ok := table.Lookup(a("10.1.2.3"))
	if !ok || got != 20 || newID != id {
		t.Fatalf("Lookup() = (%d, %d, %v); want (%d, 20, true)", newID, got, ok, id)
	}
	var walked int
	table.WalkParents(a("10.1.2.3"), func(walkID routeid.ID, prefix netip.Prefix, value int) bool {
		if prefix == p("10.1.0.0/16") {
			if walkID != id || value != 20 {
				t.Fatalf("walk route = (%d, %d); want (%d, 20)", walkID, value, id)
			}
			walked++
		}
		return true
	})
	if walked != 1 {
		t.Fatalf("updated route visited %d times", walked)
	}
}

// TestStructuralAddDeleteAndNormalization adds a child, deletes it (via a
// different host of the same prefix), checks stats, then a junk mutation
// must not bump generation
func TestStructuralAddDeleteAndNormalization(t *testing.T) {
	table, err := preorder2.New([]prefixentry.Entry[string]{{Prefix: p("10.0.0.7/8"), Value: "parent"}}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	if err := table.ApplyBatch([]routeupdate.Mutation[string]{{Prefix: p("10.1.2.99/24"), Value: "child"}}); err != nil {
		t.Fatal(err)
	}
	if _, got, ok := table.Exact(p("10.1.2.1/24")); !ok || got != "child" {
		t.Fatalf("added Exact() = (%q, %v)", got, ok)
	}
	if err := table.ApplyBatch([]routeupdate.Mutation[string]{{Prefix: p("10.1.2.1/24"), Delete: true}}); err != nil {
		t.Fatal(err)
	}
	if _, got, ok := table.Lookup(a("10.1.2.3")); !ok || got != "parent" {
		t.Fatalf("post-delete Lookup() = (%q, %v)", got, ok)
	}
	if stats := table.Stats(); stats.StructuralPublications != 2 || stats.PayloadPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	before := table.Generation()
	if err := table.ApplyBatch([]routeupdate.Mutation[string]{{Prefix: netip.Prefix{}, Value: "bad"}}); !errors.Is(err, prefixentry.ErrBadIP) {
		t.Fatalf("invalid mutation error = %v", err)
	}
	if table.Generation() != before {
		t.Fatal("invalid mutation changed generation")
	}
}

// TestSubmitCoalescesRequests fires 8 payload Submits at the same prefix
// with a batch delay and checks they share a generation, last value wins
func TestSubmitCoalescesRequests(t *testing.T) {
	table, err := preorder2.New([]prefixentry.Entry[int]{{Prefix: p("10.0.0.0/8"), Value: 0}}, routeupdate.Options{
		QueueSize:     32,
		MaxBatchSize:  16,
		MaxBatchDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	results := make([]<-chan routeupdate.Result, 8)
	for i := range results {
		results[i] = table.Submit([]routeupdate.Mutation[int]{{Prefix: p("10.0.0.0/8"), Value: i + 1}})
	}
	var generation uint64
	for i, result := range results {
		got := <-result
		if got.Err != nil {
			t.Fatal(got.Err)
		}
		if i == 0 {
			generation = got.Generation
		} else if got.Generation != generation {
			t.Fatalf("request %d generation = %d; want coalesced generation %d", i, got.Generation, generation)
		}
	}
	if _, got, ok := table.Lookup(a("10.1.2.3")); !ok || got != 8 {
		t.Fatalf("Lookup() = (%d, %v); want (8, true)", got, ok)
	}
}

// TestConcurrentReadersAndWriter hammers Lookup from 8 goroutines while we
// ApplyBatch payload updates. just checking we don't panic or see id==0
func TestConcurrentReadersAndWriter(t *testing.T) {
	table, err := preorder2.New([]prefixentry.Entry[int]{{Prefix: p("10.0.0.0/8"), Value: 0}}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					id, _, ok := table.Lookup(a("10.1.2.3"))
					if !ok || id == 0 {
						t.Errorf("concurrent Lookup() = (%d, %v)", id, ok)
						return
					}
				}
			}
		}()
	}
	for i := 1; i <= 100; i++ {
		if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: p("10.0.0.0/8"), Value: i}}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if _, got, _ := table.Lookup(a("10.1.2.3")); got != 100 {
		t.Fatalf("final value = %d; want 100", got)
	}
}

// TestCloseIsIdempotentAndRejectsSubmissions Close's twice then Submit must
// come back ErrClosed
func TestCloseIsIdempotentAndRejectsSubmissions(t *testing.T) {
	table, err := preorder2.New[int](nil, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: p("10.0.0.0/8"), Value: 1}}); err != nil {
		t.Fatal(err)
	}
	table.Close()
	table.Close()
	result := <-table.Submit([]routeupdate.Mutation[int]{{Prefix: p("10.0.0.0/8"), Value: 2}})
	if !errors.Is(result.Err, preorder2.ErrClosed) {
		t.Fatalf("Submit after Close error = %v", result.Err)
	}
}
