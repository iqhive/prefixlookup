package compiledfib

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// prefix parses s or panics, keeps the tests readable
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr parses s or panics, same as prefix
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// TestLookupLongestPrefix stands up a mixed v4/v6 table and checks LPM via
// Lookup, Lookup4 and Lookup6, plus a miss on fd00::/8
func TestLookupLongestPrefix(t *testing.T) {
	table, err := New([]prefixentry.Entry[string]{
		{Prefix: prefix("0.0.0.0/0"), Value: "v4-default"},
		{Prefix: prefix("10.0.0.0/8"), Value: "v4-eight"},
		{Prefix: prefix("10.1.2.99/24"), Value: "v4-24"},
		{Prefix: prefix("2001:db8::/32"), Value: "v6-32"},
		{Prefix: prefix("2001:db8:1::/48"), Value: "v6-48"},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	tests := []struct {
		address string
		want    string
	}{
		{"192.0.2.1", "v4-default"},
		{"10.2.0.1", "v4-eight"},
		{"10.1.2.3", "v4-24"},
		{"2001:db8:2::1", "v6-32"},
		{"2001:db8:1::1", "v6-48"},
	}
	for _, test := range tests {
		got, ok := table.Lookup(addr(test.address))
		if !ok || got != test.want {
			t.Errorf("Lookup(%s) = %q, %v; want %q, true", test.address, got, ok, test.want)
		}
	}
	if _, ok := table.Lookup(addr("fd00::1")); ok {
		t.Error("unexpected IPv6 match")
	}

	got4, ok := table.Lookup4(10<<24 | 1<<16 | 2<<8 | 4)
	if !ok || got4 != "v4-24" {
		t.Fatalf("Lookup4 = %q, %v", got4, ok)
	}
	hi, lo := prefixentry.Addr6(addr("2001:db8:1::2"))
	got6, ok := table.Lookup6(hi, lo)
	if !ok || got6 != "v6-48" {
		t.Fatalf("Lookup6 = %q, %v", got6, ok)
	}
}

// TestPayloadUpdateSharesTopology checks that replacing a value on an existing
// prefix reuses the index and routes map, bumps generation, and shows up in
// Stats as payload-only
func TestPayloadUpdateSharesTopology(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 1},
		{Prefix: prefix("10.1.0.0/16"), Value: 2},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	before := table.current.Load()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: prefix("10.1.2.3/16"), Value: 22},
	}); err != nil {
		t.Fatal(err)
	}
	after := table.current.Load()
	if after.generation != before.generation+1 {
		t.Fatalf("generation = %d; want %d", after.generation, before.generation+1)
	}
	if after.index != before.index || reflect.ValueOf(after.routes).Pointer() != reflect.ValueOf(before.routes).Pointer() {
		t.Fatal("payload update did not share topology")
	}
	if got, ok := table.Lookup(addr("10.1.9.9")); !ok || got != 22 {
		t.Fatalf("updated lookup = %d, %v", got, ok)
	}
	if got, ok := table.Lookup(addr("10.2.0.1")); !ok || got != 1 {
		t.Fatalf("unchanged lookup = %d, %v", got, ok)
	}
	if stats := table.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestNetNoOpBatchSharesEntireGenerationData feeds batches that cancel out
// (nil, delete of absent, add-then-delete) and checks we still share the
// whole generation, just bump the number
func TestNetNoOpBatchSharesEntireGenerationData(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	batches := [][]routeupdate.Mutation[int]{
		nil,
		{{Prefix: prefix("198.51.100.0/24"), Delete: true}},
		{
			{Prefix: prefix("192.0.2.0/24"), Value: 2},
			{Prefix: prefix("192.0.2.0/24"), Delete: true},
		},
	}
	for _, batch := range batches {
		before := table.current.Load()
		if err := table.ApplyBatch(batch); err != nil {
			t.Fatal(err)
		}
		after := table.current.Load()
		if after.index != before.index || after.payloads != before.payloads ||
			reflect.ValueOf(after.routes).Pointer() != reflect.ValueOf(before.routes).Pointer() {
			t.Fatal("net-no-op batch copied immutable generation data")
		}
		if after.generation != before.generation+1 {
			t.Fatalf("generation = %d; want %d", after.generation, before.generation+1)
		}
	}
	if stats := table.Stats(); stats.PayloadPublications != 3 || stats.StructuralPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if _, ok := table.Lookup(addr("192.0.2.1")); ok {
		t.Fatal("cancelled addition remained present")
	}
}

// TestPayloadUpdateIsRetainedByLaterStructuralBuild does a payload change then
// a structural add, and checks the payload change is still visible after the
// rebuild (the catalogue must have been updated, not just the pages)
func TestPayloadUpdateIsRetainedByLaterStructuralBuild(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: prefix("192.0.2.0/24"), Value: 3},
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(addr("10.1.2.3")); !ok || got != 2 {
		t.Fatalf("lookup after structural build = %d, %v; want 2, true", got, ok)
	}
}

// TestDeleteThenReplaceExistingPrefixIsPayloadOnly puts a delete and a
// re-insert of the same prefix in one batch. net topology is unchanged so we
// should take the payload path, not rebuild
func TestDeleteThenReplaceExistingPrefixIsPayloadOnly(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	before := table.current.Load()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: prefix("10.0.0.0/8"), Delete: true},
		{Prefix: prefix("10.0.0.0/8"), Value: 3},
	}); err != nil {
		t.Fatal(err)
	}
	after := table.current.Load()
	if after.index != before.index || reflect.ValueOf(after.routes).Pointer() != reflect.ValueOf(before.routes).Pointer() {
		t.Fatal("unchanged net topology was rebuilt")
	}
	if got, ok := table.Lookup(addr("10.1.2.3")); !ok || got != 3 {
		t.Fatalf("lookup = %d, %v; want 3, true", got, ok)
	}
	if stats := table.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestAddDeleteAndNormalization checks a real add, a delete (via a different
// host of the same prefix), structural stats, and that a junk prefix doesn't
// publish a generation
func TestAddDeleteAndNormalization(t *testing.T) {
	table, err := New([]prefixentry.Entry[string]{
		{Prefix: prefix("10.0.0.1/8"), Value: "base"},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	if err := table.ApplyBatch([]routeupdate.Mutation[string]{
		{Prefix: prefix("10.1.2.3/16"), Value: "added"},
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(addr("10.1.9.9")); !ok || got != "added" {
		t.Fatalf("added lookup = %q, %v", got, ok)
	}
	if err := table.ApplyBatch([]routeupdate.Mutation[string]{
		{Prefix: prefix("10.1.255.255/16"), Delete: true},
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(addr("10.1.9.9")); !ok || got != "base" {
		t.Fatalf("lookup after delete = %q, %v", got, ok)
	}
	if stats := table.Stats(); stats.StructuralPublications != 2 {
		t.Fatalf("structural publications = %d; want 2", stats.StructuralPublications)
	}

	bad := netip.PrefixFrom(netip.Addr{}, 0)
	start := table.Generation()
	if err := table.ApplyBatch([]routeupdate.Mutation[string]{{Prefix: bad}}); !errors.Is(err, prefixentry.ErrBadIP) {
		t.Fatalf("invalid mutation error = %v", err)
	}
	if table.Generation() != start {
		t.Fatal("invalid mutation published a generation")
	}
}

// TestConcurrentSubmitCoalescesAndCompletes fires 32 concurrent payload
// updates at the same prefix with a batch delay, and checks they all land on
// one generation
func TestConcurrentSubmitCoalescesAndCompletes(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 0},
	}, routeupdate.Options{QueueSize: 64, MaxBatchSize: 64, MaxBatchDelay: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	const requests = 32
	results := make([]<-chan routeupdate.Result, requests)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = table.Submit([]routeupdate.Mutation[int]{
				{Prefix: prefix("10.0.0.0/8"), Value: i},
			})
		}(i)
	}
	close(start)
	wg.Wait()
	var generation uint64
	for i, resultCh := range results {
		select {
		case result := <-resultCh:
			if result.Err != nil {
				t.Fatalf("result %d: %v", i, result.Err)
			}
			if generation == 0 {
				generation = result.Generation
			} else if result.Generation != generation {
				t.Fatalf("result generation = %d; want %d", result.Generation, generation)
			}
		case <-time.After(time.Second):
			t.Fatalf("result %d did not complete", i)
		}
	}
	if stats := table.Stats(); stats.PayloadPublications != 1 {
		t.Fatalf("payload publications = %d; want 1", stats.PayloadPublications)
	}
}

// TestConcurrentReadersAndWriter hammers Lookup4 from 8 goroutines while the
// test goroutine ApplyBatch's payload updates. just checking we don't panic
// or return a zero
func TestConcurrentReadersAndWriter(t *testing.T) {
	table, err := New([]prefixentry.Entry[uint64]{
		{Prefix: prefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	var stop atomic.Bool
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				value, ok := table.Lookup4(10<<24 | 1)
				if !ok || value == 0 {
					t.Errorf("lookup = %d, %v", value, ok)
					return
				}
			}
		}()
	}
	for i := uint64(2); i < 100; i++ {
		if err := table.ApplyBatch([]routeupdate.Mutation[uint64]{
			{Prefix: prefix("10.0.0.0/8"), Value: i},
		}); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	readers.Wait()
}

// TestCloseDrainsAndIsIdempotent Submit's a payload update, Close's twice,
// checks the queued result landed, then Submit after close gets ErrClosed
func TestCloseDrainsAndIsIdempotent(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{MaxBatchDelay: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result := table.Submit([]routeupdate.Mutation[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 2},
	})
	table.Close()
	table.Close()
	if got := <-result; got.Err != nil {
		t.Fatalf("queued result: %v", got.Err)
	}
	if got, ok := table.Lookup(addr("10.1.2.3")); !ok || got != 2 {
		t.Fatalf("lookup after close = %d, %v", got, ok)
	}
	closed := <-table.Submit([]routeupdate.Mutation[int]{
		{Prefix: prefix("10.0.0.0/8"), Value: 3},
	})
	if !errors.Is(closed.Err, ErrClosed) {
		t.Fatalf("submit after close error = %v", closed.Err)
	}
}
