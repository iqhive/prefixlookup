package preorder2

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// TestPayloadPublicationSharesTopologyAndExactMap replaces a value and checks
// topology and the exact map are reused, pages is a new object, Stats says payload
func TestPayloadPublicationSharesTopologyAndExactMap(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	table, err := New([]prefixentry.Entry[int]{{Prefix: prefix, Value: 1}}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	before := table.current.Load()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: 2}}); err != nil {
		t.Fatal(err)
	}
	after := table.current.Load()
	if after.topology != before.topology || reflect.ValueOf(after.exact).Pointer() != reflect.ValueOf(before.exact).Pointer() {
		t.Fatal("payload publication did not share topology and exact map")
	}
	if after.pages == before.pages {
		t.Fatal("payload publication did not replace route pages")
	}
	if stats := table.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestNetNoOpBatchSharesEntireSnapshotData feeds batches that cancel out
// (nil, delete of absent, add-then-delete) and checks we share the whole
// snapshot, just bump generation
func TestNetNoOpBatchSharesEntireSnapshotData(t *testing.T) {
	table, err := New([]prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Value: 1},
	}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	cancelled := netip.MustParsePrefix("192.0.2.0/24")
	batches := [][]routeupdate.Mutation[int]{
		nil,
		{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Delete: true}},
		{
			{Prefix: cancelled, Value: 2},
			{Prefix: cancelled, Delete: true},
		},
	}
	for _, batch := range batches {
		before := table.current.Load()
		if err := table.ApplyBatch(batch); err != nil {
			t.Fatal(err)
		}
		after := table.current.Load()
		if after.topology != before.topology || after.pages != before.pages ||
			reflect.ValueOf(after.exact).Pointer() != reflect.ValueOf(before.exact).Pointer() {
			t.Fatal("net-no-op batch copied immutable snapshot data")
		}
		if after.generation != before.generation+1 {
			t.Fatalf("generation = %d; want %d", after.generation, before.generation+1)
		}
	}
	if stats := table.Stats(); stats.PayloadPublications != 3 || stats.StructuralPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if _, _, ok := table.Exact(cancelled); ok {
		t.Fatal("cancelled addition remained present")
	}
}

// TestPayloadUpdateIsRetainedByLaterStructuralBuild does a payload change
// then a structural add, and checks the payload change survived the rebuild
func TestPayloadUpdateIsRetainedByLaterStructuralBuild(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	table, err := New([]prefixentry.Entry[int]{{Prefix: prefix, Value: 1}}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	if err := table.ApplyBatch([]routeupdate.Mutation[int]{{Prefix: prefix, Value: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Value: 3},
	}); err != nil {
		t.Fatal(err)
	}
	if _, got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 2 {
		t.Fatalf("lookup after structural build = %d, %v; want 2, true", got, ok)
	}
}

// TestDeleteThenReplaceExistingPrefixIsPayloadOnly puts a delete and a
// re-insert of the same prefix in one batch. net topology unchanged so we
// take the payload path
func TestDeleteThenReplaceExistingPrefixIsPayloadOnly(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	table, err := New([]prefixentry.Entry[int]{{Prefix: prefix, Value: 1}}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(table.Close)

	before := table.current.Load()
	if err := table.ApplyBatch([]routeupdate.Mutation[int]{
		{Prefix: prefix, Delete: true},
		{Prefix: prefix, Value: 3},
	}); err != nil {
		t.Fatal(err)
	}
	after := table.current.Load()
	if after.topology != before.topology || reflect.ValueOf(after.exact).Pointer() != reflect.ValueOf(before.exact).Pointer() {
		t.Fatal("unchanged net topology was rebuilt")
	}
	if _, got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 3 {
		t.Fatalf("lookup = %d, %v; want 3, true", got, ok)
	}
	if stats := table.Stats(); stats.PayloadPublications != 1 || stats.StructuralPublications != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}
