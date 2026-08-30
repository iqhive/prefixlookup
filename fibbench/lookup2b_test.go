package fibbench

import (
	"net/netip"

	soaart "github.com/iqhive/prefixlookup/aosart"
	steplpm "github.com/iqhive/prefixlookup/slotlpm"
)

// adapters for slotlpm (imported as steplpm) and aosart (imported as soaart) -
// same concrete-type story as lookup2_test.go: we don't want newRebuilding's
// atomic.Value + interface + closure tax on the numbers
//
// the import aliases look backwards because the packages got renamed under
// us and the bench labels stayed put - don't "fix" the Name() strings

// ---------------------------------------------------------------- slotlpm

type slotlpmTable struct{ table *steplpm.Table[NextHop] }

// Name still says "steplpm" so the CSV/history doesn't fork - the type is
// slotlpm, the package import is aliased, it's a mess, leave the label
func (*slotlpmTable) Name() string { return "steplpm" }

// Reset constructs a fresh slotlpm table from the route dump
func (t *slotlpmTable) Reset(routes []route) {
	table, err := steplpm.New(slotlpmEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	t.table = table
}

// Read is a straight Lookup
func (t *slotlpmTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply wraps a single change as a batch of one
func (t *slotlpmTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch maps our mutations onto slotlpm's type and applies them
func (t *slotlpmTable) ApplyBatch(changes []mutation) {
	mutations := make([]steplpm.Mutation[NextHop], len(changes))
	for i, change := range changes {
		mutations[i] = steplpm.Mutation[NextHop]{
			Prefix: change.prefix, Value: change.next, Delete: change.remove,
		}
	}
	if err := t.table.ApplyBatch(mutations); err != nil {
		panic(err)
	}
}

// Close is a no-op - no worker to stop
func (t *slotlpmTable) Close() {}

// slotlpmEntriesOf converts the bench dump into slotlpm entries
func slotlpmEntriesOf(routes []route) []steplpm.Entry[NextHop] {
	entries := make([]steplpm.Entry[NextHop], len(routes))
	for i, r := range routes {
		entries[i] = steplpm.Entry[NextHop]{Prefix: r.prefix, Value: r.next}
	}
	return entries
}

// buildSlotlpmObject builds the immutable index plus a tightly sized value
// vector - comparable with a raw *bart.Table, no growth slack
func buildSlotlpmObject(routes []route) any {
	builder := steplpm.NewBuilder()
	ids := make([]uint32, len(routes))
	for i, r := range routes {
		id, err := builder.Add(r.prefix)
		if err != nil {
			panic(err)
		}
		ids[i] = id
	}
	// sized exactly - appended vectors keep slack the memory bench would
	// count as held bytes
	values := make([]NextHop, builder.Routes()+1)
	for i, r := range routes {
		values[ids[i]] = r.next
	}
	return &struct {
		index  *steplpm.Index
		values []NextHop
	}{index: builder.Build(), values: values}
}

// buildSlotlpmManagedObject builds the managed table (prefix set + ids so
// mutation isn't a full rebuild)
func buildSlotlpmManagedObject(routes []route) any {
	table, err := steplpm.New(slotlpmEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	return table
}

// ---------------------------------------------------------------- aosart

type aosartTable struct{ table *soaart.Table[NextHop] }

// Name still says "soaart" - package is aosart, label stayed for the history
func (*aosartTable) Name() string { return "soaart" }

// Reset constructs a fresh aosart table from the route dump
func (t *aosartTable) Reset(routes []route) {
	table, err := soaart.New(aosartEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	t.table = table
}

// Read is a straight Lookup
func (t *aosartTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply wraps a single change as a batch of one
func (t *aosartTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch maps our mutations onto aosart's type and applies them
func (t *aosartTable) ApplyBatch(changes []mutation) {
	mutations := make([]soaart.Mutation[NextHop], len(changes))
	for i, change := range changes {
		mutations[i] = soaart.Mutation[NextHop]{
			Prefix: change.prefix, Value: change.next, Delete: change.remove,
		}
	}
	if err := t.table.ApplyBatch(mutations); err != nil {
		panic(err)
	}
}

// Close is a no-op
func (t *aosartTable) Close() {}

// aosartEntriesOf converts the bench dump into aosart entries
func aosartEntriesOf(routes []route) []soaart.Entry[NextHop] {
	entries := make([]soaart.Entry[NextHop], len(routes))
	for i, r := range routes {
		entries[i] = soaart.Entry[NextHop]{Prefix: r.prefix, Value: r.next}
	}
	return entries
}

// buildAosartObject builds the immutable index plus tightly sized values for
// the memory bench
func buildAosartObject(routes []route) any {
	builder := soaart.NewBuilder()
	ids := make([]uint32, len(routes))
	for i, r := range routes {
		id, err := builder.Add(r.prefix)
		if err != nil {
			panic(err)
		}
		ids[i] = id
	}
	values := make([]NextHop, builder.Routes()+1)
	for i, r := range routes {
		values[ids[i]] = r.next
	}
	return &struct {
		index  *soaart.Index
		values []NextHop
	}{index: builder.Build(), values: values}
}

// buildAosartManagedObject builds the managed table that can mutate
func buildAosartManagedObject(routes []route) any {
	table, err := soaart.New(aosartEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	return table
}
