package fibbench

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/iqhive/prefixlookup/parityset"
	"github.com/iqhive/prefixlookup/soaart"
	"github.com/iqhive/prefixlookup/steplpm"
)

// adapters for parityset / steplpm / soaart, plus the BART fairness addendum
//
// why these are concrete types, not newRebuilding:
// newRebuilding reads through atomic.Value + an interface assertion + a
// lookupFunc closure - we measured that at 6.68 ns/op vs 0.83 ns/op for a
// concrete type holding atomic.Pointer, while the bare loop is 0.88 ns/op,
// so nearly six nanoseconds of every newRebuilding result is harness tax
//
// the fast in-repo tables (compiled-fib, preorder2, split-rib-fib) already
// implement table concretely, and a managed table behind an atomic pointer
// is the production shape, so the new impls do the same
//
// bart-*-direct wraps BART in that exact shape - rebuild on every mutation,
// store the pointer - so bart-lite vs bart-lite-direct is the harness tax
// alone, and parityset vs bart-lite-direct is the data structure alone

// ---------------------------------------------------------------- parityset

type paritysetTable struct{ table *parityset.Table }

// Name is the bench-subtest label - membership-only set, no next-hop payload
func (*paritysetTable) Name() string { return "parityset" }

// Reset rebuilds the managed table from a full route dump - we panic on
// constructor failure because a bench that can't load isn't a result
func (t *paritysetTable) Reset(routes []route) {
	table, err := parityset.NewTable(prefixesOf(routes))
	if err != nil {
		panic(err)
	}
	t.table = table
}

// Read is Contains with a dummy NextHop of 1 so we still fit the value-returning
// table interface - hit/miss is the only thing this structure can say
func (t *paritysetTable) Read(addr netip.Addr) (NextHop, bool) {
	return 1, t.table.Contains(addr)
}

// Apply is the single-mutation path - we just wrap it as a one-element batch
func (t *paritysetTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch maps our mutation type onto parityset.Mutation (prefix + delete
// flag, no payload) and applies in one go
func (t *paritysetTable) ApplyBatch(changes []mutation) {
	mutations := make([]parityset.Mutation, len(changes))
	for i, change := range changes {
		mutations[i] = parityset.Mutation{Prefix: change.prefix, Delete: change.remove}
	}
	if err := t.table.ApplyBatch(mutations); err != nil {
		panic(err)
	}
}

// Close is a no-op - parityset doesn't hold a worker we need to stop
func (t *paritysetTable) Close() {}

// prefixesOf strips next-hops so membership constructors can take a prefix
// slice - we don't Mask here, the impls do that themselves
func prefixesOf(routes []route) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(routes))
	for i, r := range routes {
		prefixes[i] = r.prefix
	}
	return prefixes
}

// buildParitysetObject builds the immutable compiled index - that's the
// artefact we compare to a raw *bart.Lite in the memory bench
func buildParitysetObject(routes []route) any {
	set, err := parityset.New(prefixesOf(routes))
	if err != nil {
		panic(err)
	}
	return set
}

// buildParitysetManagedObject builds the managed table, which also keeps the
// authoritative prefix set so deletes actually work
func buildParitysetManagedObject(routes []route) any {
	table, err := parityset.NewTable(prefixesOf(routes))
	if err != nil {
		panic(err)
	}
	return table
}

// ---------------------------------------------------------------- steplpm

type steplpmTable struct{ table *steplpm.Table[NextHop] }

// Name is the bench label for the stride-LPM table
func (*steplpmTable) Name() string { return "steplpm" }

// Reset constructs a fresh steplpm table from the route dump
func (t *steplpmTable) Reset(routes []route) {
	table, err := steplpm.New(steplpmEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	t.table = table
}

// Read is a straight Lookup - this one actually returns the next hop
func (t *steplpmTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply forwards a single change as a one-element batch
func (t *steplpmTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch copies our mutations into steplpm's type and ApplyBatch's them
func (t *steplpmTable) ApplyBatch(changes []mutation) {
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

// Close is a no-op - no worker goroutine on this table
func (t *steplpmTable) Close() {}

// steplpmEntriesOf is the route→Entry conversion we share between Reset and
// the memory-bench builders
func steplpmEntriesOf(routes []route) []steplpm.Entry[NextHop] {
	entries := make([]steplpm.Entry[NextHop], len(routes))
	for i, r := range routes {
		entries[i] = steplpm.Entry[NextHop]{Prefix: r.prefix, Value: r.next}
	}
	return entries
}

// buildSteplpmObject builds the immutable index plus a tightly sized value
// vector - that's the artefact we compare to a raw *bart.Table
func buildSteplpmObject(routes []route) any {
	builder := steplpm.NewBuilder()
	ids := make([]uint32, len(routes))
	for i, r := range routes {
		id, err := builder.Add(r.prefix)
		if err != nil {
			panic(err)
		}
		ids[i] = id
	}
	// sized exactly - an appended vector would keep growth slack, and the
	// memory bench would count that as held bytes
	values := make([]NextHop, builder.Routes()+1)
	for i, r := range routes {
		values[ids[i]] = r.next
	}
	return &struct {
		index  *steplpm.Index
		values []NextHop
	}{index: builder.Build(), values: values}
}

// buildSteplpmManagedObject builds the managed table, which also keeps the
// prefix set and route ids so mutation isn't a full rebuild
func buildSteplpmManagedObject(routes []route) any {
	table, err := steplpm.New(steplpmEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	return table
}

// ------------------------------------------------- BART fairness addendum

// bartLiteDirect is bart.Lite behind the same concrete atomic.Pointer adapter
// the new impls use, with the same rebuild-and-publish mutation strategy as
// newRebuilding - so we're not charging BART the harness tax
type bartLiteDirect struct {
	current atomic.Pointer[bart.Lite]
	mu      sync.Mutex
	routes  map[netip.Prefix]NextHop
}

// newBARTLiteDirect is the factory the bench table list calls - empty map,
// first Reset fills it
func newBARTLiteDirect() *bartLiteDirect {
	return &bartLiteDirect{routes: make(map[netip.Prefix]NextHop)}
}

// Name is the fairness-addendum label so it doesn't collide with bart-lite
func (*bartLiteDirect) Name() string { return "bart-lite-direct" }

// Read loads the published Lite and Does Contains - dummy NextHop 1
func (t *bartLiteDirect) Read(addr netip.Addr) (NextHop, bool) {
	return 1, t.current.Load().Lookup(addr)
}

// Reset replaces the route map under the mutex then publish()s a new Lite
func (t *bartLiteDirect) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.routes)
	for _, r := range routes {
		t.routes[r.prefix.Masked()] = r.next
	}
	t.publish()
}

// Apply is the single-mutation wrapper
func (t *bartLiteDirect) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch mutates the authoritative map then rebuilds - same strategy as
// newRebuilding, just without the interface/closure tax
func (t *bartLiteDirect) ApplyBatch(changes []mutation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, change := range changes {
		prefix := change.prefix.Masked()
		if change.remove {
			delete(t.routes, prefix)
		} else {
			t.routes[prefix] = change.next
		}
	}
	t.publish()
}

// Close is a no-op - nothing to stop
func (t *bartLiteDirect) Close() {}

// publish clones the map into a fresh bart.Lite and stores the pointer -
// readers never see a half-built table
func (t *bartLiteDirect) publish() {
	lite := new(bart.Lite)
	for prefix := range t.routes {
		lite.Insert(prefix)
	}
	t.current.Store(lite)
}

// bartTableDirect is the value-returning equivalent of bartLiteDirect
type bartTableDirect struct {
	current atomic.Pointer[bart.Table[NextHop]]
	mu      sync.Mutex
	routes  map[netip.Prefix]NextHop
}

// newBARTTableDirect is the factory - empty map until Reset
func newBARTTableDirect() *bartTableDirect {
	return &bartTableDirect{routes: make(map[netip.Prefix]NextHop)}
}

// Name is the fairness-addendum label for the payload table
func (*bartTableDirect) Name() string { return "bart-table-direct" }

// Read loads the published bart.Table and looks up the next hop
func (t *bartTableDirect) Read(addr netip.Addr) (NextHop, bool) {
	return t.current.Load().Lookup(addr)
}

// Reset replaces the route map and publishes a new bart.Table
func (t *bartTableDirect) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.routes)
	for _, r := range routes {
		t.routes[r.prefix.Masked()] = r.next
	}
	t.publish()
}

// Apply is the single-mutation wrapper
func (t *bartTableDirect) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch mutates the map then rebuilds the whole bart.Table
func (t *bartTableDirect) ApplyBatch(changes []mutation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, change := range changes {
		prefix := change.prefix.Masked()
		if change.remove {
			delete(t.routes, prefix)
		} else {
			t.routes[prefix] = change.next
		}
	}
	t.publish()
}

// Close is a no-op
func (t *bartTableDirect) Close() {}

// publish clones the map into a fresh bart.Table[NextHop] and stores it
func (t *bartTableDirect) publish() {
	table := new(bart.Table[NextHop])
	for prefix, next := range t.routes {
		table.Insert(prefix, next)
	}
	t.current.Store(table)
}

// ---------------------------------------------------------------- soaart

type soaartTable struct{ table *soaart.Table[NextHop] }

// Name is the bench label for the SoA ART table
func (*soaartTable) Name() string { return "soaart" }

// Reset constructs a fresh soaart table from the route dump
func (t *soaartTable) Reset(routes []route) {
	table, err := soaart.New(soaartEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	t.table = table
}

// Read is a straight Lookup
func (t *soaartTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply forwards a single change as a batch of one
func (t *soaartTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch maps our mutations onto soaart's type and applies them
func (t *soaartTable) ApplyBatch(changes []mutation) {
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

// Close is a no-op - no worker
func (t *soaartTable) Close() {}

// soaartEntriesOf converts the bench route dump into soaart entries
func soaartEntriesOf(routes []route) []soaart.Entry[NextHop] {
	entries := make([]soaart.Entry[NextHop], len(routes))
	for i, r := range routes {
		entries[i] = soaart.Entry[NextHop]{Prefix: r.prefix, Value: r.next}
	}
	return entries
}

// buildSoaartObject builds the immutable index plus a tightly sized value
// vector for the memory bench - same trick as steplpm so we don't count
// slice slack
func buildSoaartObject(routes []route) any {
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

// buildSoaartManagedObject builds the managed table that can mutate
func buildSoaartManagedObject(routes []route) any {
	table, err := soaart.New(soaartEntriesOf(routes))
	if err != nil {
		panic(err)
	}
	return table
}
