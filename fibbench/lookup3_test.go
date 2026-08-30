package fibbench

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/iqhive/prefixlookup/dirlpm"
	"github.com/iqhive/prefixlookup/dirset"
	"github.com/iqhive/prefixlookup/orderwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// adapters for the dirset / dirlpm / orderwalk family
//
// these are tuned to a real BGP table shape - genPrefixes now follows that
// occupancy, but makeFixture does not, so they can still trade footprint on
// BenchmarkMemory for latency; BenchmarkRealTable is where their assumptions
// actually get exercised
//
// concrete types holding an atomic pointer, not newRebuilding - see
// lookup2_test.go for the harness-tax rant

// ---------------------------------------------------------------- dirset

type dirsetTable struct {
	mu      sync.Mutex
	current atomic.Pointer[dirset.Set]
	routes  map[netip.Prefix]struct{}
}

// Name is the membership-set label
func (*dirsetTable) Name() string { return "dirset" }

// Read loads the published set and Contains - dummy NextHop 1 so we fit the
// value-returning table interface
func (t *dirsetTable) Read(addr netip.Addr) (NextHop, bool) {
	return 1, t.current.Load().Contains(addr)
}

// Reset replaces the authoritative prefix map then publish()s a new set
func (t *dirsetTable) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = make(map[netip.Prefix]struct{}, len(routes))
	for _, r := range routes {
		t.routes[r.prefix.Masked()] = struct{}{}
	}
	t.publish()
}

// Apply wraps a single change as a batch of one
func (t *dirsetTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch mutates the map under the mutex then rebuilds - dirset has no
// incremental Apply, so every update is a full New
func (t *dirsetTable) ApplyBatch(changes []mutation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, change := range changes {
		prefix := change.prefix.Masked()
		if change.remove {
			delete(t.routes, prefix)
		} else {
			t.routes[prefix] = struct{}{}
		}
	}
	t.publish()
}

// publish snapshots the map into a prefix slice and stores a new dirset -
// readers only ever see a fully built set
func (t *dirsetTable) publish() {
	prefixes := make([]netip.Prefix, 0, len(t.routes))
	for prefix := range t.routes {
		prefixes = append(prefixes, prefix)
	}
	t.current.Store(mustBuild(dirset.New(prefixes)))
}

// Close is a no-op
func (t *dirsetTable) Close() {}

// buildDirsetObject is the memory-bench artefact - just the compiled set,
// no mutation maps hanging off it
func buildDirsetObject(routes []route) any {
	prefixes := make([]netip.Prefix, len(routes))
	for i, r := range routes {
		prefixes[i] = r.prefix
	}
	return mustBuild(dirset.New(prefixes))
}

// ---------------------------------------------------------------- dirlpm

type dirlpmTable struct{ table *dirlpm.Table[NextHop] }

// Name is the managed LPM label
func (*dirlpmTable) Name() string { return "dirlpm" }

// Reset closes any previous table (it's got a worker) then builds a new one
func (t *dirlpmTable) Reset(routes []route) {
	if t.table != nil {
		t.table.Close()
	}
	t.table = mustBuild(dirlpm.New(entries(routes), routeupdate.Options{}))
}

// Read is a straight Lookup
func (t *dirlpmTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply wraps a single change as a batch of one
func (t *dirlpmTable) Apply(change mutation)                { t.ApplyBatch([]mutation{change}) }

// ApplyBatch hands routeupdate mutations through to the managed table
func (t *dirlpmTable) ApplyBatch(changes []mutation) {
	if err := t.table.ApplyBatch(routeMutations(changes)); err != nil {
		panic(err)
	}
}

// Close stops the worker and nils the pointer so a later Reset doesn't
// double-close
func (t *dirlpmTable) Close() {
	if t.table != nil {
		t.table.Close()
		t.table = nil
	}
}

// buildDirlpmObject wraps the managed table in managedObject so BenchmarkMemory
// will Close it - otherwise we leak workers across subtests
func buildDirlpmObject(routes []route) any {
	return managedObject{mustBuild(dirlpm.New(entries(routes), routeupdate.Options{}))}
}

// ---------------------------------------------------------------- orderwalk

type orderwalkTable struct {
	mu      sync.Mutex
	current atomic.Pointer[orderwalk.Table[NextHop]]
	routes  map[netip.Prefix]NextHop
}

// Name is the immutable-walk table label
func (*orderwalkTable) Name() string { return "orderwalk" }

// Read loads the published table and Lookup
func (t *orderwalkTable) Read(addr netip.Addr) (NextHop, bool) {
	return t.current.Load().Lookup(addr)
}

// Reset replaces the authoritative map then publish()s
func (t *orderwalkTable) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = make(map[netip.Prefix]NextHop, len(routes))
	for _, r := range routes {
		t.routes[r.prefix.Masked()] = r.next
	}
	t.publish()
}

// Apply wraps a single change as a batch of one
func (t *orderwalkTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch mutates the map then rebuilds - orderwalk is immutable so every
// update is a full New
func (t *orderwalkTable) ApplyBatch(changes []mutation) {
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

// publish dumps the map into an entry slice and stores a new orderwalk table
func (t *orderwalkTable) publish() {
	built := make([]prefixentry.Entry[NextHop], 0, len(t.routes))
	for prefix, next := range t.routes {
		built = append(built, prefixentry.Entry[NextHop]{Prefix: prefix, Value: next})
	}
	t.current.Store(mustBuild(orderwalk.New(built)))
}

// Close is a no-op
func (t *orderwalkTable) Close() {}

// buildOrderwalkObject is the memory-bench artefact - compiled table, no
// mutation maps
func buildOrderwalkObject(routes []route) any { return mustBuild(orderwalk.New(entries(routes))) }
