package fibbench

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	// "github.com/iqhive/prefixlookup/old/arenaartset"
	// "github.com/iqhive/prefixlookup/old/coverartset"
	// "github.com/iqhive/prefixlookup/old/latticeartset"
	"github.com/iqhive/prefixlookup/old/arenaartlpm"
	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/old/bitfrontlpm"
	"github.com/iqhive/prefixlookup/old/bitlpm"
	"github.com/iqhive/prefixlookup/old/blocklpm"
	"github.com/iqhive/prefixlookup/old/fiborderwalk"

	// "github.com/iqhive/prefixlookup/rangeset"
	"github.com/iqhive/prefixlookup/artlpm"
	"github.com/iqhive/prefixlookup/artset"
	"github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/flatlpm"
	"github.com/iqhive/prefixlookup/flatset"
	"github.com/iqhive/prefixlookup/flatwalk"
	"github.com/iqhive/prefixlookup/groupartset"
	"github.com/iqhive/prefixlookup/old/bitwalk"
	"github.com/iqhive/prefixlookup/old/fibbitwalk"
	"github.com/iqhive/prefixlookup/old/lenlpm"
	"github.com/iqhive/prefixlookup/old/soarangeset"
	"github.com/iqhive/prefixlookup/old/thinrangeset"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/preorder2"
	"github.com/iqhive/prefixlookup/rangematch"
	"github.com/iqhive/prefixlookup/routeupdate"
	"github.com/iqhive/prefixlookup/splitribfib"
	"github.com/iqhive/prefixlookup/versioned"

	"github.com/aromatt/netipds"
	original "github.com/asergeyev/nradix"
	"github.com/gaissmai/bart"
	iqnradix "github.com/iqhive/nradix"
	"github.com/kentik/patricia"
	patricia32 "github.com/kentik/patricia/uint32_tree"
	iptrie "github.com/phemmer/go-iptrie"
	"github.com/yl2chen/cidranger"
	"tailscale.com/net/art"
)

type NextHop uint32

type route struct {
	prefix netip.Prefix
	next   NextHop
}

type mutation struct {
	prefix netip.Prefix
	next   NextHop
	remove bool
}

type fixture struct {
	routes       []route
	hot          []netip.Addr
	uniform      []netip.Addr
	cacheAdverse []netip.Addr
	depth        map[string][]netip.Addr
	updates      []mutation
}

type table interface {
	Name() string
	Reset([]route)
	Apply(mutation)
	ApplyBatch([]mutation)
	Read(netip.Addr) (NextHop, bool)
	Close()
}

type tableFactory struct {
	name           string
	new            func() table
	valueReturning bool
}

var fullFactories = []tableFactory{
	{"flatset", func() table { return new(flatsetTable) }, false},
	{"parityset", func() table { return new(paritysetTable) }, false},
	{"dirset", func() table { return new(dirsetTable) }, false},
	{"flatlpm", func() table { return new(flatlpmTable) }, true},
	{"steplpm", func() table { return new(steplpmTable) }, true},
	{"slotlpm", func() table { return new(slotlpmTable) }, true},
	{"dirlpm", func() table { return new(dirlpmTable) }, true},
	{"flatwalk", func() table { return new(flatwalkTable) }, true},
	{"soaart", func() table { return new(soaartTable) }, true},
	{"aosart", func() table { return new(aosartTable) }, true},
	{"orderwalk", func() table { return new(orderwalkTable) }, true},
	{"artwalk", func() table { return newRebuilding("artwalk", buildArtwalk) }, true},
	// {"latticeartset", func() table { return newRebuilding("latticeartset", buildLatticeartset) }, false},
	// {"coverartset", func() table { return newRebuilding("coverartset", buildCoverartset) }, false},
	// {"arenaartset", func() table { return newRebuilding("arenaartset", buildArenaartset) }, false},
	{"artset", func() table { return newRebuilding("artset", buildArtset) }, false},
	{"groupartset", func() table { return newRebuilding("groupartset", buildGroupartset) }, false},
	{"artlpm", func() table { return newRebuilding("artlpm", buildArtlpm) }, true},
	{"arenaartlpm", func() table { return newRebuilding("arenaartlpm", buildArenaartlpm) }, true},
	{"compiled-fib", func() table { return new(compiledFIBTable) }, true},
	{"fiborderwalk", func() table { return newRebuilding("fiborderwalk", buildFiborderwalk) }, true},
	{"preorder2", func() table { return new(preorder2Table) }, true},
	{"range-match", func() table { return newRebuilding("range-match", buildRangeMatch) }, false},
	{"soarangeset", func() table { return newRebuilding("soarangeset", buildSoarangeset) }, false},
	{"thinrangeset", func() table { return newRebuilding("thinrangeset", buildThinrangeset) }, false},
	{"split-rib-fib", func() table { return new(splitRIBFIBTable) }, true},
	// {"compiled-fib1", func() table { return newRebuilding("compiled-fib1", buildCompiled1) }, true},
	// {"split-rib-fib1", func() table { return newRebuilding("split-rib-fib1", buildFibbitwalk) }, true},
	// {"hybrid-fib", func() table { return newRebuilding("hybrid-fib", buildHybridFIB) }, true},
	// {"binary-trie", func() table { return newRebuilding("binary-trie", buildBinaryTrie) }, true},
	// {"walk-trie", func() table { return newRebuilding("walk-trie", buildWalkTrie) }, true},
	// {"sorted-prefix", func() table { return newRebuilding("sorted-prefix", buildSortedPrefix) }, true},
	// {"rangeset", func() table { return newRebuilding("rangeset", buildRangeset) }, false},
	{"iqhive-nradix-v1.0.13", func() table { return newRebuilding("iqhive-nradix-v1.0.13", buildLegacy) }, true},
	{"asergeyev-nradix-original", func() table { return newRebuilding("asergeyev-nradix-original", buildOriginal) }, true},
	{"versioned-fib", func() table {
		return newRebuilding("versioned-fib", buildVersioned(versioned.ModeFIB))
	}, true},
	{"versioned-rib", func() table {
		return newRebuilding("versioned-rib", buildVersioned(versioned.ModeRIB))
	}, true},
	{"versioned-hybrid", func() table {
		return newRebuilding("versioned-hybrid", buildVersioned(versioned.ModeHybrid))
	}, true},
	{"bart-table", func() table { return newRebuilding("bart-table", buildBART) }, true},
	{"bart-fast", func() table { return newRebuilding("bart-fast", buildBARTFast) }, true},
	{"bart-lite", func() table { return newRebuilding("bart-lite", buildBARTLite) }, false},
	// fairness addendum: BART behind the same concrete adapter the new
	// impls use, isolating the 6.7 ns newRebuilding harness tax
	{"bart-lite-direct", func() table { return newBARTLiteDirect() }, false},
	{"bart-table-direct", func() table { return newBARTTableDirect() }, true},

	{"tailscale-art", func() table { return newRebuilding("tailscale-art", buildART) }, true},
	{"go-iptrie", func() table { return newRebuilding("go-iptrie", buildIPTrie) }, true},
	{"kentik-patricia", func() table { return newRebuilding("kentik-patricia", buildPatricia) }, true},
	{"netipds", func() table { return newRebuilding("netipds", buildNetipDS) }, false},
	{"cidranger", func() table { return newRebuilding("cidranger", buildCIDRanger) }, false},
}

var defaultImplementations = map[string]struct{}{
	// Top boolean
	"dirset":       {},
	"dirlpm":       {},
	"parityset":    {},
	"flatset":      {},
	"thinrangeset": {},

	// Top LPM
	"compiled-fib": {},
	"slotlpm":      {},
	"flatlpm":      {},
	"steplpm":      {},

	// Top walkers
	"flatwalk":      {},
	"aosart":        {},
	"split-rib-fib": {},
	"soaart":        {},
	"preorder2":     {},
	"fiborderwalk":  {},

	// Superceded implementations:
	//
	// "orderwalk": {}, // fiborderwalk better on almost all dimensions
	// "artwalk":   {}, // no lookup, walk, or update leaf within 20%
	// "latticeartset":   {}, "coverartset": {}, "arenaartset": {},
	// "artset":      {}, // never first, never within 20%, never top-3
	// "groupartset": {}, // best leftover on a couple of generated membership rows, but those are 60%+ slower than dirset
	// "artlpm": {}, // fast BulkLoad() but never lands within 20% of a winner anywhere else
	// "binary-trie": {},
	// "arenaartlpm":  {}, // closest is real-table memory vs flatlpm (20%+ more)
	// "compiled-fib1": {}, // compiled-fib replaced this
	// "hybrid-fib": {},
	// "range-match": {},
	// "rangeset": {},
	// "soarangeset":  {}, // only ties thinrangeset on MembershipMemory/Scale/1000000, everywhere else it is the slower range layout
	// "sorted-prefix": {},
	// "split-rib-fib1": {},
	// "walk-trie": {},

	// Top competitors
	"bart-table": {}, "bart-fast": {}, "bart-lite": {},
	"bart-lite-direct": {}, "bart-table-direct": {},
	// "kentik-patricia": {},
	"netipds": {},
}

// useFullImplementationSet reads PREFIXLOOKUP_IMPLEMENTATIONS: empty/"default"
// is the short list, "full" is everything, anything else is a comma-separated
// allowlist so an iteration run doesn't pay for the whole matrix
func useFullImplementationSet() (bool, error) {
	switch set := os.Getenv("PREFIXLOOKUP_IMPLEMENTATIONS"); set {
	case "", "default":
		return false, nil
	case "full":
		return true, nil
	default:
		// any other value is a comma-separated allowlist - keeps an iteration
		// run to the handful of impls under comparison instead of the whole
		// default set
		allowed := make(map[string]struct{})
		for _, name := range strings.Split(set, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			allowed[name] = struct{}{}
		}
		if len(allowed) == 0 {
			return false, fmt.Errorf("PREFIXLOOKUP_IMPLEMENTATIONS must be default, full, or a comma-separated list, got %q", set)
		}
		known := make(map[string]struct{}, len(fullFactories)+len(fullMemoryFactories))
		for _, factory := range fullFactories {
			known[factory.name] = struct{}{}
		}
		for _, factory := range fullMemoryFactories {
			known[factory.name] = struct{}{}
		}
		for name := range allowed {
			if _, ok := known[name]; !ok {
				return false, fmt.Errorf("PREFIXLOOKUP_IMPLEMENTATIONS names unknown implementation %q", name)
			}
		}
		defaultImplementations = allowed
		return false, nil
	}
}

// selectTableFactories is the lookup-bench filter - full returns all, else
// we keep names that sit in defaultImplementations (which the allowlist
// path overwrites)
func selectTableFactories(all []tableFactory, full bool) []tableFactory {
	if full {
		return all
	}
	selected := make([]tableFactory, 0, len(defaultImplementations))
	for _, factory := range all {
		if _, ok := defaultImplementations[factory.name]; ok {
			selected = append(selected, factory)
		}
	}
	return selected
}

var factories []tableFactory

type memoryFactory struct {
	name  string
	build func([]route) any
}

// printBenchmarkManifest dumps leaf counts for run-bench2.sh so we don't
// have to run every bench once just to discover sub-benchmark names
func printBenchmarkManifest() {
	factoryCount := len(factories)
	memoryFactoryCount := len(memoryFactories)
	counts := map[string]int{
		"BenchmarkComparativeParallel": 2 * 4 * factoryCount,
		"BenchmarkQueryDistributions":  3 * factoryCount,
		"BenchmarkFamilyMixes":         3 * factoryCount,
		"BenchmarkTraversal":           8,
		"BenchmarkFIB":                 2 * factoryCount * (3*4 + 3),
		"BenchmarkMixedReadWrite":      4 * factoryCount,
		"BenchmarkScaleSweep":          3 * factoryCount,
		"BenchmarkBulkLoad":            factoryCount,
		"BenchmarkUpdateBatches":       3 * factoryCount,
		"BenchmarkConvergenceStorm":    4 * factoryCount,
		"BenchmarkMemory":              2 * memoryFactoryCount,
		"BenchmarkMembershipMemory":    4 * len(membershipMemoryFactories()),
		// "BenchmarkComparativeSerial":      3 * factoryCount, //
		// "BenchmarkIPv6":                   factoryCount,           //
		// "BenchmarkComparativeMemory":      2 * memoryFactoryCount, //
		// "BenchmarkComparativeBuild":       factoryCount,           //
		// "BenchmarkGCPressure":             memoryFactoryCount,     //
		// "BenchmarkLookupBySize":           3, //
		// "BenchmarkLookupNodePrefixBySize": 3, //
		// "BenchmarkBuildBySize":            3, //
		// "BenchmarkWalkV4BySize":           3, //
		// "BenchmarkRetainedMemoryBySize":   3, //
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("BENCHMARK_COUNT %s %d\n", name, counts[name])
	}
}

var fullMemoryFactories = []memoryFactory{
	{"flatset", buildFlatsetObject},
	{"parityset", buildParitysetObject},
	{"flatlpm", buildFlatlpmObject},
	{"steplpm", buildSteplpmObject},
	{"slotlpm", buildSlotlpmObject},
	{"flatwalk", buildFlatwalkObject},
	{"dirlpm", buildDirlpmObject},
	{"dirset", buildDirsetObject},
	{"orderwalk", buildOrderwalkObject},
	{"soaart", buildSoaartObject},
	{"aosart", buildAosartObject},
	{"compiled2", buildCompiled2Object},
	{"preorder2", buildFiborderwalk2Object},
	{"split-rib-fib2", buildSplitRIBFIB2Object},
	{"compiled-fib", buildCompiled1Object},
	{"split-rib-fib", buildFibbitwalkObject},
	{"fiborderwalk", buildFiborderwalkObject},
	{"hybrid-fib", buildBitfrontlpmObject},
	{"binary-trie", buildBitlpmObject},
	{"walk-trie", buildBitwalkObject},
	{"sorted-prefix", buildLenlpmObject},
	{"range-match", buildRangeMatchObject},
	// {"rangeset", buildRangesetObject},
	{"soarangeset", buildSoarangesetObject},
	{"thinrangeset", buildThinrangesetObject},
	{"iqhive-nradix-v1.0.13", buildLegacyObject},
	{"asergeyev-nradix-original", buildOriginalObject},
	{"artlpm", buildArtlpmObject},
	// {"latticeartset", buildLatticeartsetObject},
	// {"coverartset", buildCoverartsetObject},
	// {"arenaartset", buildArenaartsetObject},
	{"artset", buildArtsetObject},
	{"groupartset", buildGroupartsetObject},
	{"arenaartlpm", buildArenaartlpmObject},
	{"artwalk", buildArtwalkObject},
	{"versioned-fib", buildVersionedObject(versioned.ModeFIB)},
	{"versioned-rib", buildVersionedObject(versioned.ModeRIB)},
	{"versioned-hybrid", buildVersionedObject(versioned.ModeHybrid)},
	{"bart-table", buildBARTObject},
	{"bart-fast", buildBARTFastObject},
	{"bart-lite", buildBARTLiteObject},
	{"bart-lite-direct", buildBARTLiteObject},
	{"tailscale-art", buildARTObject},
	{"go-iptrie", buildIPTrieObject},
	{"kentik-patricia", buildPatriciaObject},
	{"netipds", buildNetipDSObject},
	{"cidranger", buildCIDRangerObject},
}

// selectMemoryFactories is the same filter for the retained-bytes factories
func selectMemoryFactories(all []memoryFactory, full bool) []memoryFactory {
	if full {
		return all
	}
	selected := make([]memoryFactory, 0, len(defaultImplementations))
	for _, factory := range all {
		if _, ok := defaultImplementations[factory.name]; ok {
			selected = append(selected, factory)
		}
	}
	return selected
}

var memoryFactories []memoryFactory

// TestMain wires PREFIXLOOKUP_IMPLEMENTATIONS into factories/memoryFactories,
// optionally prints the manifest and bails, otherwise runs the suite
func TestMain(m *testing.M) {
	full, err := useFullImplementationSet()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	factories = selectTableFactories(fullFactories, full)
	memoryFactories = selectMemoryFactories(fullMemoryFactories, full)
	if os.Getenv("PREFIXLOOKUP_BENCHMARK_MANIFEST") != "" {
		printBenchmarkManifest()
		return
	}
	os.Exit(m.Run())
}

type lookupTable interface {
	Lookup(netip.Addr) (NextHop, bool)
}

type rebuildingTable struct {
	name   string
	build  func([]route) lookupTable
	mu     sync.Mutex
	routes map[netip.Prefix]NextHop
	value  atomic.Value
}

// newRebuilding is the slow adapter for impls that can only rebuild from a
// prefix dump - we keep an authoritative map, rebuild on every mutation,
// publish through atomic.Value (that's the 6.7 ns tax the concrete adapters
// exist to avoid)
func newRebuilding(name string, build func([]route) lookupTable) *rebuildingTable {
	return &rebuildingTable{name: name, build: build, routes: make(map[netip.Prefix]NextHop)}
}

// Name is the bench-subtest label we stored at construction
func (t *rebuildingTable) Name() string { return t.name }

// Read loads the published lookupTable and Lookup - interface assertion
// every time, that's the tax
func (t *rebuildingTable) Read(addr netip.Addr) (NextHop, bool) {
	return t.value.Load().(lookupTable).Lookup(addr)
}

// Reset replaces the authoritative map then publish()s
func (t *rebuildingTable) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.routes)
	for _, route := range routes {
		t.routes[route.prefix.Masked()] = route.next
	}
	t.publish()
}

// Apply wraps a single change as a batch of one
func (t *rebuildingTable) Apply(change mutation) {
	t.ApplyBatch([]mutation{change})
}

// ApplyBatch mutates the map then rebuilds the whole table
func (t *rebuildingTable) ApplyBatch(changes []mutation) {
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

// Close is a no-op - rebuilt tables don't own a worker
func (t *rebuildingTable) Close() {}

// publish dumps the map into a route slice and stores build()'s result
func (t *rebuildingTable) publish() {
	routes := make([]route, 0, len(t.routes))
	for prefix, next := range t.routes {
		routes = append(routes, route{prefix, next})
	}
	t.value.Store(t.build(routes))
}

type lookupFunc func(netip.Addr) (NextHop, bool)

// Lookup lets a naked func sit on lookupTable - we use this when wrapping
// competitor APIs that don't return (NextHop, bool) natively
func (f lookupFunc) Lookup(addr netip.Addr) (NextHop, bool) { return f(addr) }

// entries converts the bench dump into prefixentry.Entry for our constructors
func entries(routes []route) []prefixentry.Entry[NextHop] {
	result := make([]prefixentry.Entry[NextHop], len(routes))
	for i, route := range routes {
		result[i] = prefixentry.Entry[NextHop]{Prefix: route.prefix, Value: route.next}
	}
	return result
}

// routeMutations maps our mutation type onto routeupdate.Mutation for the
// managed tables
func routeMutations(changes []mutation) []routeupdate.Mutation[NextHop] {
	mutations := make([]routeupdate.Mutation[NextHop], len(changes))
	for i, change := range changes {
		mutations[i] = routeupdate.Mutation[NextHop]{Prefix: change.prefix, Value: change.next, Delete: change.remove}
	}
	return mutations
}

type compiledFIBTable struct{ table *compiledfib.Table[NextHop] }

// Name is hardcoded "compiled2" - that's the managed compiledfib, don't
// confuse it with the memory-bench "compiled-fib" label
func (*compiledFIBTable) Name() string { return "compiled2" }

// Reset closes any previous worker then New's from the dump
func (t *compiledFIBTable) Reset(routes []route) {
	if t.table != nil {
		t.table.Close()
	}
	t.table = mustBuild(compiledfib.New(entries(routes), routeupdate.Options{}))
}

// Read is a straight Lookup
func (t *compiledFIBTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply wraps a single change as a batch of one
func (t *compiledFIBTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch hands routeupdate mutations through to compiledfib
func (t *compiledFIBTable) ApplyBatch(changes []mutation) {
	if err := t.table.ApplyBatch(routeMutations(changes)); err != nil {
		panic(err)
	}
}

// Close stops the worker and nils the pointer so a later Reset doesn't
// double-close
func (t *compiledFIBTable) Close() {
	if t.table != nil {
		t.table.Close()
		t.table = nil
	}
}

// flatsetTable and flatwalkTable hold their immutable value behind an atomic
// pointer rather than going through rebuildingTable, whose atomic.Value load
// and second interface dispatch would be charged to the impl
type flatsetTable struct {
	mu      sync.Mutex
	current atomic.Pointer[flatset.Set]
	routes  map[netip.Prefix]NextHop
}

// Name is the membership-set label
func (*flatsetTable) Name() string { return "flatset" }

// Read is Contains with dummy NextHop 1 - membership only
func (t *flatsetTable) Read(addr netip.Addr) (NextHop, bool) {
	return 1, t.current.Load().Contains(addr)
}

// Reset replaces the authoritative map then publish()s a new set
func (t *flatsetTable) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = make(map[netip.Prefix]NextHop, len(routes))
	for _, r := range routes {
		t.routes[r.prefix.Masked()] = r.next
	}
	t.publish()
}

// Apply wraps a single change as a batch of one
func (t *flatsetTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch mutates the map then rebuilds - flatset is immutable
func (t *flatsetTable) ApplyBatch(changes []mutation) {
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

// publish snapshots prefixes and stores a new flatset
func (t *flatsetTable) publish() {
	prefixes := make([]netip.Prefix, 0, len(t.routes))
	for prefix := range t.routes {
		prefixes = append(prefixes, prefix)
	}
	t.current.Store(mustBuild(flatset.New(prefixes)))
}

// Close is a no-op
func (t *flatsetTable) Close() {}

// buildFlatsetObject is the memory-bench artefact - compiled set, no maps
func buildFlatsetObject(routes []route) any {
	prefixes := make([]netip.Prefix, len(routes))
	for i, r := range routes {
		prefixes[i] = r.prefix
	}
	return mustBuild(flatset.New(prefixes))
}

type flatwalkTable struct {
	mu      sync.Mutex
	current atomic.Pointer[flatwalk.Table[NextHop]]
	routes  map[netip.Prefix]NextHop
}

// Name is the immutable-walk label
func (*flatwalkTable) Name() string { return "flatwalk" }

// Read loads the published table and Lookup
func (t *flatwalkTable) Read(addr netip.Addr) (NextHop, bool) {
	return t.current.Load().Lookup(addr)
}

// Reset replaces the map then publish()s
func (t *flatwalkTable) Reset(routes []route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = make(map[netip.Prefix]NextHop, len(routes))
	for _, r := range routes {
		t.routes[r.prefix.Masked()] = r.next
	}
	t.publish()
}

// Apply wraps a single change as a batch of one
func (t *flatwalkTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch mutates the map then rebuilds - flatwalk is immutable
func (t *flatwalkTable) ApplyBatch(changes []mutation) {
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

// publish dumps the map into entries and stores a new flatwalk table
func (t *flatwalkTable) publish() {
	entries := make([]prefixentry.Entry[NextHop], 0, len(t.routes))
	for prefix, next := range t.routes {
		entries = append(entries, prefixentry.Entry[NextHop]{Prefix: prefix, Value: next})
	}
	t.current.Store(mustBuild(flatwalk.New(entries)))
}

// Close is a no-op
func (t *flatwalkTable) Close() {}

// buildFlatwalkObject is the memory-bench artefact
func buildFlatwalkObject(routes []route) any { return mustBuild(flatwalk.New(entries(routes))) }

type flatlpmTable struct{ table *flatlpm.Table[NextHop] }

// Name is the managed LPM label
func (*flatlpmTable) Name() string { return "flatlpm" }

// Reset closes any previous worker then New's from the dump
func (t *flatlpmTable) Reset(routes []route) {
	if t.table != nil {
		t.table.Close()
	}
	t.table = mustBuild(flatlpm.New(entries(routes), routeupdate.Options{}))
}

// Read is a straight Lookup
func (t *flatlpmTable) Read(addr netip.Addr) (NextHop, bool) { return t.table.Lookup(addr) }

// Apply wraps a single change as a batch of one
func (t *flatlpmTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch hands routeupdate mutations through
func (t *flatlpmTable) ApplyBatch(changes []mutation) {
	if err := t.table.ApplyBatch(routeMutations(changes)); err != nil {
		panic(err)
	}
}

// Close stops the worker and nils the pointer
func (t *flatlpmTable) Close() {
	if t.table != nil {
		t.table.Close()
		t.table = nil
	}
}

// buildFlatlpmObject wraps the managed table so BenchmarkMemory will Close it
func buildFlatlpmObject(routes []route) any {
	return managedObject{mustBuild(flatlpm.New(entries(routes), routeupdate.Options{}))}
}

type preorder2Table struct{ table *preorder2.Table[NextHop] }

// Name is the preorder2 managed-table label
func (*preorder2Table) Name() string { return "preorder2" }

// Reset closes any previous worker then New's from the dump
func (t *preorder2Table) Reset(routes []route) {
	if t.table != nil {
		t.table.Close()
	}
	t.table = mustBuild(preorder2.New(entries(routes), routeupdate.Options{}))
}

// Read strips the route id preorder2 returns
func (t *preorder2Table) Read(addr netip.Addr) (NextHop, bool) {
	_, value, ok := t.table.Lookup(addr)
	return value, ok
}

// Apply wraps a single change as a batch of one
func (t *preorder2Table) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch hands routeupdate mutations through
func (t *preorder2Table) ApplyBatch(changes []mutation) {
	if err := t.table.ApplyBatch(routeMutations(changes)); err != nil {
		panic(err)
	}
}

// Close stops the worker and nils the pointer
func (t *preorder2Table) Close() {
	if t.table != nil {
		t.table.Close()
		t.table = nil
	}
}

type splitRIBFIBTable struct{ table *splitribfib.Table[NextHop] }

// Name still says split-rib-fib2 - that's the current splitribfib package
func (*splitRIBFIBTable) Name() string { return "split-rib-fib2" }

// Reset closes any previous worker then New's from the dump
func (t *splitRIBFIBTable) Reset(routes []route) {
	if t.table != nil {
		t.table.Close()
	}
	t.table = mustBuild(splitribfib.New(entries(routes), routeupdate.Options{}))
}

// Read strips the route id
func (t *splitRIBFIBTable) Read(addr netip.Addr) (NextHop, bool) {
	_, value, ok := t.table.Lookup(addr)
	return value, ok
}

// Apply wraps a single change as a batch of one
func (t *splitRIBFIBTable) Apply(change mutation) { t.ApplyBatch([]mutation{change}) }

// ApplyBatch hands routeupdate mutations through
func (t *splitRIBFIBTable) ApplyBatch(changes []mutation) {
	if err := t.table.ApplyBatch(routeMutations(changes)); err != nil {
		panic(err)
	}
}

// Close stops the worker and nils the pointer
func (t *splitRIBFIBTable) Close() {
	if t.table != nil {
		t.table.Close()
		t.table = nil
	}
}

type managedLookup interface {
	Close()
}

type managedObject struct{ managedLookup }

// Close is the memory-bench hook so we actually stop managed workers
func (o managedObject) Close() { o.managedLookup.Close() }

// buildCompiled2Object is compiledfib wrapped so the memory bench Closes the worker
func buildCompiled2Object(routes []route) any {
	return managedObject{mustBuild(compiledfib.New(entries(routes), routeupdate.Options{}))}
}

// buildFiborderwalk2Object is preorder2 wrapped the same way - name's leftover
// from when this was fiborderwalk2
func buildFiborderwalk2Object(routes []route) any {
	return managedObject{mustBuild(preorder2.New(entries(routes), routeupdate.Options{}))}
}

// buildSplitRIBFIB2Object is splitribfib wrapped for the memory bench
func buildSplitRIBFIB2Object(routes []route) any {
	return managedObject{mustBuild(splitribfib.New(entries(routes), routeupdate.Options{}))}
}

// buildCompiled1 wraps blocklpm as lookupTable for newRebuilding
func buildCompiled1(routes []route) lookupTable {
	return lookupFunc(buildCompiled1Object(routes).(*blocklpm.Table[NextHop]).Lookup)
}

// buildCompiled1Object constructs blocklpm for the memory bench
func buildCompiled1Object(routes []route) any {
	t, err := blocklpm.New(entries(routes))
	if err != nil {
		panic(err)
	}
	return t
}

// buildFibbitwalk wraps fibbitwalk, stripping the extra id on Lookup
func buildFibbitwalk(routes []route) lookupTable {
	t := buildFibbitwalkObject(routes).(*fibbitwalk.Table[NextHop])
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { _, v, ok := t.Lookup(a); return v, ok })
}

// buildFibbitwalkObject constructs fibbitwalk for the memory bench
func buildFibbitwalkObject(routes []route) any {
	t, err := fibbitwalk.New(entries(routes))
	if err != nil {
		panic(err)
	}
	return t
}

// buildFiborderwalk wraps fiborderwalk, stripping the extra id
func buildFiborderwalk(routes []route) lookupTable {
	t := buildFiborderwalkObject(routes).(*fiborderwalk.Table[NextHop])
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { _, v, ok := t.Lookup(a); return v, ok })
}

// buildFiborderwalkObject constructs fiborderwalk for the memory bench
func buildFiborderwalkObject(routes []route) any {
	t, err := fiborderwalk.New(entries(routes))
	if err != nil {
		panic(err)
	}
	return t
}

// buildHybridFIB wraps bitfrontlpm as lookupTable - "hybrid" is the old name
func buildHybridFIB(routes []route) lookupTable {
	return lookupFunc(buildBitfrontlpmObject(routes).(*bitfrontlpm.Table[NextHop]).Lookup)
}

// buildBitfrontlpmObject constructs bitfrontlpm for the memory bench
func buildBitfrontlpmObject(routes []route) any { return mustBuild(bitfrontlpm.New(entries(routes))) }

// buildBinaryTrie wraps bitlpm as lookupTable
func buildBinaryTrie(routes []route) lookupTable {
	return lookupFunc(buildBitlpmObject(routes).(*bitlpm.Table[NextHop]).Lookup)
}

// buildBitlpmObject constructs bitlpm for the memory bench
func buildBitlpmObject(routes []route) any { return mustBuild(bitlpm.New(entries(routes))) }

// buildWalkTrie wraps bitwalk as lookupTable
func buildWalkTrie(routes []route) lookupTable {
	return lookupFunc(buildBitwalkObject(routes).(*bitwalk.Table[NextHop]).Lookup)
}

// buildBitwalkObject constructs bitwalk for the memory bench
func buildBitwalkObject(routes []route) any { return mustBuild(bitwalk.New(entries(routes))) }

// buildSortedPrefix wraps lenlpm as lookupTable
func buildSortedPrefix(routes []route) lookupTable {
	return lookupFunc(buildLenlpmObject(routes).(*lenlpm.Table[NextHop]).Lookup)
}

// buildLenlpmObject constructs lenlpm for the memory bench
func buildLenlpmObject(routes []route) any { return mustBuild(lenlpm.New(entries(routes))) }

// buildRangeMatch wraps rangematch - dummy NextHop 1, membership only
func buildRangeMatch(routes []route) lookupTable {
	s := buildRangeMatchObject(routes).(*rangematch.Set)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Match(a); return 1, ok })
}

// buildRangeMatchObject constructs rangematch for the memory bench
func buildRangeMatchObject(routes []route) any {
	prefixes := make([]netip.Prefix, len(routes))
	for i, route := range routes {
		prefixes[i] = route.prefix
	}
	return mustBuild(rangematch.New(prefixes))
}

//	func buildRangeset(routes []route) lookupTable {
//		s := buildRangesetObject(routes).(*rangeset.Set)
//		return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Match(a); return 1, ok })
//	}
//
//	func buildRangesetObject(routes []route) any {
//		prefixes := make([]netip.Prefix, len(routes))
//		for i, route := range routes {
//			prefixes[i] = route.prefix
//		}
//		return mustBuild(rangeset.New(prefixes))
//	}
//
// buildSoarangeset wraps soarangeset as membership-only lookupTable
func buildSoarangeset(routes []route) lookupTable {
	s := buildSoarangesetObject(routes).(*soarangeset.Set)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Match(a); return 1, ok })
}

// buildSoarangesetObject constructs soarangeset for the memory bench
func buildSoarangesetObject(routes []route) any {
	prefixes := make([]netip.Prefix, len(routes))
	for i, route := range routes {
		prefixes[i] = route.prefix
	}
	return mustBuild(soarangeset.New(prefixes))
}

// buildThinrangeset wraps thinrangeset as membership-only lookupTable
func buildThinrangeset(routes []route) lookupTable {
	s := buildThinrangesetObject(routes).(*thinrangeset.Set)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Match(a); return 1, ok })
}

// buildThinrangesetObject constructs thinrangeset for the memory bench
func buildThinrangesetObject(routes []route) any {
	prefixes := make([]netip.Prefix, len(routes))
	for i, route := range routes {
		prefixes[i] = route.prefix
	}
	return mustBuild(thinrangeset.New(prefixes))
}

// mustBuild panics on constructor error - benches can't usefully continue
func mustBuild[T any](value *T, err error) *T {
	if err != nil {
		panic(err)
	}
	return value
}

// buildLegacy wraps iqhive/nradix as lookupTable - nil or err is a miss
func buildLegacy(routes []route) lookupTable {
	t := buildLegacyObject(routes).(*iqnradix.Tree)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) {
		v, err := t.FindCIDRNetIPAddr(a)
		if err != nil || v == nil {
			return 0, false
		}
		return v.(NextHop), true
	})
}

// buildLegacyObject fills an nradix tree from the dump for the memory bench
func buildLegacyObject(routes []route) any {
	t := iqnradix.NewTree(0)
	for _, r := range routes {
		if err := t.SetCIDRNetIPPrefix(r.prefix, r.next, true); err != nil {
			panic(err)
		}
	}
	return t
}

// buildOriginal wraps asergeyev/nradix - v4 and v6 trees, string CIDR API,
// 4-in-6 goes to the v4 tree
func buildOriginal(routes []route) lookupTable {
	t := buildOriginalObject(routes).(*originalTables)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) {
		tree := t.v6
		if a.Is4() || a.Is4In6() {
			tree = t.v4
		}
		v, err := tree.FindCIDR(a.String())
		if err != nil || v == nil {
			return 0, false
		}
		return v.(NextHop), true
	})
}

type originalTables struct {
	v4 *original.Tree
	v6 *original.Tree
}

// buildOriginalObject fills the pair of asergeyev trees
func buildOriginalObject(routes []route) any {
	t := &originalTables{v4: original.NewTree(0), v6: original.NewTree(0)}
	for _, r := range routes {
		tree := t.v6
		if r.prefix.Addr().Is4() {
			tree = t.v4
		}
		if err := tree.SetCIDR(r.prefix.String(), r.next); err != nil {
			panic(err)
		}
	}
	return t
}

// buildArtlpm wraps artlpm as lookupTable
func buildArtlpm(routes []route) lookupTable {
	t := buildArtlpmObject(routes).(*artlpm.Table[NextHop])
	return lookupFunc(t.Lookup)
}

// buildArtlpmObject inserts then BuildFront - without the front table we'd
// be measuring a different structure
func buildArtlpmObject(routes []route) any {
	t := artlpm.New[NextHop]()
	for _, r := range routes {
		t.Insert(r.prefix, r.next)
	}
	t.BuildFront()
	return t
}

//	func buildLatticeartset(routes []route) lookupTable {
//		s := buildLatticeartsetObject(routes).(*artset.Set)
//		return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Contains(a); return 1, ok })
//	}
//
//	func buildLatticeartsetObject(routes []route) any {
//		s := artset.New()
//		for _, r := range routes {
//			s.Insert(r.prefix)
//		}
//		return s
//	}
//
//	func buildCoverartset(routes []route) lookupTable {
//		s := buildCoverartsetObject(routes).(*coverartset.Set)
//		return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Contains(a); return 1, ok })
//	}
//
//	func buildCoverartsetObject(routes []route) any {
//		s := coverartset.New()
//		for _, r := range routes {
//			s.Insert(r.prefix)
//		}
//		return s
//	}
//
//	func buildArenaartset(routes []route) lookupTable {
//		s := buildArenaartsetObject(routes).(*arenaartset.Set)
//		return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Contains(a); return 1, ok })
//	}
//
//	func buildArenaartsetObject(routes []route) any {
//		s := arenaartset.New()
//		for _, r := range routes {
//			s.Insert(r.prefix)
//		}
//		return s
//	}

// buildArtset wraps artset as membership-only lookupTable
func buildArtset(routes []route) lookupTable {
	s := buildArtsetObject(routes).(*artset.Set)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Contains(a); return 1, ok })
}

// buildArtsetObject fills an artset for the memory bench
func buildArtsetObject(routes []route) any {
	s := artset.New()
	for _, r := range routes {
		s.Insert(r.prefix)
	}
	return s
}

// buildGroupartset wraps groupartset as membership-only lookupTable
func buildGroupartset(routes []route) lookupTable {
	s := buildGroupartsetObject(routes).(*groupartset.Set)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := s.Contains(a); return 1, ok })
}

// buildGroupartsetObject fills a groupartset for the memory bench
func buildGroupartsetObject(routes []route) any {
	s := groupartset.New()
	for _, r := range routes {
		s.Insert(r.prefix)
	}
	return s
}

// buildArenaartlpm wraps arenaartlpm as lookupTable
func buildArenaartlpm(routes []route) lookupTable {
	c := buildArenaartlpmObject(routes).(*arenaartlpm.Table[NextHop])
	return lookupFunc(c.Lookup)
}

// buildArenaartlpmObject inserts then Rebuild so we're measuring the compact
// table, not the mutable one with dead slots
func buildArenaartlpmObject(routes []route) any {
	c := arenaartlpm.New[NextHop]()
	for _, r := range routes {
		c.Insert(r.prefix, r.next)
	}
	return c.Rebuild()
}

// buildArtwalk wraps artwalk as lookupTable
func buildArtwalk(routes []route) lookupTable {
	r := buildArtwalkObject(routes).(*artwalk.Table[NextHop])
	return lookupFunc(r.Lookup)
}

// buildArtwalkObject fills an artwalk RIB for the memory bench
func buildArtwalkObject(routes []route) any {
	r := artwalk.New[NextHop]()
	for _, route := range routes {
		r.Insert(route.prefix, route.next)
	}
	return r
}

// buildVersioned returns a newRebuilding builder closed over mode
func buildVersioned(mode versioned.Mode) func([]route) lookupTable {
	return func(routes []route) lookupTable {
		s := buildVersionedObject(mode)(routes).(*versioned.Table[NextHop])
		return lookupFunc(s.Lookup)
	}
}

// buildVersionedObject loads via a single Update so we don't publish N times
func buildVersionedObject(mode versioned.Mode) func([]route) any {
	return func(routes []route) any {
		s := versioned.New[NextHop](mode)
		s.Update(func(w *versioned.Writer[NextHop]) {
			for _, route := range routes {
				w.Insert(route.prefix, route.next)
			}
		})
		return s
	}
}

// buildNetipDS wraps netipds - we special-case defaults because Encompasses
// on a /0 is weird, everything else is Encompasses||OverlapsPrefix on the host
func buildNetipDS(routes []route) lookupTable {
	s := buildNetipDSObject(routes).(*netipDSFinal)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) {
		if (a.Is4() || a.Is4In6()) && s.default4 || a.Is6() && !a.Is4In6() && s.default6 {
			return 1, true
		}
		host := netip.PrefixFrom(a, a.BitLen())
		ok := s.set.Encompasses(host) || s.set.OverlapsPrefix(host)
		return 1, ok
	})
}

type netipDSFinal struct {
	set                *netipds.PrefixSet
	default4, default6 bool
}

// buildNetipDSObject fills a PrefixSet and notes whether /0 exists per family
func buildNetipDSObject(routes []route) any {
	var builder netipds.PrefixSetBuilder
	result := &netipDSFinal{}
	for _, route := range routes {
		if err := builder.Add(route.prefix); err != nil {
			panic(err)
		}
		if route.prefix.Bits() == 0 {
			if route.prefix.Addr().Is4() {
				result.default4 = true
			} else {
				result.default6 = true
			}
		}
	}
	result.set = builder.PrefixSet()
	return result
}

// buildCIDRanger wraps cidranger - net.IP slice conversion every lookup, that's
// their API, we don't try to be clever
func buildCIDRanger(routes []route) lookupTable {
	r := buildCIDRangerObject(routes).(cidranger.Ranger)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) {
		ok, err := r.Contains(net.IP(a.AsSlice()))
		return 1, err == nil && ok
	})
}

// buildCIDRangerObject parses each prefix back to net.IPNet because that's
// what NewBasicRangerEntry wants
func buildCIDRangerObject(routes []route) any {
	r := cidranger.NewPCTrieRanger()
	for _, route := range routes {
		_, network, err := net.ParseCIDR(route.prefix.String())
		if err != nil {
			panic(err)
		}
		if err := r.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			panic(err)
		}
	}
	return r
}

// buildBART wraps gaissmai/bart.Table as lookupTable
func buildBART(routes []route) lookupTable {
	t := buildBARTObject(routes).(*bart.Table[NextHop])
	return lookupFunc(t.Lookup)
}

// buildBARTObject fills a bart.Table for the memory bench
func buildBARTObject(routes []route) any {
	t := new(bart.Table[NextHop])
	for _, r := range routes {
		t.Insert(r.prefix, r.next)
	}
	return t
}

// buildBARTFast wraps bart.Fast
func buildBARTFast(routes []route) lookupTable {
	t := buildBARTFastObject(routes).(*bart.Fast[NextHop])
	return lookupFunc(t.Lookup)
}

// buildBARTFastObject fills a bart.Fast for the memory bench
func buildBARTFastObject(routes []route) any {
	t := new(bart.Fast[NextHop])
	for _, r := range routes {
		t.Insert(r.prefix, r.next)
	}
	return t
}

// buildBARTLite wraps bart.Lite as membership-only lookupTable
func buildBARTLite(routes []route) lookupTable {
	l := buildBARTLiteObject(routes).(*bart.Lite)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) { ok := l.Lookup(a); return 1, ok })
}

// buildBARTLiteObject fills a bart.Lite for the memory bench
func buildBARTLiteObject(routes []route) any {
	l := new(bart.Lite)
	for _, r := range routes {
		l.Insert(r.prefix)
	}
	return l
}

// buildART wraps tailscale.com/net/art - Get not Lookup
func buildART(routes []route) lookupTable {
	t := buildARTObject(routes).(*art.Table[NextHop])
	return lookupFunc(t.Get)
}

// buildARTObject fills a tailscale ART table
func buildARTObject(routes []route) any {
	t := new(art.Table[NextHop])
	for _, r := range routes {
		t.Insert(r.prefix, r.next)
	}
	return t
}

// buildIPTrie wraps go-iptrie - nil Find is a miss, payload is NextHop
func buildIPTrie(routes []route) lookupTable {
	t := buildIPTrieObject(routes).(*iptrie.Trie)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) {
		v := t.Find(a)
		if v == nil {
			return 0, false
		}
		return v.(NextHop), true
	})
}

// buildIPTrieObject uses TrieLoader - that's the bulk-insert path they want
func buildIPTrieObject(routes []route) any {
	t := iptrie.NewTrie()
	loader := iptrie.NewTrieLoader(t)
	for _, r := range routes {
		loader.Insert(r.prefix, r.next)
	}
	return t
}

// buildPatricia wraps kentik/patricia - separate v4/v6 trees, host-order
// uint32 for v4 via flat4
func buildPatricia(routes []route) lookupTable {
	t := buildPatriciaObject(routes).(*patriciaTables)
	return lookupFunc(func(a netip.Addr) (NextHop, bool) {
		if a.Is4() {
			ok, v := t.v4.FindDeepestTag(patricia.NewIPv4Address(flat4(a), 32))
			return NextHop(v), ok
		}
		value := a.As16()
		ok, v := t.v6.FindDeepestTag(patricia.NewIPv6Address(value[:], 128))
		return NextHop(v), ok
	})
}

type patriciaTables struct {
	v4 *patricia32.TreeV4
	v6 *patricia32.TreeV6
}

// buildPatriciaObject fills the kentik v4+v6 pair
func buildPatriciaObject(routes []route) any {
	v4, v6 := patricia32.NewTreeV4(), patricia32.NewTreeV6()
	for _, r := range routes {
		if r.prefix.Addr().Is4() {
			v4.Set(patricia.NewIPv4Address(flat4(r.prefix.Addr()), uint(r.prefix.Bits())), uint32(r.next))
		} else {
			a := r.prefix.Addr().As16()
			v6.Set(patricia.NewIPv6Address(a[:], uint(r.prefix.Bits())), uint32(r.next))
		}
	}
	return &patriciaTables{v4: v4, v6: v6}
}

// flat4 packs a v4 netip.Addr into host-order uint32 for kentik
func flat4(addr netip.Addr) uint32 {
	a := addr.As4()
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

var fixtureCache sync.Map

// makeFixture builds the synthetic "not-quite-DFZ" table we use when we don't
// want genPrefixes - defaults plus `size` prefixes (every 8th is v6), three
// query streams (hot = first 256 cycling, uniform, cacheAdverse with a prime
// stride), plus depth buckets and a two-mutation overwrite pair
//
// this is the old internet-like shape: 10/8-ish v4, 2001:db8 v6, not the
// occupancy-faithful genPrefixes dump - we keep it because BenchmarkFIB's
// MatchDepth scenarios need the short/medium/long buckets
func makeFixture(size int) *fixture {
	if value, ok := fixtureCache.Load(size); ok {
		return value.(*fixture)
	}
	routes := make([]route, 0, size+2)
	routes = append(routes, route{netip.MustParsePrefix("0.0.0.0/0"), 1}, route{netip.MustParsePrefix("::/0"), 2})
	depth := map[string][]netip.Addr{"short": {}, "medium": {}, "long": {}}
	for i := 0; i < size; i++ {
		if i&7 == 0 {
			a := [16]byte{0x20, 1, 0xd, 0xb8, byte(i >> 16), byte(i >> 8), byte(i)}
			bits := 32 + i%97
			prefix := netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked()
			routes = append(routes, route{prefix, NextHop(i + 3)})
			bucket := "medium"
			if bits <= 48 {
				bucket = "short"
			} else if bits >= 96 {
				bucket = "long"
			}
			depth[bucket] = append(depth[bucket], prefix.Addr().Next())
		} else {
			a := [4]byte{10 + byte(i>>20), byte(i >> 12), byte(i >> 4), byte(i << 4)}
			bits := 8 + i%25
			prefix := netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
			routes = append(routes, route{prefix, NextHop(i + 3)})
			bucket := "medium"
			if bits <= 16 {
				bucket = "short"
			} else if bits >= 25 {
				bucket = "long"
			}
			depth[bucket] = append(depth[bucket], prefix.Addr().Next())
		}
	}
	uniform := make([]netip.Addr, 1<<14)
	for i := range uniform {
		uniform[i] = routes[2+(i*4051)%size].prefix.Addr().Next()
	}
	hot := make([]netip.Addr, len(uniform))
	for i := range hot {
		hot[i] = uniform[i&255]
	}
	cacheAdverse := make([]netip.Addr, len(uniform))
	for i := range cacheAdverse {
		cacheAdverse[i] = uniform[(i*7919)&(len(uniform)-1)]
	}
	for name, values := range depth {
		ring := make([]netip.Addr, 1024)
		for i := range ring {
			ring[i] = values[i%len(values)]
		}
		depth[name] = ring
	}
	updates := []mutation{{routes[len(routes)-1].prefix, 0xf001, false}, {routes[len(routes)-1].prefix, routes[len(routes)-1].next, false}}
	f := &fixture{routes, hot, uniform, cacheAdverse, depth, updates}
	actual, _ := fixtureCache.LoadOrStore(size, f)
	return actual.(*fixture)
}

var sink atomic.Uint64

// benchmarkReads is the lookup loop - 1 worker is a tight serial for, more
// uses b.RunParallel so Go's own scheduler shards it
//
// queries must be a power of two, we mask with (len-1)
func benchmarkReads(b *testing.B, t table, queries []netip.Addr, workers int) {
	old := runtime.GOMAXPROCS(workers)
	defer runtime.GOMAXPROCS(old)
	b.ReportAllocs()
	b.ResetTimer()
	if workers == 1 {
		var sum uint64
		for i := 0; i < b.N; i++ {
			v, ok := t.Read(queries[i&(len(queries)-1)])
			sum += uint64(v)
			if ok {
				sum++
			}
		}
		sink.Store(sum)
		return
	}
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		var sum uint64
		for pb.Next() {
			v, ok := t.Read(queries[i&(len(queries)-1)])
			sum += uint64(v)
			if ok {
				sum++
			}
			i++
		}
		sink.Add(sum)
	})
}

// BenchmarkFIB is the "software router forwarding plane" suite - Light (1k,
// cache-resident) vs Heavy (1M, is not), InternetHot (tiny working set) vs
// UniformRouted, 1 vs 32 workers, plus MatchDepth short/medium/long so a
// structure that cheats on /24s shows up on the long v6 probes
func BenchmarkFIB(b *testing.B) {
	loads := []struct {
		name string
		size int
	}{{"Light", 1_000}, {"Heavy", 1_000_000}}
	for _, load := range loads {
		f := makeFixture(load.size)
		for _, factory := range factories {
			b.Run(load.name+"/"+factory.name, func(b *testing.B) {
				t := factory.new()
				defer t.Close()
				t.Reset(f.routes)
				for _, scenario := range []struct {
					name    string
					queries []netip.Addr
				}{
					{"InternetHot", f.hot},
					{"UniformRouted", f.uniform},
					// {"CacheAdverse", f.cacheAdverse},
				} {
					for _, workers := range []int{1, 32} {
						b.Run(fmt.Sprintf("%s/%dx", scenario.name, workers), func(b *testing.B) { benchmarkReads(b, t, scenario.queries, workers) })
					}
				}
				for name, queries := range f.depth {
					b.Run("MatchDepth/"+name, func(b *testing.B) { benchmarkReads(b, t, queries, 1) })
				}
			})
		}
	}
}

// BenchmarkMixedReadWrite pretends we're forwarding while BGP is withdrawing
// - 100k table, one Apply overlapping N lookups (10M/1M/100k-to-1), we
// sample at most 1M reads per cycle so a 10M-to-1 run doesn't take forever
//
// we report both serialised and overlapped ns/read because some tables block
// lookups during Apply and some don't
func BenchmarkMixedReadWrite(b *testing.B) {
	f := makeFixture(100_000)
	for _, ratio := range []uint64{10_000_000, 1_000_000, 100_000} {
		for _, factory := range factories {
			b.Run(fmt.Sprintf("%d-to-1/%s", ratio, factory.name), func(b *testing.B) {
				t := factory.new()
				defer t.Close()
				t.Reset(f.routes)
				sampledReads := ratio
				if sampledReads > 1_000_000 {
					sampledReads = 1_000_000
				}

				var totalReadTime, totalWriteTime time.Duration
				var totalWallTime time.Duration
				var localSink uint64
				b.ReportAllocs()
				b.ResetTimer()
				for cycle := 0; cycle < b.N; cycle++ {
					start := make(chan struct{})
					writeDone := make(chan time.Duration, 1)
					go func(change mutation) {
						<-start
						started := time.Now()
						t.Apply(change)
						writeDone <- time.Since(started)
					}(f.updates[cycle&1])

					wallStarted := time.Now()
					close(start)
					readStarted := time.Now()
					for i := uint64(0); i < sampledReads; i++ {
						value, ok := t.Read(f.uniform[i&uint64(len(f.uniform)-1)])
						localSink += uint64(value)
						if ok {
							localSink++
						}
					}
					totalReadTime += time.Since(readStarted)
					totalWriteTime += <-writeDone
					totalWallTime += time.Since(wallStarted)
				}
				b.StopTimer()
				sink.Add(localSink)

				cycles := float64(max(b.N, 1))
				readNS := float64(totalReadTime.Nanoseconds()) / cycles / float64(sampledReads)
				writeNS := float64(totalWriteTime.Nanoseconds()) / cycles
				serializedNS := readNS + writeNS/float64(ratio)
				overlappedNS := max(readNS, writeNS/float64(ratio))
				b.ReportMetric(readNS, "read-ns")
				b.ReportMetric(writeNS, "write-ns")
				b.ReportMetric(float64(sampledReads), "sampled-reads/write")
				b.ReportMetric(serializedNS, "serialized-ns/read")
				b.ReportMetric(overlappedNS, "overlapped-ns/read")
				b.ReportMetric(1e9/overlappedNS, "sustainable-reads/s")
				b.ReportMetric(float64(totalWallTime.Nanoseconds())/cycles, "wall-ns/cycle")
			})
		}
	}
}

// BenchmarkScaleSweep is cacheAdverse lookups at 1k/100k/1M - we want the
// curve, not a single size, so a structure that falls off a cliff past L3
// is visible
func BenchmarkScaleSweep(b *testing.B) {
	for _, size := range []int{1_000, 100_000, 1_000_000} {
		f := makeFixture(size)
		for _, factory := range factories {
			b.Run(fmt.Sprintf("%d/%s", size, factory.name), func(b *testing.B) {
				t := factory.new()
				t.Reset(f.routes)
				benchmarkReads(b, t, f.cacheAdverse, 1)
				b.StopTimer()
				t.Close()
			})
		}
	}
}

// BenchmarkBulkLoad is Reset-from-empty at 100k - that's "reload the FIB
// after a process restart", not incremental BGP
func BenchmarkBulkLoad(b *testing.B) {
	f := makeFixture(100_000)
	for _, factory := range factories {
		b.Run(factory.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				t := factory.new()
				t.Reset(f.routes)
				t.Close()
			}
		})
	}
}

// BenchmarkUpdateBatches is ApplyBatch of 1/16/256 mutations on a 100k table
// - 1 is the "every BGP update is its own publish" case, 256 is what we'd
// coalesce toward
func BenchmarkUpdateBatches(b *testing.B) {
	f := makeFixture(100_000)
	for _, batch := range []int{1, 16, 256} {
		changes := make([]mutation, batch)
		for i := range changes {
			changes[i] = f.updates[i&1]
		}
		for _, factory := range factories {
			b.Run(fmt.Sprintf("Batch%d/%s", batch, factory.name), func(b *testing.B) {
				t := factory.new()
				t.Reset(f.routes)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					t.ApplyBatch(changes)
				}
				b.StopTimer()
				t.Close()
				b.ReportMetric(float64(batch), "mutations/op")
			})
		}
	}
}

// BenchmarkConvergenceStorm is a withdraw-then-restore of 64 prefixes on a
// 100k table - Atomic applies the whole storm as one batch, Individual is one
// mutation at a time (that's a naive BGP speaker)
func BenchmarkConvergenceStorm(b *testing.B) {
	f := makeFixture(64_000)
	storm := make([]mutation, 64)
	// storm's for yanking 50 prefixes out (goes from the end of f.routes back)
	restore := make([]mutation, len(storm))
	// restore is a parallel slice, going to bring those prefixes back
	for i := range storm {
		r := f.routes[len(f.routes)-1-i]
		// r grabs the last i-th route, so we work backwards through the entries
		storm[i] = mutation{prefix: r.prefix, remove: true}
		// this one's prepping a delete for each prefix
		restore[i] = mutation{prefix: r.prefix, next: r.next}
		// here, lining up each prefix for a restore with its original next-hop
	}
	for _, factory := range factories {
		for _, mode := range []struct {
			name  string
			chunk int
		}{
			{"Atomic", 256},
			// {"Chunk16", 16},
			// {"Chunk64", 64},
			{"Individual", 1}} {
			// chunk size 1 means we're sending one update at a time, like the worst-case
			b.Run(factory.name+"/"+mode.name, func(b *testing.B) {
				t := factory.new()
				t.Reset(f.routes)
				b.StopTimer()
				runtime.GC()
				b.StartTimer()
				b.ReportAllocs()
				for range b.N {
					for first := 0; first < len(storm); first += mode.chunk {
						// big move: run through storm slices in chunks (could be atomic or single)
						t.ApplyBatch(storm[first:min(first+mode.chunk, len(storm))])
						// send each chunk of the withdraw storm through
					}
					for first := 0; first < len(restore); first += mode.chunk {
						// same deal, but this time for restoring the prefixes
						t.ApplyBatch(restore[first:min(first+mode.chunk, len(restore))])
						// bring everything back chunk at a time
					}
				}
				b.StopTimer()
				t.Close()
			})
		}
	}
}

type cleanup interface{ Close() }

// closeObject Closes if the memory-bench artefact implements cleanup -
// managed tables need this or we leak workers
func closeObject(obj any) {
	if closer, ok := obj.(cleanup); ok {
		closer.Close()
	}
}

// retainedBytes is after-before with a floor of 0 so a GC that moved things
// the wrong way doesn't report a huge "negative" as uint wrap
func retainedBytes(before, after uint64) uint64 {
	if after <= before {
		return 0
	}
	return after - before
}

// membershipMemoryNames are the boolean sets. a default route collapses
// their index, so BenchmarkMemory on makeFixture is the minimum, not the
// scaling cost - BenchmarkMembershipMemory splits those two questions
var membershipMemoryNames = map[string]struct{}{
	"flatset":          {},
	"parityset":        {},
	"dirset":           {},
	"artset":           {},
	"groupartset":      {},
	"soarangeset":      {},
	"thinrangeset":     {},
	"range-match":      {},
	"bart-lite":        {},
	"bart-lite-direct": {},
	"netipds":          {},
	"cidranger":        {},
}

// membershipMemoryFactories is the memory-factory subset that answers
// membership, in the same order as memoryFactories so the bench names
// stay stable when the allowlist changes
func membershipMemoryFactories() []memoryFactory {
	out := make([]memoryFactory, 0, len(membershipMemoryNames))
	for _, factory := range memoryFactories {
		if _, ok := membershipMemoryNames[factory.name]; ok {
			out = append(out, factory)
		}
	}
	return out
}

// reportRetainedHeap is the GC / ReadMemStats / KeepAlive sandwich
// BenchmarkMembershipMemory uses - prefixes==0 skips the per-prefix
// metric, which is the Min case (two default routes, the interesting
// number is the absolute heap)
func reportRetainedHeap(b *testing.B, factory memoryFactory, routes []route, prefixes int) {
	b.Helper()
	b.StopTimer()
	// twice: Min is a few dozen bytes, and a single GC often leaves
	// enough slack that HeapAlloc moves by more than the Set itself
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	t := factory.build(routes)
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	retained := retainedBytes(before.HeapAlloc, after.HeapAlloc)
	b.ReportMetric(float64(retained), "retained-B")
	if prefixes > 0 {
		b.ReportMetric(float64(retained)/float64(prefixes), "retained-B/prefix")
	}
	b.ReportMetric(1, "measurements")
	runtime.KeepAlive(t)
	closeObject(t)
}

// BenchmarkMemory is retained heap at 1k/100k/1M - GC before and after
// build, KeepAlive so the compiler can't drop the table, closeObject so
// workers die
//
// makeFixture inserts 0.0.0.0/0 and ::/0, so every membership set on this
// bench is the collapsed minimum; BenchmarkMembershipMemory is the one
// that also measures the uncovered scaling cost
func BenchmarkMemory(b *testing.B) {
	for _, size := range []int{1_000, 100_000, 1_000_000} {
		f := makeFixture(size)
		for _, factory := range memoryFactories {
			b.Run(fmt.Sprintf("%d/%s", size, factory.name), func(b *testing.B) {
				b.StopTimer()
				// want a nice clean heap, run the GC up front so we're not counting old junk
				runtime.GC()
				var before runtime.MemStats
				// grab memory details before we build the table, so we can see what changes
				runtime.ReadMemStats(&before)
				t := factory.build(f.routes)
				// another GC to try shake out any unused memory after building
				runtime.GC()
				var after runtime.MemStats
				// righto, now snag memory stats again to compare with before
				runtime.ReadMemStats(&after)
				retained := retainedBytes(before.HeapAlloc, after.HeapAlloc)
				// chuck the main memory result into the benchmark output
				b.ReportMetric(float64(retained), "retained-B")
				// also handy to see how much per route/prefix, so divide it out
				b.ReportMetric(float64(retained)/float64(size), "retained-B/prefix")
				b.ReportMetric(1, "measurements")
				// make sure compiler doesn't sneakily drop our table before measuring
				runtime.KeepAlive(t)
				// close up shop and tidy resources after test
				closeObject(t)
			})
		}
	}
}

// BenchmarkMembershipMemory is min vs scaling retained heap for boolean
// membership sets
//
// Min is both default routes and nothing else: the index is dropped and
// what remains is the Set object. Scale is genPrefixes with no defaults,
// so the structure actually has to hold the union. Memory/100000 on
// makeFixture is Min in disguise, which is why those B/pfx figures look
// like zero
func BenchmarkMembershipMemory(b *testing.B) {
	factories := membershipMemoryFactories()
	if len(factories) == 0 {
		b.Skip("no membership memory factories in the current implementation set")
	}

	b.Run("Min", func(b *testing.B) {
		routes := []route{
			{netip.MustParsePrefix("0.0.0.0/0"), 1},
			{netip.MustParsePrefix("::/0"), 2},
		}
		for _, factory := range factories {
			b.Run(factory.name, func(b *testing.B) {
				reportRetainedHeap(b, factory, routes, 0)
			})
		}
	})

	b.Run("Scale", func(b *testing.B) {
		for _, size := range []int{1_000, 100_000, 1_000_000} {
			routes := routesFromPrefixes(genPrefixes(size, dfzV6Mix, 13))
			for _, factory := range factories {
				b.Run(fmt.Sprintf("%d/%s", size, factory.name), func(b *testing.B) {
					reportRetainedHeap(b, factory, routes, size)
				})
			}
		}
	})
}
