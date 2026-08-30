// Package versioned is implementation (5): the lock-free concurrent-reader
// wrapper around artlpm and artwalk
//
// this is what a 100k/s read-heavy workload should actually use. writers
// rebuild off to the side and publish with one atomic store
package versioned

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/artlpm"
)

// Mode selects what a Table builds, trading write cost and memory against
// read latency and query capability
type Mode int

const (
	// ModeFIB builds only the forwarding index: a Table for value lookups
	// smallest and fastest to publish, answers Lookup and Contains but not
	// the hierarchy queries
	ModeFIB Mode = iota

	// ModeRIB builds only the hierarchy-preserving index - it answers every
	// query including Supernets and Subnets, at a modestly higher Lookup cost
	// than ModeFIB because RIB nodes carry parent links and can't use the
	// register-resident IPv4 descent
	ModeRIB

	// ModeHybrid builds both, published together in one snapshot so they can
	// never disagree. reads take the fastest path available for each query
	// type: the FIB for Lookup and Contains, the RIB for hierarchy walking
	//
	// this is the recommended mode for a read-heavy workload that also needs
	// hierarchy queries. it costs roughly twice the memory of either alone and
	// the publication cost of both
	ModeHybrid
)

// Table is implementation (5): the hybrid, and the type a high-rate
// read-heavy workload should actually use
//
// the concurrency model, and why the mutex had to go:
//
// the legacy tree guards every read with sync.RWMutex.RLock. that's correct
// but it doesn't scale: RLock is an atomic read-modify-write on one shared
// word, so every reader on every core contends for the same cache line. the
// line ping-pongs between cores and the cost grows with core count. measured
// effect on this machine is a 21% per-op slowdown going from 1 to 64 readers
// - on a workload that's almost entirely reads and should have scaled
// perfectly flat
//
// we remove reader synchronisation entirely. the data structures are
// immutable once published, and readers reach them through a single
// atomic.Pointer load:
//
//   - a reader does one acquire load and then touches only immutable memory
//     there's no RMW, so no cache line is ever contended, and readers never
//     block, never spin, and never wait for a writer
//   - a writer builds a complete new generation off to the side and installs
//     it with one release store. readers in flight continue on the previous
//     generation and finish normally. Go's GC frees it once the last of them
//     has finished, which is exactly the reclamation problem that RCU and
//     hazard pointers exist to solve in C, and which the Go runtime solves
//     for free
//
// the trade: writes become far more expensive. each publication is O(n)
// because it rebuilds the whole index, against O(depth) for a mutation in
// place. that's the correct trade for the stated workload - reads outnumber
// writes by orders of magnitude - but it's the wrong one for a write-heavy
// table
//
// two mechanisms keep it practical. Update coalesces any number of mutations
// into one rebuild and one publication, so a burst of a thousand route
// changes costs one rebuild rather than a thousand. and writers are
// serialised by an ordinary mutex that readers never touch, so write
// serialisation never affects read latency
type Table[V any] struct {
	cur  atomic.Pointer[generation[V]]
	mu   sync.Mutex // serialises writers only, readers never acquire it
	mode Mode
}

// generation is one immutable published state
// both indexes are published together inside it, so a reader can never
// observe a FIB from one generation against a RIB from another
type generation[V any] struct {
	fib *artlpm.Table[V]
	rib *artwalk.Table[V]
	n   int
}

// New returns an empty table in the given mode
// we build the empty generation immediately so Load never sees nil
func New[V any](mode Mode) *Table[V] {
	s := &Table[V]{mode: mode}
	s.cur.Store(s.build(nil))
	return s
}

// build constructs a fresh generation containing the given prefixes
// FIB and/or RIB depending on mode. once the FIB is populated we BuildFront
// because the generation is immutable from here
func (s *Table[V]) build(entries []entry[V]) *generation[V] {
	g := &generation[V]{n: len(entries)}
	if s.mode == ModeFIB || s.mode == ModeHybrid {
		g.fib = artlpm.New[V]()
		for _, e := range entries {
			g.fib.Insert(e.pfx, e.val)
		}
		// generation is immutable from here, so the IPv4 accel table can be
		// built once and amortised over every read of it
		g.fib.BuildFront()
	}
	if s.mode == ModeRIB || s.mode == ModeHybrid {
		g.rib = artwalk.New[V]()
		for _, e := range entries {
			g.rib.Insert(e.pfx, e.val)
		}
	}
	return g
}

// entry is one prefix+value we stage in a Writer
type entry[V any] struct {
	pfx netip.Prefix
	val V
}

// -----------------------------------------------------------------------------
// Reads: wait-free, one atomic load, no locks
// -----------------------------------------------------------------------------

// Lookup does LPM. safe for unlimited concurrent use, never blocks a writer
// or another reader. we Load then hit the FIB if we have one, else the RIB
func (s *Table[V]) Lookup(addr netip.Addr) (val V, ok bool) {
	g := s.cur.Load()
	if g.fib != nil {
		return g.fib.Lookup(addr)
	}
	return g.rib.Lookup(addr)
}

// Contains reports whether any stored prefix covers addr
// FIB.Contains if we have a FIB, else RIB.Lookup and throw away the value
func (s *Table[V]) Contains(addr netip.Addr) bool {
	g := s.cur.Load()
	if g.fib != nil {
		return g.fib.Contains(addr)
	}
	_, ok := g.rib.Lookup(addr)
	return ok
}

// Size returns how many prefixes are in the current generation
// just Load().n, we store it so we don't have to walk
func (s *Table[V]) Size() int { return s.cur.Load().n }

// Supernets walks upward from addr through every covering prefix, longest first
// requires ModeRIB or ModeHybrid, no-op otherwise
//
// the whole walk runs against one generation, so the result is a consistent
// view even if a writer publishes concurrently
func (s *Table[V]) Supernets(addr netip.Addr, fn func(netip.Prefix, V) bool) {
	if g := s.cur.Load(); g.rib != nil {
		g.rib.Supernets(addr, fn)
	}
}

// Subnets walks downward through every prefix covered by pfx
// requires ModeRIB or ModeHybrid, no-op otherwise
//
// this is output-sensitive: a short prefix on a large table enumerates a large
// fraction of it, and the generation stays live for the duration. bound the
// result on a request path by returning false from fn
func (s *Table[V]) Subnets(pfx netip.Prefix, fn func(netip.Prefix, V) bool) {
	if g := s.cur.Load(); g.rib != nil {
		g.rib.Subnets(pfx, fn)
	}
}

// Parent returns the immediate covering prefix of pfx
// requires ModeRIB or ModeHybrid, otherwise we return false
func (s *Table[V]) Parent(pfx netip.Prefix) (netip.Prefix, V, bool) {
	var zero V
	g := s.cur.Load()
	if g.rib == nil {
		return netip.Prefix{}, zero, false
	}
	return g.rib.Parent(pfx)
}

// All calls fn for every stored prefix in the current generation
// we prefer the FIB walk if we have one (it's cheaper), else the RIB
func (s *Table[V]) All(fn func(netip.Prefix, V) bool) {
	g := s.cur.Load()
	if g.fib != nil {
		g.fib.All(fn)
		return
	}
	if g.rib != nil {
		g.rib.All(fn)
	}
}

// -----------------------------------------------------------------------------
// Writes: serialised, coalesced, published atomically
// -----------------------------------------------------------------------------

// Writer accumulates mutations to be published as a single new generation
// entries is the staged table, index is prefix->slot so Insert can overwrite
// in place. Delete tombstones with a zero prefix
type Writer[V any] struct {
	s       *Table[V]
	entries []entry[V]
	index   map[netip.Prefix]int
}

// Update runs fn against a Writer holding the current contents and publishes
// the result as one new generation
//
// every mutation made inside fn is applied to a private copy, readers continue
// to observe the previous generation until fn returns and the new generation
// is installed with a single atomic store. coalescing is the point: a thousand
// route changes inside one Update cost one O(n) rebuild, not a thousand
//
// concurrent Update calls are serialised. readers are never blocked by either
func (s *Table[V]) Update(fn func(w *Writer[V])) {
	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.cur.Load()
	w := &Writer[V]{
		s:       s,
		entries: make([]entry[V], 0, g.n+8),
		index:   make(map[netip.Prefix]int, g.n+8),
	}
	// materialise the current contents from whichever index exists
	collect := func(p netip.Prefix, v V) bool {
		w.index[p] = len(w.entries)
		w.entries = append(w.entries, entry[V]{p, v})
		return true
	}
	if g.fib != nil {
		g.fib.All(collect)
	} else if g.rib != nil {
		g.rib.All(collect)
	}

	fn(w)

	// drop tombstones left by Delete before building
	live := w.entries[:0]
	for _, e := range w.entries {
		if e.pfx.IsValid() {
			live = append(live, e)
		}
	}
	s.cur.Store(s.build(live))
}

// Insert stores val for pfx within the update
// Masked() first, then overwrite if we already have it, else append
func (w *Writer[V]) Insert(pfx netip.Prefix, val V) {
	pfx = pfx.Masked()
	if i, ok := w.index[pfx]; ok {
		w.entries[i].val = val
		return
	}
	w.index[pfx] = len(w.entries)
	w.entries = append(w.entries, entry[V]{pfx, val})
}

// Delete removes pfx within the update, reporting whether it was present
// we tombstone in place, Update compacts these out before building. removing
// from the slice here would invalidate every later index
func (w *Writer[V]) Delete(pfx netip.Prefix) bool {
	pfx = pfx.Masked()
	i, ok := w.index[pfx]
	if !ok {
		return false
	}
	// tombstone in place, Update compacts these out before building. removing
	// from the slice here would invalidate every later index
	w.entries[i].pfx = netip.Prefix{}
	delete(w.index, pfx)
	return true
}

// Size returns how many prefixes are currently staged in the update
// len of the index map, tombstones are already gone from it
func (w *Writer[V]) Size() int { return len(w.index) }

// Insert publishes a single prefix. convenience wrapper around Update, pays
// a full O(n) rebuild, so prefer batching with Update when applying more
// than one change
func (s *Table[V]) Insert(pfx netip.Prefix, val V) {
	s.Update(func(w *Writer[V]) { w.Insert(pfx, val) })
}

// Delete publishes the removal of a single prefix, reporting whether it was
// present. as with Insert, prefer Update for batches
func (s *Table[V]) Delete(pfx netip.Prefix) bool {
	var found bool
	s.Update(func(w *Writer[V]) { found = w.Delete(pfx) })
	return found
}
