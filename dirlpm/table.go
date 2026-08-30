// Package dirlpm is our value-returning LPM table shaped around a real
// BGP table rather than a generated one
//
// value-lookup specialist - flatlpm compresses every stride the same way,
// we split the two families and only spend memory where a full table's own
// distribution makes it cheap
//
// IPv4 is expanded - a collector's full table puts about thirty prefixes in
// each occupied /16 and 63% of them are /24, so expanding a /16 into a
// 256-entry array of value indices costs about 33 bytes per prefix and turns
// a lookup into two array indexes with no arithmetic at all - no bitmask, no
// rank, no popcount, no branch on prefix shape - fibbench's genPrefixes
// follows that occupancy, makeFixture does not
//
// IPv6 is compressed - a full table's IPv6 half occupies 66 of the 65536 /16
// blocks and is dominated by /48, so the same expansion would need a block
// at four successive strides and cost several hundred bytes per prefix
// IPv6 therefore keeps the flatart arena trie, that's where that structure
// is strongest
//
// Result: IPv4 in three dependent loads, IPv6 in four or five, at the cost
// of retaining more than flatlpm - pick flatlpm when footprint matters,
// pick this when it doesn't
package dirlpm

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iqhive/prefixlookup/internal/flatart"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// ErrClosed is what Submit returns once Close has started
var ErrClosed = errors.New("dirlpm: table closed")

// ErrTooLarge means we blew the 31-bit slot width - top bit is the block tag
var ErrTooLarge = errors.New("dirlpm: table exceeds 2^31 entries")

// top bit clear = value index, zero meaning no match
// otherwise it's the base of the next expanded block, already multiplied by
// blockSize so descending is an OR rather than a shift - don't change that,
// lookup4 relies on it
const (
	tagBlock  = 0x8000_0000
	blockSize = 256
	maxSlot   = tagBlock - 1
)

// generation is one immutable published state
type generation[V any] struct {
	// IPv4: 16-bit root over expanded 256-entry blocks for /17../24 and,
	// where needed, a third level for /25../32
	root4  []uint32
	level2 []uint32
	level3 []uint32
	value4 []V

	// IPv6: compressed arena trie, we don't expand this family
	index6 flatart.Index
	value6 []V

	// exact4 holds every IPv4 prefix as key<<8|bits, sorted - a prefix's value
	// index is its position plus one, so the array answers Exact and doubles
	// as the catalogue a structural rebuild reads - no map, no second value
	// table, don't split them
	exact4 []uint64

	number uint64
}

type request[V any] struct {
	mutations []routeupdate.Mutation[V]
	done      chan routeupdate.Result
}

// Stats is a snapshot of successful publications, split by whether we
// rebuilt the forwarding structures or just swapped values
type Stats struct {
	PayloadPublications    uint64
	StructuralPublications uint64
}

// Table is the lock-free value lookup we publish from one dedicated writer
// readers only ever see an atomic pointer to a generation
type Table[V any] struct {
	current atomic.Pointer[generation[V]]
	queue   chan request[V]
	stop    chan struct{}
	done    chan struct{}
	options routeupdate.Options

	submitMu  sync.Mutex
	closed    bool
	closeOnce sync.Once

	payloadPublications    atomic.Uint64
	structuralPublications atomic.Uint64
}

// New builds the initial generation and kicks off the dedicated writer
// last duplicate after we normalise wins, we don't try to be clever about it
func New[V any](entries []prefixentry.Entry[V], options routeupdate.Options) (*Table[V], error) {
	// fold entries into a catalogue so rebuilds have one code path
	catalog := make(map[netip.Prefix]V, len(entries))
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		catalog[prefix] = entry.Value
	}
	g, err := buildGeneration(catalog, 1)
	if err != nil {
		return nil, err
	}
	options = options.Normalize()
	t := &Table[V]{
		queue:   make(chan request[V], options.QueueSize),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		options: options,
	}
	// publish before the writer goroutine can race a reader
	t.current.Store(g)
	go t.manage()
	return t, nil
}

// Lookup is the forwarding path we actually hit
// v4 is two array indexes through the expanded table, v6 walks the compressed arena
// 4-in-6 is treated as v4 after Unmap, zoned addrs are a miss
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	// grab the published gen, readers never lock
	g := t.current.Load()
	if addr.Is4() {
		// expanded DIR path, no arithmetic
		return g.result4(g.lookup4(prefixentry.Addr4(addr)))
	}
	if !addr.IsValid() || addr.Zone() != "" {
		var zero V
		return zero, false
	}
	if addr.Is4In6() {
		// same expanded path as native v4
		return g.result4(g.lookup4(prefixentry.Addr4(addr.Unmap())))
	}
	hi, lo := prefixentry.Addr6(addr)
	return g.result6(g.index6.Lookup6(hi, lo))
}

// Lookup4 is the decoded IPv4 fast path - skip netip, we've already got the key
func (t *Table[V]) Lookup4(key uint32) (V, bool) {
	g := t.current.Load()
	return g.result4(g.lookup4(key))
}

// Lookup6 is the decoded IPv6 fast path, same idea - no netip on the hot path
func (t *Table[V]) Lookup6(hi, lo uint64) (V, bool) {
	g := t.current.Load()
	return g.result6(g.index6.Lookup6(hi, lo))
}

// lookup4 walks the expanded levels
// every slot already holds the answer for its whole span, so there's nothing
// to resolve on the way out - don't add a best-so-far
func (g *generation[V]) lookup4(key uint32) uint32 {
	slot := g.root4[key>>16]
	if slot >= tagBlock {
		// tagged means descend, the low bits are already a byte-scaled base
		slot = g.level2[slot&^tagBlock|(key>>8)&0xff]
		if slot >= tagBlock {
			// /25../32 live here, rare on a full table
			slot = g.level3[slot&^tagBlock|key&0xff]
		}
	}
	return slot
}

// result4 maps a non-zero slot onto value4
// slot 0 is "no match", we never store a real value there
func (g *generation[V]) result4(slot uint32) (V, bool) {
	if slot != 0 {
		return g.value4[slot], true
	}
	var zero V
	return zero, false
}

// result6 is the IPv6 analogue of result4 - same zero-means-miss convention
func (g *generation[V]) result6(slot uint32) (V, bool) {
	if slot != 0 {
		return g.value6[slot], true
	}
	var zero V
	return zero, false
}

// Exact returns the value stored for exactly this prefix, not a covering one
// v4 is a bisection of exact4, v6 asks the arena
func (t *Table[V]) Exact(prefix netip.Prefix) (V, bool) {
	g := t.current.Load()
	slot, is4 := g.exact(prefix)
	if slot == 0 {
		var zero V
		return zero, false
	}
	if is4 {
		return g.value4[slot], true
	}
	return g.value6[slot], true
}

// exact finds the value index for this exact prefix, plus which family it's in
// we normalise first so 4-in-6 and zoned addrs don't leak into the tables
func (g *generation[V]) exact(input netip.Prefix) (slot uint32, is4 bool) {
	prefix, ok := prefixentry.NormalizePrefix(input)
	if !ok {
		return 0, false
	}
	addr := prefix.Addr()
	if addr.Is4In6() {
		// mapped v4 needs a /96 or longer or it isn't actually v4
		if prefix.Bits() < 96 {
			return 0, false
		}
		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, prefix.Bits()-96)
	}
	if !addr.Is4() {
		return g.index6.Exact(prefix), false
	}
	target := packExact4(prefixentry.Addr4(addr), uint8(prefix.Bits()))
	// exact4 is sorted key<<8|bits, position+1 is the value index - don't
	// change that, rebuild reads the same array
	position := sort.Search(len(g.exact4), func(i int) bool { return g.exact4[i] >= target })
	if position < len(g.exact4) && g.exact4[position] == target {
		return uint32(position + 1), true
	}
	return 0, true
}

// packExact4 stuffs an IPv4 key and length into one word so we can bsearch it
func packExact4(key uint32, prefixBits uint8) uint64 {
	return uint64(key)<<8 | uint64(prefixBits)
}

// unpackExact4 is the inverse - rebuild uses this to recover the catalogue
func unpackExact4(packed uint64) netip.Prefix {
	key, prefixBits := uint32(packed>>8), int(uint8(packed))
	addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
	return netip.PrefixFrom(addr, prefixBits)
}

// Generation is the currently published generation number - readers just load it
func (t *Table[V]) Generation() uint64 { return t.current.Load().number }

// Stats returns a point-in-time publication count, two atomics, no lock
func (t *Table[V]) Stats() Stats {
	return Stats{
		PayloadPublications:    t.payloadPublications.Load(),
		StructuralPublications: t.structuralPublications.Load(),
	}
}

// Bytes reports the retained size of the forwarding structures, excluding
// payload storage - exact4 is counted because rebuild needs it
func (t *Table[V]) Bytes() int {
	g := t.current.Load()
	return 4*(len(g.root4)+len(g.level2)+len(g.level3)) + 8*len(g.exact4) + g.index6.Bytes()
}

// ApplyBatch submits mutations and waits until their generation is published
func (t *Table[V]) ApplyBatch(mutations []routeupdate.Mutation[V]) error {
	return (<-t.Submit(mutations)).Err
}

// Submit queues mutations for async publication
// we normalise on the caller side so a bad prefix never reaches the writer
func (t *Table[V]) Submit(mutations []routeupdate.Mutation[V]) <-chan routeupdate.Result {
	done := make(chan routeupdate.Result, 1)
	normalized := make([]routeupdate.Mutation[V], len(mutations))
	for i, mutation := range mutations {
		prefix, ok := prefixentry.NormalizePrefix(mutation.Prefix)
		if !ok {
			done <- routeupdate.Result{Generation: t.Generation(), Err: prefixentry.ErrBadIP}
			close(done)
			return done
		}
		normalized[i] = mutation
		normalized[i].Prefix = prefix
	}

	t.submitMu.Lock()
	if t.closed {
		// Close already flipped the flag, don't enqueue
		t.submitMu.Unlock()
		done <- routeupdate.Result{Generation: t.Generation(), Err: ErrClosed}
		close(done)
		return done
	}
	t.queue <- request[V]{mutations: normalized, done: done}
	t.submitMu.Unlock()
	return done
}

// Close stops accepting updates and waits for queued work to publish
// closeOnce so a second call just waits, we don't close stop twice
func (t *Table[V]) Close() {
	t.closeOnce.Do(func() {
		t.submitMu.Lock()
		t.closed = true
		close(t.stop)
		t.submitMu.Unlock()
	})
	<-t.done
}

// manage is the single writer loop
// it batches whatever's on the queue, publishes one generation, then does it
// again - Close drains remaining work before we exit
func (t *Table[V]) manage() {
	defer close(t.done)
	for {
		select {
		case first := <-t.queue:
			t.publish(t.collect(first))
		case <-t.stop:
			// drain without waiting for MaxBatchDelay, we're shutting down
			for {
				select {
				case first := <-t.queue:
					t.publish(t.appendQueued([]request[V]{first}))
				default:
					return
				}
			}
		}
	}
}

// collect gathers a batch, either immediately or up to MaxBatchDelay
// stop during the wait means drain the rest, don't sit on the timer
func (t *Table[V]) collect(first request[V]) []request[V] {
	batch := []request[V]{first}
	if t.options.MaxBatchDelay <= 0 {
		return t.appendQueued(batch)
	}
	timer := time.NewTimer(t.options.MaxBatchDelay)
	defer timer.Stop()
	for len(batch) < t.options.MaxBatchSize {
		select {
		case req := <-t.queue:
			batch = append(batch, req)
		case <-timer.C:
			return batch
		case <-t.stop:
			return t.appendQueued(batch)
		}
	}
	return batch
}

// appendQueued pulls whatever's already sitting on the queue, no waiting
func (t *Table[V]) appendQueued(batch []request[V]) []request[V] {
	for len(batch) < t.options.MaxBatchSize {
		select {
		case req := <-t.queue:
			batch = append(batch, req)
		default:
			return batch
		}
	}
	return batch
}

// publish compiles one generation from a coalesced batch
// last mutation per prefix wins, and we only rebuild the forwarding
// structures when the set of prefixes actually changed
func (t *Table[V]) publish(batch []request[V]) {
	current := t.current.Load()
	// coalesce - later Submit of the same prefix overwrites the earlier one
	mutations := make(map[netip.Prefix]routeupdate.Mutation[V], len(batch))
	for _, req := range batch {
		for _, mutation := range req.mutations {
			mutations[mutation.Prefix] = mutation
		}
	}

	structural := false
	for prefix, mutation := range mutations {
		slot, _ := current.exact(prefix)
		// insert of a missing prefix or delete of a present one is structural
		if (slot == 0) != mutation.Delete {
			structural = true
			break
		}
	}

	var next *generation[V]
	var err error
	if structural {
		next, err = t.rebuild(current, mutations)
	} else {
		next = t.repayload(current, mutations)
	}

	result := routeupdate.Result{Generation: current.number, Err: err}
	if err == nil {
		t.current.Store(next)
		result.Generation = next.number
		if structural {
			t.structuralPublications.Add(1)
		} else {
			t.payloadPublications.Add(1)
		}
	}
	// wake every waiter with the same result, even on failure
	for _, req := range batch {
		req.done <- result
		close(req.done)
	}
}

// repayload publishes changed values against the existing forwarding
// structures - only the affected family's value slice is copied, we
// measured a full copy of both as a waste on v4-only updates
func (t *Table[V]) repayload(current *generation[V], mutations map[netip.Prefix]routeupdate.Mutation[V]) *generation[V] {
	next := *current
	next.number = current.number + 1
	copied4, copied6 := false, false
	for prefix, mutation := range mutations {
		slot, is4 := current.exact(prefix)
		if slot == 0 {
			continue
		}
		if is4 {
			if !copied4 {
				next.value4 = append([]V(nil), current.value4...)
				copied4 = true
			}
			next.value4[slot] = mutation.Value
			continue
		}
		if !copied6 {
			next.value6 = append([]V(nil), current.value6...)
			copied6 = true
		}
		next.value6[slot] = mutation.Value
	}
	return &next
}

// rebuild recovers the catalogue from the exact-prefix array and the IPv6
// index, applies the mutations, and compiles a replacement generation
// we don't keep a live map - that was compiledfib's biggest retained chunk
func (t *Table[V]) rebuild(current *generation[V], mutations map[netip.Prefix]routeupdate.Mutation[V]) (*generation[V], error) {
	catalog := make(map[netip.Prefix]V, len(current.exact4)+len(current.value6)+len(mutations))
	for i, packed := range current.exact4 {
		catalog[unpackExact4(packed)] = current.value4[i+1]
	}
	current.index6.All(func(prefix netip.Prefix, slot uint32) bool {
		catalog[prefix] = current.value6[slot]
		return true
	})
	for prefix, mutation := range mutations {
		if mutation.Delete {
			delete(catalog, prefix)
		} else {
			catalog[prefix] = mutation.Value
		}
	}
	return buildGeneration(catalog, current.number+1)
}
