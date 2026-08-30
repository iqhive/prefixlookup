// Package tests_test is our centralised external hardening and quality suite
// for prefixlookup - we only poke exported APIs, we brute-force an oracle for
// shared behaviour, we keep compat checks in one spot, and we replay the
// committed fuzz corpus
//
// implementation-specific unit tests stay beside their packages; this dir
// is the cross-package contract dump and the old nradix hardening names so
// we notice omissions in review without peeking at unexported state
package tests_test

import (
	"math/rand"
	"net/netip"
	"sort"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type oracle struct {
	values map[netip.Prefix]int
}

// newOracle is the empty brute-force table - just a map, nothing clever
func newOracle() *oracle { return &oracle{values: make(map[netip.Prefix]int)} }

// insert stores value under the masked prefix (last write wins, same as the
// real tables) - we always Mask so "10.1.0.0/8" and "10.0.0.0/8" don't fork
func (o *oracle) insert(prefix netip.Prefix, value int) { o.values[prefix.Masked()] = value }

// delete drops the masked prefix and tells us whether it was actually there
func (o *oracle) delete(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	_, ok := o.values[prefix]
	delete(o.values, prefix)
	return ok
}

// lookup is the slow LPM - scan every stored prefix, keep the longest that
// Contains the addr - this is the ground truth everything else has to match
func (o *oracle) lookup(addr netip.Addr) (int, bool) {
	best, value, found := -1, 0, false
	for prefix, candidate := range o.values {
		if prefix.Contains(addr) && prefix.Bits() > best {
			best, value, found = prefix.Bits(), candidate, true
		}
	}
	return value, found
}

// entries dumps the map as a prefixentry slice so immutable constructors can
// take the same bag the mutable tests built incrementally
func (o *oracle) entries() []prefixentry.Entry[int] {
	entries := make([]prefixentry.Entry[int], 0, len(o.values))
	for prefix, value := range o.values {
		entries = append(entries, prefixentry.Entry[int]{Prefix: prefix, Value: value})
	}
	return entries
}

// randPrefix draws a fully random masked prefix - v4 gets /0–/32, v6 /0–/128
// - we don't try to look like a real FIB here, that's fibbench's job
func randPrefix(rng *rand.Rand, v4 bool) netip.Prefix {
	if v4 {
		var bytes [4]byte
		rng.Read(bytes[:])
		return netip.PrefixFrom(netip.AddrFrom4(bytes), rng.Intn(33)).Masked()
	}
	var bytes [16]byte
	rng.Read(bytes[:])
	return netip.PrefixFrom(netip.AddrFrom16(bytes), rng.Intn(129)).Masked()
}

// randomOracle fills an oracle with both defaults plus `count` random
// prefixes - defaults get -4/-6 so they're obvious in failure dumps
func randomOracle(seed int64, count int) *oracle {
	rng := rand.New(rand.NewSource(seed))
	o := newOracle()
	o.insert(netip.MustParsePrefix("0.0.0.0/0"), -4)
	o.insert(netip.MustParsePrefix("::/0"), -6)
	for i := 0; i < count; i++ {
		o.insert(randPrefix(rng, i%2 == 0), i)
	}
	return o
}

type lookupTable interface {
	Lookup(netip.Addr) (int, bool)
}

// verifyLookup probes `table` against oracle `o` - half the addrs sit inside
// stored prefixes (so we hit), half are fresh randoms (so we mix misses) -
// seed is separate from the table-build seed on purpose
func verifyLookup(t *testing.T, name string, table lookupTable, o *oracle, seed int64, probes int) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	prefixes := make([]netip.Prefix, 0, len(o.values))
	for prefix := range o.values {
		prefixes = append(prefixes, prefix)
	}
	for i := 0; i < probes; i++ {
		var addr netip.Addr
		if i%2 == 0 {
			addr = prefixes[rng.Intn(len(prefixes))].Addr()
		} else {
			addr = randPrefix(rng, i%4 == 1).Addr()
		}
		got, gotOK := table.Lookup(addr)
		want, wantOK := o.lookup(addr)
		if gotOK != wantOK || gotOK && got != want {
			t.Fatalf("%s Lookup(%v) = (%v,%v), want (%v,%v)", name, addr, got, gotOK, want, wantOK)
		}
	}
}

// sortedPrefixes is a stable-ish dump of the oracle keys, shortest then
// address order - we use it when we want a deterministic delete shuffle
func sortedPrefixes(values map[netip.Prefix]int) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for prefix := range values {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
	return prefixes
}
