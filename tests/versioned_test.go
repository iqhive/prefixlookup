package tests_test

import (
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/iqhive/prefixlookup/versioned"
)

// TestVersionedModesAndBatches walks ModeFIB / ModeRIB / ModeHybrid, loads a
// random oracle through Update, checks lookups, then does an in-batch
// overwrite of the same prefix and looks at Supernets
//
// FIB isn't supposed to hand back hierarchy (n==0), RIB/Hybrid must - that's
// the whole point of the mode split, so we fail if either side lies
func TestVersionedModesAndBatches(t *testing.T) {
	for _, mode := range []versioned.Mode{versioned.ModeFIB, versioned.ModeRIB, versioned.ModeHybrid} {
		table, want := versioned.New[int](mode), randomOracle(101, 900)
		table.Update(func(writer *versioned.Writer[int]) {
			for prefix, value := range want.values {
				writer.Insert(prefix, value)
			}
		})
		if table.Size() != len(want.values) {
			t.Fatalf("mode %v size = %d, want %d", mode, table.Size(), len(want.values))
		}
		verifyLookup(t, "versioned", table, want, 102, 5000)
		prefix := netip.MustParsePrefix("192.168.0.0/16")
		table.Update(func(writer *versioned.Writer[int]) {
			writer.Insert(prefix, 1)
			writer.Insert(prefix, 2)
			if writer.Size() != len(want.values)+1 {
				t.Fatalf("writer size = %d", writer.Size())
			}
		})
		if value, ok := table.Lookup(netip.MustParseAddr("192.168.1.1")); !ok || value != 2 {
			t.Fatalf("overwrite = (%d,%v)", value, ok)
		}
		n := 0
		table.Supernets(netip.MustParseAddr("192.168.1.1"), func(netip.Prefix, int) bool { n++; return true })
		if mode == versioned.ModeFIB && n != 0 {
			t.Fatalf("FIB Supernets returned %d", n)
		}
		if mode != versioned.ModeFIB && n == 0 {
			t.Fatal("hierarchy mode returned no Supernets")
		}
	}
}

// TestVersionedConcurrentReadersAndWriters is the "readers keep seeing a
// stable snapshot while writers publish" smoke - we load 256 /24s under 10/8,
// spin 8 readers looking up those routes, then run 20 Updates that insert
// unrelated 192.x/16s
//
// readers must keep hitting the original payload; if a publish tears the FIB
// we'll see a miss or a wrong value - we don't try to observe the new routes
// from the readers, that's not the contract we're after here
func TestVersionedConcurrentReadersAndWriters(t *testing.T) {
	table := versioned.New[int](versioned.ModeHybrid)
	const routes = 256
	table.Update(func(writer *versioned.Writer[int]) {
		for i := 0; i < routes; i++ {
			writer.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 0}), 24), i)
		}
	})
	var stop atomic.Bool
	var reads atomic.Int64
	var wg sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				i := rng.Intn(routes)
				if value, ok := table.Lookup(netip.AddrFrom4([4]byte{10, 0, byte(i), 1})); !ok || value != i {
					t.Errorf("stable lookup = (%d,%v), want %d", value, ok, i)
					return
				}
				reads.Add(1)
			}
		}(int64(reader + 1))
	}
	for writer := 0; writer < 20; writer++ {
		writer := writer
		table.Update(func(update *versioned.Writer[int]) {
			update.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{192, byte(writer), 0, 0}), 16), writer)
		})
	}
	stop.Store(true)
	wg.Wait()
	if reads.Load() == 0 {
		t.Fatal("no concurrent reads completed")
	}
}
