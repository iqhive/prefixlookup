package compiledfib

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"

	blockindex "github.com/iqhive/prefixlookup/old/blocklpm"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
)

// retained runs f after a GC and returns the HeapAlloc delta plus f's result
// we keep the result alive so the delta actually includes it
func retained(f func() any) (uint64, any) {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	v := f()
	runtime.GC()
	runtime.ReadMemStats(&b)
	return b.HeapAlloc - a.HeapAlloc, v
}

// TestProbeBreakdown splits retained size into catalogue map, routes map,
// full generation, and index alone. we KeepAlive everything so GC doesn't
// eat the samples
func TestProbeBreakdown(t *testing.T) {
	routes, _ := fixture(100_000)
	catalog := map[netip.Prefix]nh{}
	for _, r := range routes {
		p, _ := prefixentry.NormalizePrefix(r.Prefix)
		catalog[p] = r.Value
	}
	fmt.Printf("unique prefixes = %d\n", len(catalog))
	fmt.Printf("sizeof(netip.Prefix)=%d sizeof(Entry[nh])=%d sizeof(generation[nh])=%d\n",
		unsafe.Sizeof(netip.Prefix{}), unsafe.Sizeof(prefixentry.Entry[nh]{}), unsafe.Sizeof(generation[nh]{}))
	fmt.Printf("sizeof(blockindex.Table[routeid.ID]) = %d\n", unsafe.Sizeof(blockindex.Table[routeid.ID]{}))

	// 1. catalogue map alone (retained by the manager goroutine)
	b1, keep1 := retained(func() any {
		m := make(map[netip.Prefix]nh, len(catalog))
		for k, v := range catalog {
			m[k] = v
		}
		return m
	})
	fmt.Printf("catalog map[netip.Prefix]nh (%d entries) = %d B (%.1f B/entry, %.1f B/pfx-nominal)\n",
		len(catalog), b1, float64(b1)/float64(len(catalog)), float64(b1)/100000)

	// 2. routes map[netip.Prefix]routeid.ID
	b2, keep2 := retained(func() any {
		m := make(map[netip.Prefix]routeid.ID, len(catalog))
		i := routeid.ID(0)
		for k := range catalog {
			i++
			m[k] = i
		}
		return m
	})
	fmt.Printf("routes map[netip.Prefix]routeid.ID = %d B (%.1f B/entry, %.1f B/pfx-nominal)\n",
		b2, float64(b2)/float64(len(catalog)), float64(b2)/100000)

	// 3. whole generation
	b3, keep3 := retained(func() any {
		g, err := buildGeneration(catalog, 1)
		if err != nil {
			t.Fatal(err)
		}
		return g
	})
	fmt.Printf("full generation = %d B (%.1f B/pfx-nominal)\n", b3, float64(b3)/100000)
	g := keep3.(*generation[nh])
	fmt.Printf("  index ForwardingBytes = %d (%.1f B/pfx-nominal)\n", g.index.ForwardingBytes(), float64(g.index.ForwardingBytes())/100000)

	// 4. index alone
	indexed := make([]prefixentry.Entry[routeid.ID], 0, len(catalog))
	i := routeid.ID(0)
	for k := range catalog {
		i++
		indexed = append(indexed, prefixentry.Entry[routeid.ID]{Prefix: k, Value: i})
	}
	b4, keep4 := retained(func() any {
		idx, err := blockindex.New(indexed)
		if err != nil {
			t.Fatal(err)
		}
		return idx
	})
	fmt.Printf("index alone = %d B (%.1f B/pfx-nominal); ForwardingBytes=%d\n",
		b4, float64(b4)/100000, keep4.(*blockindex.Table[routeid.ID]).ForwardingBytes())

	runtime.KeepAlive(keep1)
	runtime.KeepAlive(keep2)
	runtime.KeepAlive(keep3)
	runtime.KeepAlive(keep4)
}
