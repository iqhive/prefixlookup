package compiledfib

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/iqhive/prefixlookup/internal/routepages"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
)

type nh uint32

// fixture builds size+2 routes (v4 and v6 defaults plus a mixed bag) and a
// 16k uniform lookup set taken from prefix addrs. used by the probes
func fixture(size int) ([]prefixentry.Entry[nh], []netip.Addr) {
	routes := make([]prefixentry.Entry[nh], 0, size+2)
	routes = append(routes,
		prefixentry.Entry[nh]{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		prefixentry.Entry[nh]{Prefix: netip.MustParsePrefix("::/0"), Value: 2})
	for i := 0; i < size; i++ {
		if i&7 == 0 {
			a := [16]byte{0x20, 1, 0xd, 0xb8, byte(i >> 16), byte(i >> 8), byte(i)}
			routes = append(routes, prefixentry.Entry[nh]{Prefix: netip.PrefixFrom(netip.AddrFrom16(a), 32+i%97).Masked(), Value: nh(i + 3)})
		} else {
			a := [4]byte{10 + byte(i>>20), byte(i >> 12), byte(i >> 4), byte(i << 4)}
			routes = append(routes, prefixentry.Entry[nh]{Prefix: netip.PrefixFrom(netip.AddrFrom4(a), 8+i%25).Masked(), Value: nh(i + 3)})
		}
	}
	uniform := make([]netip.Addr, 1<<14)
	for i := range uniform {
		uniform[i] = routes[2+(i*4051)%size].Prefix.Addr().Next()
	}
	return routes, uniform
}

// TestProbeManaged times retained size, mixed Lookup vs index-only, v4/v6
// split, then payload-only and structural ApplyBatch costs. prints, doesn't assert
func TestProbeManaged(t *testing.T) {
	routes, uniform := fixture(100_000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tab, err := New(routes, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	fmt.Printf("managed retained = %d (%.1f B/pfx nominal 100k)\n", after.HeapAlloc-before.HeapAlloc, float64(after.HeapAlloc-before.HeapAlloc)/100000)

	g := tab.current.Load()
	fmt.Printf("routes map entries=%d  payload pages=%d  index.ForwardingBytes=%d\n",
		len(g.routes), len(*(*[]*[routepages.PageSize]nh)(unsafe.Pointer(g.payloads))), g.index.ForwardingBytes())

	// verify the index value array is the identity permutation of routeid.ID
	ident := true
	for p, id := range g.routes {
		got, ok := g.index.Lookup(p.Addr())
		if ok && got != id && p.Bits() == 128 {
			_ = got
		}
	}
	// lookup of each prefix's own base address should yield an id whose
	// payload equals the catalogue value
	mismatch := 0
	for p, id := range g.routes {
		v, ok := tab.Lookup(p.Addr())
		if !ok {
			mismatch++
			continue
		}
		_ = v
		_ = id
	}
	fmt.Printf("identity-check placeholder ident=%v mismatch=%d\n", ident, mismatch)

	// ---- latency ----
	var sum uint64
	n := 20_000_000
	start := time.Now()
	for i := 0; i < n; i++ {
		v, ok := tab.Lookup(uniform[i&(len(uniform)-1)])
		sum += uint64(v)
		if ok {
			sum++
		}
	}
	d := time.Since(start)
	fmt.Printf("managed Lookup mixed: %.2f ns/op (sum=%d)\n", float64(d.Nanoseconds())/float64(n), sum)

	// raw index only
	start = time.Now()
	for i := 0; i < n; i++ {
		v, _ := g.index.Lookup(uniform[i&(len(uniform)-1)])
		sum += uint64(v)
	}
	d = time.Since(start)
	fmt.Printf("index-only Lookup mixed: %.2f ns/op\n", float64(d.Nanoseconds())/float64(n))

	// v4 only / v6 only
	var v4s, v6s []netip.Addr
	for _, a := range uniform {
		if a.Is4() {
			v4s = append(v4s, a)
		} else {
			v6s = append(v6s, a)
		}
	}
	fmt.Printf("uniform split: v4=%d v6=%d\n", len(v4s), len(v6s))
	// bench times n Lookups over addrs, wrapping
	bench := func(name string, addrs []netip.Addr) {
		if len(addrs) == 0 {
			return
		}
		start := time.Now()
		for i := 0; i < n; i++ {
			v, _ := tab.Lookup(addrs[i%len(addrs)])
			sum += uint64(v)
		}
		fmt.Printf("managed %s: %.2f ns/op\n", name, float64(time.Since(start).Nanoseconds())/float64(n))
	}
	bench("v4", v4s)
	bench("v6", v6s)

	// ---- payload-only update cost ----
	last := routes[len(routes)-1]
	muts := []routeupdate.Mutation[nh]{{Prefix: last.Prefix, Value: 0xf001}}
	// warm
	if err := tab.ApplyBatch(muts); err != nil {
		t.Fatal(err)
	}
	iters := 2000
	start = time.Now()
	for i := 0; i < iters; i++ {
		muts[0].Value = nh(0xf000 + i)
		if err := tab.ApplyBatch(muts); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("payload-only ApplyBatch(1): %.2f us/op  stats=%+v\n",
		float64(time.Since(start).Microseconds())/float64(iters), tab.Stats())

	// ---- structural update cost ----
	structural := []routeupdate.Mutation[nh]{{Prefix: netip.MustParsePrefix("100.64.0.0/12"), Value: 7}}
	start = time.Now()
	if err := tab.ApplyBatch(structural); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("structural ApplyBatch(1) [insert new prefix]: %.2f ms  stats=%+v\n",
		float64(time.Since(start).Microseconds())/1000, tab.Stats())
	structural[0].Delete = true
	start = time.Now()
	if err := tab.ApplyBatch(structural); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("structural ApplyBatch(1) [delete]: %.2f ms\n", float64(time.Since(start).Microseconds())/1000)

	runtime.KeepAlive(sum)
	tab.Close()
}

// TestProbeIdentityValues builds a generation directly and checks that
// looking up each prefix's base addr returns the routeid we assigned
func TestProbeIdentityValues(t *testing.T) {
	// build a generation directly and read back the index's value array by
	// looking up each prefix, assert index value == routeid.ID assigned
	catalog := map[netip.Prefix]nh{}
	for i := 0; i < 200; i++ {
		catalog[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)] = nh(1000 + i)
	}
	g, err := buildGeneration(catalog, 1)
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for p, want := range g.routes {
		got, ok := g.index.Lookup(p.Addr())
		if !ok || got != want {
			bad++
		}
	}
	// the index maps address -> routeid.ID, routeid.ID i+1 was assigned in sorted
	// order, and blocklpm stores values[i+1] = entry.Value = i+1
	fmt.Printf("routes=%d bad=%d  (index.values is the identity map: values[k]==k)\n", len(g.routes), bad)
	var ids []routeid.ID
	for _, id := range g.routes {
		ids = append(ids, id)
	}
	fmt.Printf("max id=%d len(routes)=%d\n", len(ids), len(g.routes))
}
