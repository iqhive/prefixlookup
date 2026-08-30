package fibbench

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"

	"github.com/gaissmai/bart"
	iqhivenradix "github.com/iqhive/nradix"
	"github.com/iqhive/prefixlookup/aosart"
	"github.com/iqhive/prefixlookup/flatwalk"
	"github.com/iqhive/prefixlookup/internal/benchutil"
	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/old/fiborderwalk"
	"github.com/iqhive/prefixlookup/orderwalk"
	"github.com/iqhive/prefixlookup/preorder2"
	"github.com/iqhive/prefixlookup/routeid"
	"github.com/iqhive/prefixlookup/routeupdate"
	"github.com/iqhive/prefixlookup/soaart"
	"github.com/iqhive/prefixlookup/splitribfib"
)

// routesFromPrefixes stamps a dummy next-hop (index+1) onto each prefix so
// we can feed the same genPrefixes bag into every table factory
func routesFromPrefixes(prefixes []netip.Prefix) []route {
	routes := make([]route, len(prefixes))
	for i, prefix := range prefixes {
		routes[i] = route{prefix: prefix, next: NextHop(i + 1)}
	}
	return routes
}

// benchmarkComparativeSerial is the single-threaded lookup loop we reuse for
// distribution / family-mix benches - one subtest per factory, queries
// masked with (len-1) so the stream must be a power of two
//
// we sink the payload so the compiler can't DCE the Lookup
func benchmarkComparativeSerial(b *testing.B, routes []route, queries []netip.Addr) {
	for _, factory := range factories {
		b.Run(factory.name, func(b *testing.B) {
			t := factory.new()
			t.Reset(routes)
			b.ReportAllocs()
			b.ResetTimer()
			var sum uint64
			for i := 0; i < b.N; i++ {
				value, ok := t.Read(queries[i&(len(queries)-1)])
				sum += uint64(value)
				if ok {
					sum++
				}
			}
			sink.Store(sum)
			b.StopTimer()
			t.Close()
		})
	}
}

// runComparativeThroughput pins GOMAXPROCS to `workers`, shards b.N via
// RunParallelRanges, and reports Mlookups/s plus ns/lookup/worker
//
// 7919 is a random-ish stride so workers don't all pound the same cache line
// of the query slice; hits[] is per-worker so we don't contend on the sink
func runComparativeThroughput(b *testing.B, workers int, probe func(int) bool) {
	b.Helper()
	if workers < 1 {
		b.Fatal("workers must be positive")
	}

	runtime.GC()
	previousProcs := runtime.GOMAXPROCS(workers)
	defer runtime.GOMAXPROCS(previousProcs)

	b.ReportAllocs()
	b.ResetTimer()
	var hits [64]uint64
	operations := benchutil.RunParallelRanges(b.N, workers, func(operation uint64, worker int) {
		if probe(worker*7919 + int(operation)) {
			hits[worker]++
		}
	})
	b.StopTimer()
	if operations != uint64(b.N) {
		b.Fatalf("completed %d operations, want %d", operations, b.N)
	}
	for worker := 0; worker < workers; worker++ {
		sink.Add(hits[worker])
	}
	elapsed := b.Elapsed()
	b.ReportMetric(float64(operations)/elapsed.Seconds()/1e6, "Mlookups/s")
	// Go's ns/op is aggregate wall time per lookup - this metric approximates
	// per-worker service time and avoids presenting sub-nanosecond aggregate
	// throughput as single-request latency at high worker counts
	b.ReportMetric(float64(workers)*float64(elapsed.Nanoseconds())/float64(operations), "ns/lookup/worker")
}

// BenchmarkComparativeSerial was the 1k/50k/500k serial sweep - parked because
// BenchmarkComparativeParallel + the distribution benches cover the same
// ground and we were drowning in subtests
//
// func BenchmarkComparativeSerial(b *testing.B) {
// 	for _, size := range []int{1_000, 50_000, 500_000} {
// 		prefixes := genPrefixes(size, dfzV6Mix, 1)
// 		queries := genQueriesZipf(prefixes, 1<<16, 2)
// 		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
// 			benchmarkComparativeSerial(b, routesFromPrefixes(prefixes), queries)
// 		})
// 	}
// }

// BenchmarkComparativeParallel pretends we're a software router with a DFZ-ish
// table (dfzV6Mix) at 1k (fits in cache) and 1M (does not), Zipf queries so
// the hot set is small, 1 vs 32 workers
//
// we Reset once per factory then run both worker counts against the same
// published table - that's the "many lookup threads, rare mutation" shape
func BenchmarkComparativeParallel(b *testing.B) {
	for _, size := range []int{1_000, 1_000_000} {
		prefixes := genPrefixes(size, dfzV6Mix, 3)
		routes := routesFromPrefixes(prefixes)
		queries := genQueriesZipf(prefixes, 1<<16, 4)
		for _, factory := range factories {
			t := factory.new()
			t.Reset(routes)
			for _, workers := range []int{1, 32} {
				b.Run(fmt.Sprintf("%d/x%d/%s", size, workers, factory.name), func(b *testing.B) {
					runComparativeThroughput(b, workers, func(i int) bool {
						_, ok := t.Read(queries[i&(len(queries)-1)])
						return ok
					})
				})
			}
			t.Close()
		}
	}
}

// BenchmarkQueryDistributions holds the table at 500k DFZ-mix and swaps the
// query stream: uniform (every prefix equally likely - worst cache) vs
// all-miss (the ACL/filter case)
//
// zipf is commented out because BenchmarkComparativeParallel already does
// zipf; we wired it this way so a cache-friendly structure can't hide behind
// a hot working set
func BenchmarkQueryDistributions(b *testing.B) {
	prefixes := genPrefixes(500_000, dfzV6Mix, 5)
	routes := routesFromPrefixes(prefixes)
	for _, workload := range []struct {
		name    string
		queries []netip.Addr
	}{
		// {"zipf", genQueriesZipf(prefixes, 1<<16, 6)},
		{"uniform", genQueriesUniform(prefixes, 1<<16, 7)},
		{"all-miss", genQueriesMiss(1<<16, 8)},
	} {
		b.Run(workload.name, func(b *testing.B) { benchmarkComparativeSerial(b, routes, workload.queries) })
	}
}

// BenchmarkFamilyMixes is "what if the table is v4-only / v6-only / half"
// at 200k prefixes with Zipf queries - v6-only is the one that blows up
// stride tables that specialise the v4 /24 cut
func BenchmarkFamilyMixes(b *testing.B) {
	for _, mix := range []struct {
		name string
		v6   float64
	}{{"v4-only", 0}, {"v6-only", 1}, {"mixed", 0.5}} {
		prefixes := genPrefixes(200_000, mix.v6, 9)
		queries := genQueriesZipf(prefixes, 1<<16, 10)
		b.Run(mix.name, func(b *testing.B) { benchmarkComparativeSerial(b, routesFromPrefixes(prefixes), queries) })
	}
}

// BenchmarkIPv6 was a dedicated 200k v6-only serial run - parked, it's the
// same as FamilyMixes/v6-only
//
// func BenchmarkIPv6(b *testing.B) {
// 	prefixes := genPrefixes(200_000, 1, 11)
// 	benchmarkComparativeSerial(b, routesFromPrefixes(prefixes), genQueriesZipf(prefixes, 1<<16, 12))
// }

// BenchmarkComparativeMemory was retained-bytes at 50k/500k - parked in
// favour of BenchmarkMemory / BenchmarkRealTableMemory
//
// func BenchmarkComparativeMemory(b *testing.B) {
// 	for _, size := range []int{50_000, 500_000} {
// 		routes := routesFromPrefixes(genPrefixes(size, dfzV6Mix, 13))
// 		for _, factory := range memoryFactories {
// 			b.Run(fmt.Sprintf("%d/%s", size, factory.name), func(b *testing.B) {
// 				b.StopTimer()
// 				runtime.GC()
// 				runtime.GC()
// 				var before runtime.MemStats
// 				runtime.ReadMemStats(&before)
// 				obj := factory.build(routes)
// 				runtime.GC()
// 				runtime.GC()
// 				var after runtime.MemStats
// 				runtime.ReadMemStats(&after)
// 				retained := retainedBytes(before.HeapAlloc, after.HeapAlloc)
// 				b.ReportMetric(float64(retained)/float64(size), "B/prefix")
// 				b.ReportMetric(float64(retained)/(1024*1024), "total-MiB")
// 				b.ReportMetric(1, "measurements")
// 				runtime.KeepAlive(obj)
// 				closeObject(obj)
// 			})
// 		}
// 	}
// }

// BenchmarkComparativeBuild was Reset-from-empty at 50k - parked, BulkLoad
// in fibbench_test.go covers this
//
// func BenchmarkComparativeBuild(b *testing.B) {
// 	routes := routesFromPrefixes(genPrefixes(50_000, dfzV6Mix, 14))
// 	for _, factory := range factories {
// 		b.Run(factory.name, func(b *testing.B) {
// 			b.ReportAllocs()
// 			for range b.N {
// 				t := factory.new()
// 				t.Reset(routes)
// 				t.Close()
// 			}
// 		})
// 	}
// }

// BenchmarkGCPressure was "how long does GC take with this table live" -
// parked, it was mostly measuring Go, not us
//
// func BenchmarkGCPressure(b *testing.B) {
// 	routes := routesFromPrefixes(genPrefixes(100_000, dfzV6Mix, 15))
// 	for _, factory := range memoryFactories {
// 		b.Run(factory.name, func(b *testing.B) {
// 			obj := factory.build(routes)
// 			b.ReportAllocs()
// 			b.ResetTimer()
// 			for range b.N {
// 				runtime.GC()
// 			}
// 			b.StopTimer()
// 			runtime.KeepAlive(obj)
// 			closeObject(obj)
// 		})
// 	}
// }

// BenchmarkTraversal pretends we're walking a 200k DFZ-mix RIB for BGP
// show commands / policy - Zipf addrs for Supernets (longest-first parent
// walk), a single mid-table prefix for Subnets (descendant walk)
//
// we build each RIB-capable impl once and subtest per walk kind so we're
// measuring the walk, not construction; bart uses iterator range loops
// because that's their API
func BenchmarkTraversal(b *testing.B) {
	prefixes := genPrefixes(200_000, dfzV6Mix, 16)
	routes := routesFromPrefixes(prefixes)
	queries := genQueriesZipf(prefixes, 1<<16, 17)
	artRIB := buildArtwalkObject(routes).(*artwalk.Table[NextHop])
	split, err := splitribfib.New(entries(routes), routeupdate.Options{
		MaxBatchSize: 1024,
	})
	if err != nil {
		b.Fatal(err)
	}
	ordered, err := fiborderwalk.New(entries(routes))
	if err != nil {
		b.Fatal(err)
	}
	ordered2, err := preorder2.New(entries(routes), routeupdate.Options{
		MaxBatchSize: 1024,
	})
	if err != nil {
		b.Fatal(err)
	}
	bt := new(bart.Table[NextHop])
	for _, route := range routes {
		bt.Insert(route.prefix, route.next)
	}
	walk1, err := flatwalk.New(entries(routes))
	if err != nil {
		b.Fatal(err)
	}
	walk3, err := orderwalk.New(entries(routes))
	if err != nil {
		b.Fatal(err)
	}
	walk2, err := soaart.New(soaartEntriesOf(routes))
	if err != nil {
		b.Fatal(err)
	}
	walk2b, err := aosart.New(aosartEntriesOf(routes))
	if err != nil {
		b.Fatal(err)
	}
	legacy := buildLegacyObject(routes).(*iqhivenradix.Tree)

	b.Run("Supernets/artwalk", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			artRIB.Supernets(queries[i&(len(queries)-1)], func(netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/split-rib-fib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			split.WalkParents(queries[i&(len(queries)-1)], func(routeid.ID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/fiborderwalk", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			ordered.WalkParents(queries[i&(len(queries)-1)], func(routeid.ID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/preorder2", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			ordered.WalkParents(queries[i&(len(queries)-1)], func(routeid.ID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/flatwalk", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			walk1.WalkParents(queries[i&(len(queries)-1)], func(flatwalk.RouteID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/iqhive-nradix-v1.0.13", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sink.Store(walkNradixParents(legacy, queries[i&(len(queries)-1)]))
		}
	})
	b.Run("Supernets/soaart", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			walk2.WalkSupernets(queries[i&(len(queries)-1)], func(netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/aosart", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			walk2b.WalkSupernets(queries[i&(len(queries)-1)], func(netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/orderwalk", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			walk3.WalkParents(queries[i&(len(queries)-1)], func(orderwalk.RouteID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Supernets/bart-table", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := uint64(0)
			query := netip.PrefixFrom(queries[i&(len(queries)-1)], queries[i&(len(queries)-1)].BitLen())
			for range bt.Supernets(query) {
				count++
			}
			sink.Store(count)
		}
	})

	query := prefixes[len(prefixes)/2]
	b.Run("Subnets/artwalk", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			artRIB.Subnets(query, func(netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/split-rib-fib", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			split.WalkDescendants(query, func(routeid.ID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/fiborderwalk", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			ordered.WalkDescendants(query, func(routeid.ID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/preorder2", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			ordered2.WalkDescendants(query, func(routeid.ID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/flatwalk", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			walk1.WalkDescendants(query, func(flatwalk.RouteID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	start := nradixExactNode(legacy, query)
	if start == nil {
		b.Fatalf("iqhive nradix has no exact node for %v", query)
	}
	b.Run("Subnets/iqhive-nradix-v1.0.13", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			sink.Store(walkNradixSubtree(start))
		}
	})
	b.Run("Subnets/soaart", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			walk2.WalkSubnets(query, func(netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/aosart", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			walk2b.WalkSubnets(query, func(netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/orderwalk", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			walk3.WalkDescendants(query, func(orderwalk.RouteID, netip.Prefix, NextHop) bool { count++; return true })
			sink.Store(count)
		}
	})
	b.Run("Subnets/bart-table", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			count := uint64(0)
			for range bt.Subnets(query) {
				count++
			}
			sink.Store(count)
		}
	})
}

// walkNradixParents is the iqhive nradix supernet walk: LPM node plus every
// valued ancestor, reconstructing each prefix the way WalkParents does.
// asergeyev/nradix has no parent-chain API, so it stays out
func walkNradixParents(tree *iqhivenradix.Tree, addr netip.Addr) uint64 {
	node, value, err := tree.FindCIDRNetIPAddrWithNode(addr)
	if err != nil || node == nil {
		return 0
	}
	count := uint64(0)
	if value != nil {
		if node.GetPrefix().IsValid() {
			count++
		}
	}
	for p := node.GetParent(); p != nil; p = p.GetParent() {
		if p.GetPrefix().IsValid() {
			count++
		}
	}
	return count
}

// nradixExactNode walks up from the LPM of prefix.Addr() until GetPrefix
// matches - that's the subtree root WalkDescendants would start from
func nradixExactNode(tree *iqhivenradix.Tree, prefix netip.Prefix) *iqhivenradix.Node {
	node, _, err := tree.FindCIDRNetIPAddrWithNode(prefix.Addr())
	if err != nil {
		return nil
	}
	for node != nil {
		if node.GetPrefix() == prefix {
			return node
		}
		node = node.GetTreeParent()
	}
	return nil
}

// walkNradixSubtree counts the start node and every valued descendant
func walkNradixSubtree(node *iqhivenradix.Node) uint64 {
	if node == nil {
		return 0
	}
	count := uint64(0)
	var walk func(*iqhivenradix.Node)
	walk = func(n *iqhivenradix.Node) {
		if n == nil {
			return
		}
		if n.GetValue() != nil {
			if n.GetPrefix().IsValid() {
				count++
			}
		}
		walk(n.GetLeft())
		walk(n.GetRight())
	}
	walk(node)
	return count
}
