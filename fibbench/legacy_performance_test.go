package fibbench

import (
	"net/netip"
	"testing"

	iqhivenradix "github.com/iqhive/nradix"
)

// var benchmarkSizes = []int{5_000, 50_000, 500_000}
var benchmarkValue = new(byte)

// benchmarkPrefix is a deterministic unique /32 in 10/8 - we encode i across
// the last three octets so we can go past 16M entries without colliding
func benchmarkPrefix(i int) netip.Prefix {
	// /32 prefixes give us over 16 million deterministic unique entries
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
}

// buildBenchmarkTree fills an nradix tree with `size` /32s and returns the
// matching host addrs so lookup benches don't have to re-derive them
func buildBenchmarkTree(tb testing.TB, size int) (*iqhivenradix.Tree, []netip.Addr) {
	tb.Helper()
	tree := iqhivenradix.NewTree(0)
	addresses := make([]netip.Addr, size)
	for i := range addresses {
		prefix := benchmarkPrefix(i)
		addresses[i] = prefix.Addr()
		if err := tree.SetCIDRNetIPPrefix(prefix, benchmarkValue, false); err != nil {
			tb.Fatalf("insert prefix %d: %v", i, err)
		}
	}
	return tree, addresses
}

// BenchmarkLookupBySize was the old nradix-only lookup sweep - parked because
// the comparative benches cover this, left here so we remember the sizes
//
// func BenchmarkLookupBySize(b *testing.B) {
// 	for _, size := range benchmarkSizes {
// 		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
// 			tree, addresses := buildBenchmarkTree(b, size)
// 			b.ReportAllocs()
// 			b.ResetTimer()
// 			for i := 0; i < b.N; i++ {
// 				value, err := tree.FindCIDRNetIPAddr(addresses[i%size])
// 				if err != nil || value == nil {
// 					b.Fatal(value, err)
// 				}
// 			}
// 		})
// 	}
// }

// BenchmarkLookupNodePrefixBySize was the "give me the node too" variant -
// parked with the rest of the nradix-only suite
//
// func BenchmarkLookupNodePrefixBySize(b *testing.B) {
// 	for _, size := range benchmarkSizes {
// 		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
// 			tree, addresses := buildBenchmarkTree(b, size)
// 			b.ReportAllocs()
// 			b.ResetTimer()
// 			for i := 0; i < b.N; i++ {
// 				node, value, err := tree.FindCIDRNetIPAddrWithNode(addresses[i%size])
// 				if err != nil || value == nil || !node.GetPrefix().IsValid() {
// 					b.Fatal(value, err)
// 				}
// 			}
// 		})
// 	}
// }

// BenchmarkBuildBySize was insert-from-empty across the size sweep - parked
//
// func BenchmarkBuildBySize(b *testing.B) {
// 	for _, size := range benchmarkSizes {
// 		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
// 			b.ReportAllocs()
// 			for i := 0; i < b.N; i++ {
// 				tree := iqhivenradix.NewTree(0)
// 				for j := 0; j < size; j++ {
// 					if err := tree.SetCIDRNetIPPrefix(benchmarkPrefix(j), benchmarkValue, false); err != nil {
// 						b.Fatal(err)
// 					}
// 				}
// 			}
// 		})
// 	}
// }

// BenchmarkWalkV4BySize was a full WalkV4 of the /32 dump - parked
//
// func BenchmarkWalkV4BySize(b *testing.B) {
// 	for _, size := range benchmarkSizes {
// 		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
// 			tree, _ := buildBenchmarkTree(b, size)
// 			b.ReportAllocs()
// 			b.ResetTimer()
// 			for i := 0; i < b.N; i++ {
// 				count := 0
// 				if err := tree.WalkV4(func(netip.Prefix, interface{}) error {
// 					count++
// 					return nil
// 				}); err != nil || count != size {
// 					b.Fatalf("walked %d prefixes: %v", count, err)
// 				}
// 			}
// 		})
// 	}
// }

// BenchmarkRetainedMemoryBySize was the nradix-only retained-bytes sweep -
// parked; BenchmarkMemory / BenchmarkRealTableMemory replaced it
//
// func BenchmarkRetainedMemoryBySize(b *testing.B) {
// 	for _, size := range benchmarkSizes {
// 		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
// 			b.ReportAllocs()
// 			runtime.GC()
// 			var before runtime.MemStats
// 			runtime.ReadMemStats(&before)
// 			tree, _ := buildBenchmarkTree(b, size)
// 			runtime.GC()
// 			var after runtime.MemStats
// 			runtime.ReadMemStats(&after)
// 			retained := retainedBytes(before.HeapAlloc, after.HeapAlloc)
// 			b.ReportMetric(float64(retained), "retained-B")
// 			b.ReportMetric(float64(retained)/float64(size), "retained-B/prefix")
// 			runtime.KeepAlive(tree)
// 		})
// 	}
// }
