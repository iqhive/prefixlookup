package flatart

import (
	"math"
	"math/rand"
	"net/netip"
	"testing"

	blocklpm "github.com/iqhive/prefixlookup/old/blocklpm"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// the length distributions mirror fibbench's generator so that numbers
// measured here decompose the numbers measured there
var benchV4Lengths = expand([]struct{ bits, weight int }{
	{8, 1}, {9, 1}, {10, 2}, {11, 3}, {12, 6}, {13, 11}, {14, 20}, {15, 25},
	{16, 130}, {17, 25}, {18, 40}, {19, 70}, {20, 110}, {21, 120}, {22, 190},
	{23, 160}, {24, 600}, {32, 20},
})

var benchV6Lengths = expand([]struct{ bits, weight int }{
	{20, 1}, {24, 2}, {28, 4}, {29, 30}, {30, 6}, {31, 5}, {32, 240},
	{33, 8}, {34, 10}, {35, 6}, {36, 60}, {38, 8}, {40, 90}, {44, 60},
	{47, 40}, {48, 380}, {56, 12}, {64, 30}, {128, 8},
})

// expand unrolls a weighted length table into a flat slice we can Intn
func expand(dist []struct{ bits, weight int }) []int {
	var out []int
	for _, d := range dist {
		for range d.weight {
			out = append(out, d.bits)
		}
	}
	return out
}

// benchPrefixes draws n unique prefixes with fibbench's mix and lengths
func benchPrefixes(n int, v6mix float64, seed int64) []netip.Prefix {
	rng := rand.New(rand.NewSource(seed))
	seen := make(map[netip.Prefix]bool, n)
	out := make([]netip.Prefix, 0, n)
	for len(out) < n {
		var p netip.Prefix
		if rng.Float64() < v6mix {
			var b [16]byte
			b[0] = 0x20 | byte(rng.Intn(2))
			for i := 1; i < len(b); i++ {
				b[i] = byte(rng.Intn(256))
			}
			p = netip.PrefixFrom(netip.AddrFrom16(b), benchV6Lengths[rng.Intn(len(benchV6Lengths))]).Masked()
		} else {
			b := [4]byte{byte(1 + rng.Intn(222)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
			p = netip.PrefixFrom(netip.AddrFrom4(b), benchV4Lengths[rng.Intn(len(benchV4Lengths))]).Masked()
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// benchAddrIn picks a random address inside p so queries actually hit
func benchAddrIn(p netip.Prefix, rng *rand.Rand) netip.Addr {
	a := p.Addr()
	prefixBits := p.Bits()
	if a.Is4() {
		v := prefixentry.Addr4(a)
		if prefixBits < 32 {
			v |= rng.Uint32() & (uint32(math.MaxUint32) >> uint(prefixBits))
		}
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := a.As16()
	for i := prefixBits; i < 128; i++ {
		if rng.Intn(2) == 1 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	return netip.AddrFrom16(b)
}

// benchIndex compiles prefixes with Exact on, dies on error
func benchIndex(tb testing.TB, prefixes []netip.Prefix) *Index {
	tb.Helper()
	b := NewBuilder(Options{Exact: true})
	for i, prefix := range prefixes {
		b.Insert(prefix, uint32(i+1))
	}
	ix, _, err := b.Build()
	if err != nil {
		tb.Fatal(err)
	}
	return ix
}

// benchQueries reproduces fibbench's zipf query stream, which concentrates
// lookups on a small subset and so measures dependent-load latency rather
// than footprint
func benchQueries(prefixes []netip.Prefix, n int, seed int64) []netip.Addr {
	rng := rand.New(rand.NewSource(seed))
	z := rand.NewZipf(rng, 1.1, 1, uint64(len(prefixes)-1))
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = benchAddrIn(prefixes[z.Uint64()], rng)
	}
	return out
}

// benchKeys4 strips netip so the decoded path doesn't pay for it
func benchKeys4(addrs []netip.Addr) []uint32 {
	out := make([]uint32, len(addrs))
	for i, a := range addrs {
		out[i] = prefixentry.Addr4(a)
	}
	return out
}

var benchSink uint32

// BenchmarkDecompose isolates the parts of an IPv4 lookup so the cost of
// the descent, the resolution and the netip decoding can be attributed
// separately
func BenchmarkDecompose(b *testing.B) {
	prefixes := benchPrefixes(200_000, 0, 9)
	ix := benchIndex(b, prefixes)
	addrs := benchQueries(prefixes, 1<<14, 10)
	keys := benchKeys4(addrs)
	mask := len(keys) - 1

	b.Run("Lookup4", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			sum += ix.Lookup4(keys[i&mask])
		}
		benchSink = sum
	})
	b.Run("Contains4", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			if ix.Contains4(keys[i&mask]) {
				sum++
			}
		}
		benchSink = sum
	})
	b.Run("RootOnly", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			key := keys[i&mask]
			sum += ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
		}
		benchSink = sum
	})
	// the probes below bisect the IPv4 path so the cost of each dependent load
	// and of the resolution arithmetic can be attributed separately
	b.Run("RootPlusStrideLoad", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			key := keys[i&mask]
			slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
			if slot >= tagStop {
				sum += ix.stops[slot&refMask].hostBase
			} else {
				sum += slot
			}
		}
		benchSink = sum
	})
	b.Run("RootPlusStrideHostBit", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			key := keys[i&mask]
			slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
			if slot >= tagStop {
				s := &ix.stops[slot&refMask]
				o := uint(uint8(key >> 8))
				sum += uint32(s.host[(o>>6)&3] >> (o & 63) & 1)
			} else {
				sum += slot
			}
		}
		benchSink = sum
	})
	// host-only answers the full-octet shape and abandons the rest - it is
	// deliberately incorrect, it exists to price the partial-stride fallback,
	// which the length distribution takes for about half of all queries
	b.Run("RootPlusStrideHostResolve", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			key := keys[i&mask]
			slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
			if slot >= tagStop {
				s := &ix.stops[slot&refMask]
				sum += resolveStop(s, uint8(key>>8))
			} else {
				sum += slot
			}
		}
		benchSink = sum
	})
	b.Run("ShortFallbackShare", func(b *testing.B) {
		hostHits, total := 0, 0
		for i := 0; i < len(keys); i++ {
			key := keys[i]
			slot := ix.rootLo4[ix.rootHi4[key>>24]+(key>>16&0xff)]
			if slot >= tagStop {
				s := &ix.stops[slot&refMask]
				total++
				if resolveStop(s, uint8(key>>8)) != 0 {
					hostHits++
				}
			}
		}
		b.ReportMetric(float64(hostHits)/float64(max(total, 1)), "host-hit-share")
		b.ReportMetric(float64(total)/float64(len(keys)), "stop-share")
		b.ReportMetric(1, "measurements")
	})
	b.Run("Lookup4ViaAddr", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			sum += ix.Lookup(addrs[i&mask])
		}
		benchSink = sum
	})
}

// BenchmarkDecomposeV6 does the same for IPv6, where the descent is deeper
func BenchmarkDecomposeV6(b *testing.B) {
	prefixes := benchPrefixes(200_000, 1, 9)
	ix := benchIndex(b, prefixes)
	addrs := benchQueries(prefixes, 1<<14, 10)
	mask := len(addrs) - 1

	b.Run("Lookup6", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			hi, lo := prefixentry.Addr6(addrs[i&mask])
			sum += ix.Lookup6(hi, lo)
		}
		benchSink = sum
	})
	b.Run("Contains6", func(b *testing.B) {
		var sum uint32
		for i := 0; i < b.N; i++ {
			hi, lo := prefixentry.Addr6(addrs[i&mask])
			if ix.Contains6(hi, lo) {
				sum++
			}
		}
		benchSink = sum
	})
}

// BenchmarkAgainstCompiled measures the raw lookup of both this index and
// the leaf-pushed table it is meant to replace, on identical keys and
// outside the fibbench harness, so the difference attributable to the
// structures can be separated from the interface dispatch and query-array
// traffic they share
func BenchmarkAgainstCompiled(b *testing.B) {
	for _, spec := range []struct {
		name  string
		size  int
		v6mix float64
	}{{"v4-only/200000", 200_000, 0}, {"mixed/100000", 100_000, 0.125}} {
		prefixes := benchPrefixes(spec.size, spec.v6mix, 9)
		addrs := benchQueries(prefixes, 1<<14, 10)
		mask := len(addrs) - 1

		ix := benchIndex(b, prefixes)

		entries := make([]prefixentry.Entry[uint32], len(prefixes))
		for i, prefix := range prefixes {
			entries[i] = prefixentry.Entry[uint32]{Prefix: prefix, Value: uint32(i + 1)}
		}
		compiled, err := blocklpm.New(entries)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(spec.name+"/flatart", func(b *testing.B) {
			var sum uint32
			for i := 0; i < b.N; i++ {
				sum += ix.Lookup(addrs[i&mask])
			}
			benchSink = sum
		})
		b.Run(spec.name+"/blocklpm", func(b *testing.B) {
			var sum uint32
			for i := 0; i < b.N; i++ {
				v, _ := compiled.Lookup(addrs[i&mask])
				sum += v
			}
			benchSink = sum
		})
		b.Run(spec.name+"/blocklpm-bytes", func(b *testing.B) {
			b.ReportMetric(float64(compiled.ForwardingBytes())/float64(spec.size), "fwd-B/prefix")
			b.ReportMetric(float64(ix.Bytes())/float64(spec.size), "flatart-B/prefix")
			b.ReportMetric(1, "measurements")
		})
	}
}

// BenchmarkStats reports the structural shape of the compiled index, which
// is what determines both footprint and how many lines a descent touches
func BenchmarkStats(b *testing.B) {
	for _, spec := range []struct {
		name  string
		size  int
		v6mix float64
	}{
		{"v4-only/200000", 200_000, 0},
		{"v6-only/200000", 200_000, 1},
		{"mixed/500000", 500_000, 0.15},
	} {
		b.Run(spec.name, func(b *testing.B) {
			prefixes := benchPrefixes(spec.size, spec.v6mix, 9)
			ix := benchIndex(b, prefixes)
			b.ReportMetric(float64(len(ix.nodes)), "nodes")
			b.ReportMetric(float64(len(ix.stops)), "stops")
			b.ReportMetric(float64(len(ix.rootLo4)+len(ix.rootLo6))/256, "root-blocks")
			b.ReportMetric(float64(len(ix.leaf4)+len(ix.leaf6)), "leaves")
			b.ReportMetric(float64(len(ix.refs)), "refs")
			b.ReportMetric(float64(ix.values), "values")
			b.ReportMetric(float64(ix.Bytes())/float64(spec.size), "index-B/prefix")
			b.ReportMetric(1, "measurements")
		})
	}
}
