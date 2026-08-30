package fibbench

import (
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/iqhive/prefixlookup/mrtconv"
)

// these benches run against a real BGP table rather than genPrefixes -
// genPrefixes now follows the same occupancy and length mix (heavy-tailed
// ~30.7 IPv4 prefixes per occupied /16, 63% /24, IPv6 in the dump's 65 RIR
// /16 blocks), but a collector dump is still the ground truth for absolute
// latency and retained bytes: defaults, real aggregation, the exact prefix set
//
// we load PREFIXLOOKUP_TABLE when that points at a compact binary, otherwise
// we look in PREFIXLOOKUP_MRTS (default ~/mrts), convert the newest v4/v6
// pair once, and reuse the binary so the multi-gigabyte MRT parse only
// happens when a new dump arrives

const defaultMRTDir = "/home/iqdev/mrts"
const defaultRealTablePath = defaultMRTDir + "/full-table.bin"

// realTablePath is PREFIXLOOKUP_TABLE if set, else the default bin next to
// the MRT dumps - we don't Stat here, ensureRealTable does that
func realTablePath() string {
	if path := os.Getenv("PREFIXLOOKUP_TABLE"); path != "" {
		return path
	}
	return defaultRealTablePath
}

// mrtDir is PREFIXLOOKUP_MRTS if set, else the hard-coded lab path
func mrtDir() string {
	if dir := os.Getenv("PREFIXLOOKUP_MRTS"); dir != "" {
		return dir
	}
	return defaultMRTDir
}

// ensureRealTable returns the compact binary path, converting the newest
// v4-rib* / v6-rib* dumps in the MRT dir when the bin isn't there yet
//
// name comparison is string-greater so a dated filename wins; we need at
// least one family or we bail
func ensureRealTable() (string, error) {
	path := realTablePath()
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	dir := mrtDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", dir, err)
	}
	var v4, v6 string
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "v4-rib"):
			if e.Name() > v4 {
				v4 = e.Name()
			}
		case strings.HasPrefix(e.Name(), "v6-rib"):
			if e.Name() > v6 {
				v6 = e.Name()
			}
		}
	}
	if v4 == "" && v6 == "" {
		return "", fmt.Errorf("no binary table at %s and no MRT dumps in %s", path, dir)
	}
	if err := mrtconv.Convert(
		filepath.Join(dir, v4),
		filepath.Join(dir, v6),
		path,
	); err != nil {
		return "", err
	}
	return path, nil
}

type realFixture struct {
	routes  []route
	zipf    []netip.Addr
	uniform []netip.Addr
	v4Only  []netip.Addr
	v6Only  []netip.Addr
}

var (
	realOnce    sync.Once
	realCached  *realFixture
	realLoadErr error
)

// loadRealFixture is the once-per-process loader - convert/load the dump,
// stamp dummy next-hops, pre-generate the four query streams
//
// we Skip the bench if the dump isn't around rather than Fatal, so a laptop
// without ~/mrts can still run the synthetic suite
func loadRealFixture(tb testing.TB) *realFixture {
	tb.Helper()
	realOnce.Do(func() {
		path, err := ensureRealTable()
		if err != nil {
			realLoadErr = err
			return
		}
		table, err := mrtconv.Load(path)
		if err != nil {
			realLoadErr = fmt.Errorf("load %s: %w", path, err)
			return
		}
		prefixes := table.Prefixes()
		if len(prefixes) == 0 {
			realLoadErr = fmt.Errorf("%s holds no prefixes", path)
			return
		}
		routes := make([]route, len(prefixes))
		for i, prefix := range prefixes {
			routes[i] = route{prefix: prefix, next: NextHop(i + 1)}
		}
		realCached = &realFixture{
			routes:  routes,
			zipf:    genQueriesZipf(prefixes, 1<<16, 21),
			uniform: genQueriesUniform(prefixes, 1<<16, 22),
			v4Only:  realQueries(table.V4, 1<<16, 23),
			v6Only:  realQueries(table.V6, 1<<16, 24),
		}
	})
	if realLoadErr != nil {
		tb.Skipf("real table unavailable: %v", realLoadErr)
	}
	return realCached
}

// realQueries draws uniformly from one family's prefixes - that's the
// adverse case for any structure whose speed depends on a small hot set
func realQueries(prefixes []netip.Prefix, n int, seed int64) []netip.Addr {
	if len(prefixes) == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed))
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = realAddrIn(prefixes[rng.Intn(len(prefixes))], rng)
	}
	return out
}

// realAddrIn randomises the host bits of p so we land inside the prefix
// without always hitting the network address - v4 uses a mask on the
// flattened uint32, v6 flips remaining bits independently
func realAddrIn(p netip.Prefix, rng *rand.Rand) netip.Addr {
	a := p.Addr()
	prefixBits := p.Bits()
	if a.Is4() {
		v := flat4(a)
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

// BenchmarkRealTable is lookup latency on a full BGP table under four query
// streams: Zipf (hot set stays small - the forwarding-plane shape), uniform
// (working set blows cache), and one per family so a v4 specialisation
// can't hide behind mixed traffic
func BenchmarkRealTable(b *testing.B) {
	f := loadRealFixture(b)
	for _, factory := range factories {
		t := factory.new()
		t.Reset(f.routes)
		for _, stream := range []struct {
			name    string
			queries []netip.Addr
		}{
			{"zipf", f.zipf},
			{"uniform", f.uniform},
			{"v4-only", f.v4Only},
			{"v6-only", f.v6Only},
		} {
			if len(stream.queries) == 0 {
				continue
			}
			b.Run(stream.name+"/"+factory.name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				var sum uint64
				for i := 0; i < b.N; i++ {
					value, ok := t.Read(stream.queries[i&(len(stream.queries)-1)])
					sum += uint64(value)
					if ok {
						sum++
					}
				}
				sink.Store(sum)
			})
		}
		t.Close()
	}
}

// BenchmarkRealTableNoDefault is the same table with 0.0.0.0/0 and ::/0
// stripped
//
// a full BGP table carries defaults, which makes every membership query a
// hit and lets any set that detects whole-space coverage answer from a
// single bit - right answer for a FIB, wrong shape for a filter/ACL, and it
// hides the descent we're trying to measure, so we yank them
func BenchmarkRealTableNoDefault(b *testing.B) {
	f := loadRealFixture(b)
	routes := make([]route, 0, len(f.routes))
	for _, r := range f.routes {
		if r.prefix.Bits() != 0 {
			routes = append(routes, r)
		}
	}
	for _, factory := range factories {
		t := factory.new()
		t.Reset(routes)
		for _, stream := range []struct {
			name    string
			queries []netip.Addr
		}{
			{"uniform", f.uniform},
			{"v4-only", f.v4Only},
			{"v6-only", f.v6Only},
		} {
			if len(stream.queries) == 0 {
				continue
			}
			b.Run(stream.name+"/"+factory.name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				var sum uint64
				for i := 0; i < b.N; i++ {
					value, ok := t.Read(stream.queries[i&(len(stream.queries)-1)])
					sum += uint64(value)
					if ok {
						sum++
					}
				}
				sink.Store(sum)
			})
		}
		t.Close()
	}
}

// BenchmarkRealTableParallel is aggregate throughput on the full table with
// 32 workers and the uniform stream - working set exceeds cache, memory
// latency dominates, that's the many-core forwarding-plane analogue
func BenchmarkRealTableParallel(b *testing.B) {
	f := loadRealFixture(b)
	for _, factory := range factories {
		t := factory.new()
		t.Reset(f.routes)
		b.Run(factory.name, func(b *testing.B) {
			runComparativeThroughput(b, 32, func(i int) bool {
				_, ok := t.Read(f.uniform[i&(len(f.uniform)-1)])
				return ok
			})
		})
		t.Close()
	}
}

// BenchmarkRealTableMemory reports retained size of the full table - that's
// the figure that matters for a router holding one per VRF
func BenchmarkRealTableMemory(b *testing.B) {
	f := loadRealFixture(b)
	for _, factory := range memoryFactories {
		b.Run(factory.name, func(b *testing.B) {
			b.StopTimer()
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			built := factory.build(f.routes)
			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			retained := retainedBytes(before.HeapAlloc, after.HeapAlloc)
			b.ReportMetric(float64(retained), "retained-B")
			b.ReportMetric(float64(retained)/float64(len(f.routes)), "retained-B/prefix")
			b.ReportMetric(float64(len(f.routes)), "prefixes")
			b.ReportMetric(1, "measurements")
			runtime.KeepAlive(built)
			closeObject(built)
		})
	}
}
