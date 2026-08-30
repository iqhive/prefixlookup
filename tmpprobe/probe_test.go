package tmpprobe

import (
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"

	"github.com/iqhive/prefixlookup/old/soarangeset"
	"github.com/iqhive/prefixlookup/old/thinrangeset"
	"github.com/iqhive/prefixlookup/rangematch"
)

// ---- fixture replicas -------------------------------------------------------

// fibFixture replicates fibbench makeFixture(size) prefix generation - optional
// defaults then a mix of v6 (every 8th) and v4, length from i% so it's dense enough
func fibFixture(size int, withDefaults bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, size+2)
	if withDefaults {
		out = append(out, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	}
	for i := 0; i < size; i++ {
		if i&7 == 0 {
			a := [16]byte{0x20, 1, 0xd, 0xb8, byte(i >> 16), byte(i >> 8), byte(i)}
			bits := 32 + i%97
			out = append(out, netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked())
		} else {
			a := [4]byte{10 + byte(i>>20), byte(i >> 12), byte(i >> 4), byte(i << 4)}
			bits := 8 + i%25
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked())
		}
	}
	return out
}

var v4LengthDistribution = []struct{ bits, weight int }{
	{8, 1}, {9, 1}, {10, 3}, {11, 9}, {12, 26}, {13, 52}, {14, 105}, {15, 190},
	{16, 1229}, {17, 759}, {18, 1227}, {19, 2360}, {20, 4261}, {21, 5071},
	{22, 10517}, {23, 10769}, {24, 63320},
	{25, 13}, {26, 13}, {27, 13}, {28, 12}, {29, 17}, {30, 10}, {31, 3}, {32, 19},
}

var v6LengthDistribution = []struct{ bits, weight int }{
	{16, 1}, {19, 1}, {20, 5}, {21, 1}, {22, 2}, {23, 2}, {24, 19},
	{25, 5}, {26, 7}, {27, 7}, {28, 62}, {29, 2187}, {30, 281}, {31, 143},
	{32, 10401}, {33, 2229}, {34, 2124}, {35, 751}, {36, 3671}, {37, 501},
	{38, 1053}, {39, 715}, {40, 9258}, {41, 697}, {42, 1169}, {43, 559},
	{44, 10146}, {45, 1703}, {46, 2306}, {47, 3579}, {48, 46285},
	{50, 1}, {51, 1}, {52, 11}, {55, 1}, {56, 33}, {63, 1}, {64, 78},
	{80, 1}, {112, 1}, {118, 1}, {123, 2}, {124, 1}, {125, 1}, {128, 2},
}

const (
	v4PerOccupied16 = 30.69
	v6Occupied16s   = 65
)

// picker flattens a weighted {bits,weight} table into a slice we can Intn -
// yes it's a bit wasteful, we don't care, this is probe code
func picker(d []struct{ bits, weight int }) []int {
	var t []int
	for _, e := range d {
		for i := 0; i < e.weight; i++ {
			t = append(t, e.bits)
		}
	}
	return t
}

var v4L = picker(v4LengthDistribution)
var v6L = picker(v6LengthDistribution)

// v4HomeCount estimates how many distinct /16s a dump-shaped v4 table of n4
// prefixes would occupy - divide by the measured mean, shave a tiny overlap
// fudge, then clamp to [1, 222*256]
func v4HomeCount(n4 int) int {
	if n4 <= 0 {
		return 0
	}
	h := int(float64(n4)/v4PerOccupied16 + 0.5)
	h -= int(float64(n4)*0.00065 + 0.5)
	if h < 1 {
		h = 1
	}
	const maxHomes = 222 * 256
	if h > maxHomes {
		h = maxHomes
	}
	return h
}

// v6HomeCount does the same idea for v6, except real tables only fill ~65 of
// the 2000::/3 /16s so we cap there - if n6 is smaller we just use n6 homes
func v6HomeCount(n6 int) int {
	if n6 <= 0 {
		return 0
	}
	if n6 < v6Occupied16s {
		return n6
	}
	return v6Occupied16s
}

// sampleHomes picks n unique /16 identifiers - first() supplies the high byte
// (v4 unicast-ish, or a v6 RIR /8) and we randomise the second, skipping dupes
func sampleHomes(rng *rand.Rand, n int, first func() byte) [][2]byte {
	homes := make([][2]byte, 0, n)
	seen := make(map[uint16]struct{}, n)
	for len(homes) < n {
		a, b := first(), byte(rng.Intn(256))
		k := uint16(a)<<8 | uint16(b)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		homes = append(homes, [2]byte{a, b})
	}
	return homes
}

// genPrefixes follows fibbench/workload_test.go for length mix and IPv6 RIR
// /16s - we sample homes, then fill with dump-weighted lengths; occupancy
// clustering and parent-attachment still live in fibbench, we don't bother here
func genPrefixes(n int, mix float64, seed int64) []netip.Prefix {
	rng := rand.New(rand.NewSource(seed))
	n6 := int(float64(n)*mix + 0.5)
	if n6 > n {
		n6 = n
	}
	n4 := n - n6
	// v4 homes: first octet 1..222 so we stay out of 0/223+ multicast
	v4homes := sampleHomes(rng, v4HomeCount(n4), func() byte { return byte(1 + rng.Intn(222)) })
	// v6 homes: pick a RIR /8 (2000::/3-ish) then a random second octet
	v6homes := sampleHomes(rng, v6HomeCount(n6), func() byte {
		switch rng.Intn(6) {
		case 0:
			return 0x20
		case 1:
			return 0x24
		case 2:
			return 0x26
		case 3:
			return 0x28
		case 4:
			return 0x2a
		default:
			return 0x2c
		}
	})
	seen := make(map[netip.Prefix]bool, n)
	out := make([]netip.Prefix, 0, n)
	// add fills until we hit want prefixes, sampling a home /16 then a random
	// host+length from the dump histogram - skip dupes via seen
	add := func(want int, homes [][2]byte, v6 bool) {
		if len(homes) == 0 {
			return
		}
		for len(out) < want {
			var p netip.Prefix
			home := homes[rng.Intn(len(homes))]
			if v6 {
				bits := v6L[rng.Intn(len(v6L))]
				var b [16]byte
				b[0], b[1] = home[0], home[1]
				for i := 2; i < len(b); i++ {
					b[i] = byte(rng.Intn(256))
				}
				p = netip.PrefixFrom(netip.AddrFrom16(b), bits).Masked()
			} else {
				bits := v4L[rng.Intn(len(v4L))]
				b := [4]byte{home[0], home[1], byte(rng.Intn(256)), byte(rng.Intn(256))}
				p = netip.PrefixFrom(netip.AddrFrom4(b), bits).Masked()
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	add(n4, v4homes, false)
	add(n, v6homes, true)
	return out
}

// ---- struct sizes -----------------------------------------------------------

// r4/r6/rmSet clone rangematch's layout so we can sizeof without peeking internals
type r4 struct{ first, last uint32 }
type r6 struct{ firstHi, firstLo, lastHi, lastLo uint64 }

// lite5Set / lite4Set / lite3Set are header-only stand-ins for the old set variants
type lite5Set struct {
	v4First, v4Last, v4Front []uint64
	f1, f2, f3, f4           []uint64
}
type lite4Set struct {
	a, b, c, d, e []uint64
}
type rmSet struct {
	v4      []r4
	v6      []r6
	v4Front [1 << 16]uint8
}
type lite3Set struct {
	v4    []r4
	v6    []r6
	front [65536 * 2 / 64]uint64
}

// TestSizes prints header sizeofs for the range-set layouts we're comparing -
// just unsafe.Sizeof on zero values, nothing allocated
func TestSizes(t *testing.T) {
	fmt.Printf("sizeof range4=%d range6=%d\n", unsafe.Sizeof(r4{}), unsafe.Sizeof(r6{}))
	fmt.Printf("sizeof lite5.Set(header)=%d lite4.Set(header)=%d rangematch.Set=%d lite3.Set=%d\n",
		unsafe.Sizeof(lite5Set{}), unsafe.Sizeof(lite4Set{}), unsafe.Sizeof(rmSet{}), unsafe.Sizeof(lite3Set{}))
}

// ---- retained-bytes measurement --------------------------------------------

// retained estimates heap bytes kept by build() - double GC, snapshot HeapAlloc,
// construct, GC again, subtract; we return the object so the caller can KeepAlive
func retained(build func() any) (uint64, any) {
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	obj := build()
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc <= before.HeapAlloc {
		return 0, obj
	}
	return after.HeapAlloc - before.HeapAlloc, obj
}

// report builds thinrangeset / soarangeset / rangematch on pfx and prints
// merged-range count plus retained bytes per prefix - KeepAlive so the GC
// can't eat the set before we read Ranges
func report(t *testing.T, label string, pfx []netip.Prefix) {
	n := len(pfx)
	{
		// thinrangeset (lite5) - type-assert after retained so Ranges() is live
		b, obj := retained(func() any { s, _ := thinrangeset.New(pfx); return s })
		s := obj.(*thinrangeset.Set)
		fmt.Printf("%-34s n=%7d lite5      ranges=%7d retained=%10d B  %.4f B/prefix\n", label, n, s.Ranges(), b, float64(b)/float64(n))
		runtime.KeepAlive(s)
	}
	{
		// soarangeset (lite4) - same retained recipe
		b, obj := retained(func() any { s, _ := soarangeset.New(pfx); return s })
		s := obj.(*soarangeset.Set)
		fmt.Printf("%-34s n=%7d lite4      ranges=%7d retained=%10d B  %.4f B/prefix\n", label, n, s.Ranges(), b, float64(b)/float64(n))
		runtime.KeepAlive(s)
	}
	{
		// rangematch - the one we're actually keeping
		b, obj := retained(func() any { s, _ := rangematch.New(pfx); return s })
		s := obj.(*rangematch.Set)
		fmt.Printf("%-34s n=%7d rangematch ranges=%7d retained=%10d B  %.4f B/prefix\n", label, n, s.Ranges(), b, float64(b)/float64(n))
		runtime.KeepAlive(s)
	}
	fmt.Println()
}

// TestRetained runs report across fib-fixture and dump-mix generators so we
// can see whether defaults / v6 mix change retained bytes
func TestRetained(t *testing.T) {
	report(t, "fib-fixture-100k (WITH defaults)", fibFixture(100_000, true))
	report(t, "fib-fixture-100k (NO defaults)", fibFixture(100_000, false))
	report(t, "genPrefixes 100k dump mix", genPrefixes(100_000, 0.1865, 3))
	report(t, "genPrefixes 200k v4-only", genPrefixes(200_000, 0, 9))
	report(t, "genPrefixes 200k v6-only", genPrefixes(200_000, 1, 9))
	report(t, "genPrefixes 1M dump mix", genPrefixes(1_000_000, 0.1865, 3))
}

// ---- range-count-only survey (no GC noise) ---------------------------------

// TestRangeCounts prints merged-range ratios for thinrangeset only - cheaper
// than retained() when we just want to know how well intervals collapse
func TestRangeCounts(t *testing.T) {
	for _, c := range []struct {
		name string
		pfx  []netip.Prefix
	}{
		{"fib 1k with defaults", fibFixture(1_000, true)},
		{"fib 1k no defaults", fibFixture(1_000, false)},
		{"fib 100k no defaults", fibFixture(100_000, false)},
		{"fib 1M no defaults", fibFixture(1_000_000, false)},
		{"gen 100k dump mix", genPrefixes(100_000, 0.1865, 3)},
		{"gen 500k dump mix", genPrefixes(500_000, 0.1865, 5)},
		{"gen 200k v4only", genPrefixes(200_000, 0, 9)},
		{"gen 200k v6only", genPrefixes(200_000, 1, 9)},
	} {
		s, err := thinrangeset.New(c.pfx)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%-24s inputs=%8d mergedRanges=%8d ratio=%.3f\n", c.name, len(c.pfx), s.Ranges(), float64(s.Ranges())/float64(len(c.pfx)))
	}
}

// ---- latency ---------------------------------------------------------------

// addrIn picks a random address inside p by filling host bits - v4 OR-masks a
// uint32, v6 flips remaining bits independently so we don't bias towards /64s
func addrIn(p netip.Prefix, rng *rand.Rand) netip.Addr {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		v := [4]byte(a.As4())
		u := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		if bits < 32 {
			u |= rng.Uint32() & (^uint32(0) >> uint(bits))
		}
		return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	}
	b := a.As16()
	for i := bits; i < 128; i++ {
		if rng.Intn(2) == 1 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	return netip.AddrFrom16(b)
}

// queries builds n in-prefix addresses by sampling pfx uniformly - used as
// the Match workload so hitrate is high and we're timing the hot path
func queries(pfx []netip.Prefix, n int, seed int64) []netip.Addr {
	rng := rand.New(rand.NewSource(seed))
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = addrIn(pfx[rng.Intn(len(pfx))], rng)
	}
	return out
}

// BenchmarkLat times Match for lite5 / lite4 / rangematch across a few tables -
// 64k queries, power-of-two wrap via i&(len-1), ReportMetric for hitrate
func BenchmarkLat(b *testing.B) {
	cases := []struct {
		name string
		pfx  []netip.Prefix
	}{
		{"fib100k_withdefaults", fibFixture(100_000, true)},
		{"fib100k_nodefaults", fibFixture(100_000, false)},
		{"gen200k_v4only", genPrefixes(200_000, 0, 9)},
		{"gen200k_v6only", genPrefixes(200_000, 1, 9)},
		{"gen1M_dumpmix", genPrefixes(1_000_000, 0.1865, 3)},
	}
	for _, c := range cases {
		q := queries(c.pfx, 1<<16, 10)
		s5, _ := thinrangeset.New(c.pfx)
		s4, _ := soarangeset.New(c.pfx)
		sm, _ := rangematch.New(c.pfx)
		// lite5 Match loop - wrap with i&(len-1) because len(q) is a power of two
		b.Run(c.name+"/lite5_r"+fmt.Sprint(s5.Ranges()), func(b *testing.B) {
			hit := 0
			for i := 0; i < b.N; i++ {
				if s5.Match(q[i&(len(q)-1)]) {
					hit++
				}
			}
			b.ReportMetric(float64(hit)/float64(b.N), "hitrate")
		})
		// same loop against soarangeset (lite4)
		b.Run(c.name+"/lite4", func(b *testing.B) {
			hit := 0
			for i := 0; i < b.N; i++ {
				if s4.Match(q[i&(len(q)-1)]) {
					hit++
				}
			}
			b.ReportMetric(float64(hit)/float64(b.N), "hitrate")
		})
		// and rangematch, the layout we actually ship
		b.Run(c.name+"/rangematch", func(b *testing.B) {
			hit := 0
			for i := 0; i < b.N; i++ {
				if sm.Match(q[i&(len(q)-1)]) {
					hit++
				}
			}
			b.ReportMetric(float64(hit)/float64(b.N), "hitrate")
		})
	}
}
