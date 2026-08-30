package groupartset

import (
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"
)

// TestZZSizes dumps sizeof/alignof/offsetof for bitGroup, setNode, setLeaf, Set
// we print rather than assert, this is a layout probe
func TestZZSizes(t *testing.T) {
	fmt.Printf("sizeof bitGroup = %d, align=%d\n", unsafe.Sizeof(bitGroup{}), unsafe.Alignof(bitGroup{}))
	fmt.Printf("sizeof setNode  = %d (groups=%d children=%d leaves=%d pfxIdx=%d)\n",
		unsafe.Sizeof(setNode{}),
		unsafe.Sizeof([4]bitGroup{}),
		unsafe.Sizeof([]*setNode{}),
		unsafe.Sizeof([]setLeaf{}),
		unsafe.Sizeof([]uint16{}))
	fmt.Printf("sizeof setLeaf  = %d align=%d\n", unsafe.Sizeof(setLeaf{}), unsafe.Alignof(setLeaf{}))
	fmt.Printf("sizeof Set      = %d (front=%d)\n", unsafe.Sizeof(Set{}), unsafe.Sizeof([65536*2/64]uint64{}))
	fmt.Printf("offsets: groups=%d children=%d leaves=%d pfxIdx=%d\n",
		unsafe.Offsetof(setNode{}.groups), unsafe.Offsetof(setNode{}.children),
		unsafe.Offsetof(setNode{}.leaves), unsafe.Offsetof(setNode{}.pfxIdx))
	fmt.Printf("Set offsets: root4=%d root6=%d size4=%d front=%d hasV4=%d\n",
		unsafe.Offsetof(Set{}.root4), unsafe.Offsetof(Set{}.root6), unsafe.Offsetof(Set{}.size4),
		unsafe.Offsetof(Set{}.front), unsafe.Offsetof(Set{}.hasV4))
	// bitGroup field offsets so we can see if the pad moved
	fmt.Printf("bitGroup offsets: cover=%d leafMask=%d childMask=%d leafRank=%d childRank=%d\n",
		unsafe.Offsetof(bitGroup{}.cover), unsafe.Offsetof(bitGroup{}.leafMask),
		unsafe.Offsetof(bitGroup{}.childMask), unsafe.Offsetof(bitGroup{}.leafRank),
		unsafe.Offsetof(bitGroup{}.childRank))
}

// ---- structural census ----

// census is the pile of node/leaf/pfx counters visit fills in
type census struct {
	nodes       int
	nodesByD    [17]int
	leaves      int
	leavesByD   [17]int
	pfx         int
	pfxByD      [17]int
	childSlots  int
	childCap    int
	leafCap     int
	pfxCap      int
	childHist   [257]int // len(children) histogram
	leafHist    [257]int
	pfxHist     [513]int
	nodesWithNoPfx int
}

// visit walks n and fills in node/leaf/pfx histograms by depth
// recursive, we don't care, this is offline
func (c *census) visit(n *setNode, depth int) {
	c.nodes++
	c.nodesByD[depth]++
	c.leaves += len(n.leaves)
	c.leavesByD[depth] += len(n.leaves)
	c.pfx += len(n.pfxIdx)
	c.pfxByD[depth] += len(n.pfxIdx)
	c.childSlots += len(n.children)
	c.childCap += cap(n.children)
	c.leafCap += cap(n.leaves)
	c.pfxCap += cap(n.pfxIdx)
	if len(n.children) < len(c.childHist) {
		c.childHist[len(n.children)]++
	}
	if len(n.leaves) < len(c.leafHist) {
		c.leafHist[len(n.leaves)]++
	}
	if len(n.pfxIdx) < len(c.pfxHist) {
		c.pfxHist[len(n.pfxIdx)]++
	}
	if len(n.pfxIdx) == 0 {
		c.nodesWithNoPfx++
	}
	for _, ch := range n.children {
		c.visit(ch, depth+1)
	}
}

// classes is the Go allocator size-class table sizeclass scans
var classes = []int{0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
	288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536,
	1792, 2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192,
	9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264, 28672, 32768}

// sizeclass maps n onto the Go allocator size class
// scan the table, then round up to 8k for huge slices
func sizeclass(n int) int {
	if n == 0 {
		return 0
	}
	for _, c := range classes {
		if n <= c {
			return c
		}
	}
	return (n + 8191) / 8192 * 8192
}

// buildSpec builds the 100k-prefix design-task set (87.5k v4 in 10/8, 12.5k
// v6 in 2001:db8::/32) and inserts it into a Set. seeded so it's repeatable
func buildSpec(t *testing.T) ([]netip.Prefix, *Set) {
	rng := rand.New(rand.NewSource(42))
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	// 87.5k IPv4 inside 10.0.0.0/8, lengths 8..32
	for len(out) < 87500 {
		bits := 8 + rng.Intn(25)
		b := [4]byte{10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		p := netip.PrefixFrom(netip.AddrFrom4(b), bits).Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	// 12.5k IPv6 inside 2001:db8::/32, lengths 32..128
	for len(out) < 100000 {
		bits := 32 + rng.Intn(97)
		var b [16]byte
		b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
		for i := 4; i < 16; i++ {
			b[i] = byte(rng.Intn(256))
		}
		p := netip.PrefixFrom(netip.AddrFrom16(b), bits).Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	s := New()
	for _, p := range out {
		s.Insert(p)
	}
	if s.Size() != 100000 {
		t.Fatalf("size %d", s.Size())
	}
	return out, s
}

// TestZZCensus walks both tries after buildSpec and prints node/leaf/pfx
// histograms plus size-classed byte estimates. prints only
func TestZZCensus(t *testing.T) {
	pfxs, s := buildSpec(t)
	_ = pfxs

	for name, root := range map[string]*setNode{"v4": &s.root4, "v6": &s.root6} {
		var c census
		c.visit(root, 0)
		nodeBytes := c.nodes * int(unsafe.Sizeof(setNode{}))
		// heap allocation for each node (except roots which are embedded in Set)
		nodeAlloc := (c.nodes - 1) * sizeclass(int(unsafe.Sizeof(setNode{})))
		childBytes := 0
		leafBytes := 0
		pfxBytes := 0
		// recur walks the trie adding size-classed slice capacities
		var recur func(n *setNode)
		recur = func(n *setNode) {
			if cap(n.children) > 0 {
				childBytes += sizeclass(cap(n.children) * 8)
			}
			if cap(n.leaves) > 0 {
				leafBytes += sizeclass(cap(n.leaves) * int(unsafe.Sizeof(setLeaf{})))
			}
			if cap(n.pfxIdx) > 0 {
				pfxBytes += sizeclass(cap(n.pfxIdx) * 2)
			}
			for _, ch := range n.children {
				recur(ch)
			}
		}
		recur(root)
		fmt.Printf("\n=== %s ===\n", name)
		fmt.Printf("nodes=%d leaves=%d pfxIdx=%d childSlots=%d\n", c.nodes, c.leaves, c.pfx, c.childSlots)
		fmt.Printf("nodesByDepth=%v\n", c.nodesByD[:9])
		fmt.Printf("leavesByDepth=%v\n", c.leavesByD[:17])
		fmt.Printf("pfxByDepth=%v\n", c.pfxByD[:17])
		fmt.Printf("nodes with zero pfxIdx = %d\n", c.nodesWithNoPfx)
		fmt.Printf("caps: childCap=%d leafCap=%d pfxCap=%d\n", c.childCap, c.leafCap, c.pfxCap)
		fmt.Printf("bytes: nodeStruct=%d nodeAllocSizeClassed=%d childSlices=%d leafSlices=%d pfxSlices=%d total=%d\n",
			nodeBytes, nodeAlloc, childBytes, leafBytes, pfxBytes, nodeAlloc+childBytes+leafBytes+pfxBytes)
		// child slice length histogram summary
		fmt.Printf("children len hist (0..8): %v ; >=9: ", c.childHist[:9])
		big := 0
		for i := 9; i < len(c.childHist); i++ {
			big += c.childHist[i]
		}
		fmt.Printf("%d\n", big)
		fmt.Printf("leaves len hist (0..8): %v ; >=9: ", c.leafHist[:9])
		big = 0
		for i := 9; i < len(c.leafHist); i++ {
			big += c.leafHist[i]
		}
		fmt.Printf("%d\n", big)
	}
}

// TestZZRetained snapshots HeapAlloc around buildSpec
// includes the []netip.Prefix input, so the B/pfx figure is pessimistic
func TestZZRetained(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	_, s := buildSpec(t)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// the prefix slice itself is also retained, subtract an estimate
	retained := after.HeapAlloc - before.HeapAlloc
	fmt.Printf("retained total = %d bytes, %.3f B/pfx (includes the []netip.Prefix input of ~%d bytes)\n",
		retained, float64(retained)/100000.0, 100000*24)
	runtime.KeepAlive(s)
}

// TestZZRetainedSetOnly builds the prefixes first so they aren't counted in
// the HeapAlloc delta, then inserts into a Set. closer to true retained size
func TestZZRetainedSetOnly(t *testing.T) {
	// build the prefixes first so they are not counted in the delta
	rng := rand.New(rand.NewSource(42))
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for len(out) < 87500 {
		bits := 8 + rng.Intn(25)
		b := [4]byte{10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		p := netip.PrefixFrom(netip.AddrFrom4(b), bits).Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	for len(out) < 100000 {
		bits := 32 + rng.Intn(97)
		var b [16]byte
		b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
		for i := 4; i < 16; i++ {
			b[i] = byte(rng.Intn(256))
		}
		p := netip.PrefixFrom(netip.AddrFrom16(b), bits).Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	seen = nil
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	s := New()
	for _, p := range out {
		s.Insert(p)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	retained := after.HeapAlloc - before.HeapAlloc
	fmt.Printf("SET ONLY retained = %d bytes, %.4f B/pfx\n", retained, float64(retained)/100000.0)
	runtime.KeepAlive(out)
	runtime.KeepAlive(s)
}

// ---- dependent-load / hop instrumentation ----

// hopStat tallies how Contains resolved: front-only vs cover/leaf/miss, and hops
type hopStat struct {
	nodeHops   int // number of setNode dereferences (pointer chases)
	frontOnly  int
	coverHit   int
	leafHit    int
	childMiss  int
	depthMax   int
	total      int
	byHops     [20]int
	frontCode  [3]int
}

// instrContains4 is Contains for v4 with hop/front-code instrumentation
// same control flow as contains4, we just tally which path we took
func (s *Set) instrContains4(key uint32, st *hopStat) bool {
	st.total++
	if !s.hasV4 {
		return false
	}
	code := s.getFront(key >> 16)
	st.frontCode[code]++
	switch code {
	case frontNone:
		st.frontOnly++
		st.byHops[0]++
		return false
	case frontAll:
		st.frontOnly++
		st.byHops[0]++
		return true
	}
	hi := uint64(key) << 32
	n := &s.root4
	hops := 1 // root4 is inside Set, still a load of its groups
	for depth := 0; depth < 2; depth++ {
		octet := uint(byte(key >> (24 - depth*8)))
		g := &n.groups[octet>>6]
		bit := uint64(1) << (octet & 63)
		if g.leafMask&bit != 0 {
			st.leafHit++
			st.byHops[hops+1]++
			st.nodeHops += hops
			return n.leaves[int(g.leafRank)+onesbelow(g.leafMask, bit)].covers(hi, 0)
		}
		if g.childMask&bit == 0 {
			st.childMiss++
			st.byHops[hops]++
			st.nodeHops += hops
			return false
		}
		n = n.children[int(g.childRank)+onesbelow(g.childMask, bit)]
		hops++
	}
	for depth := 2; ; depth++ {
		octet := uint(byte(key >> (24 - depth*8)))
		g := &n.groups[octet>>6]
		bit := uint64(1) << (octet & 63)
		if g.cover&bit != 0 {
			st.coverHit++
			st.byHops[hops]++
			st.nodeHops += hops
			return true
		}
		if g.leafMask&bit != 0 {
			st.leafHit++
			st.byHops[hops+1]++
			st.nodeHops += hops
			return n.leaves[int(g.leafRank)+onesbelow(g.leafMask, bit)].covers(hi, 0)
		}
		if depth == 3 || g.childMask&bit == 0 {
			st.childMiss++
			st.byHops[hops]++
			st.nodeHops += hops
			return false
		}
		n = n.children[int(g.childRank)+onesbelow(g.childMask, bit)]
		hops++
	}
}

// onesbelow counts set bits in mask strictly below bit
// Kernighan loop rather than bits.OnesCount64 so we can see it in profiles
func onesbelow(mask, bit uint64) int {
	m := mask & (bit - 1)
	c := 0
	for m != 0 {
		m &= m - 1
		c++
	}
	return c
}

// instrContains6 is Contains for v6 with hop instrumentation
// same descent as Contains, plus depthMax tracking
func (s *Set) instrContains6(addr netip.Addr, st *hopStat) bool {
	st.total++
	hi, lo := words16(addr.As16())
	n := &s.root6
	key := hi
	hops := 1
	for depth := 0; ; depth++ {
		if depth == 8 {
			key = lo
		}
		octet := uint(byte(key >> (56 - (depth&7)*8)))
		g := &n.groups[octet>>6]
		bit := uint64(1) << (octet & 63)
		if g.cover&bit != 0 {
			st.coverHit++
			st.byHops[hops]++
			st.nodeHops += hops
			if depth > st.depthMax {
				st.depthMax = depth
			}
			return true
		}
		if g.leafMask&bit != 0 {
			st.leafHit++
			st.byHops[hops+1]++
			st.nodeHops += hops
			if depth > st.depthMax {
				st.depthMax = depth
			}
			return n.leaves[int(g.leafRank)+onesbelow(g.leafMask, bit)].covers(hi, lo)
		}
		if depth == 15 || g.childMask&bit == 0 {
			st.childMiss++
			st.byHops[hops]++
			st.nodeHops += hops
			if depth > st.depthMax {
				st.depthMax = depth
			}
			return false
		}
		n = n.children[int(g.childRank)+onesbelow(g.childMask, bit)]
		hops++
	}
}

// TestZZHops instruments Contains against buildSpec: hits inside stored
// prefixes, misses in 240/4, and misses inside 10/8 so we have to descend
func TestZZHops(t *testing.T) {
	pfxs, s := buildSpec(t)
	rng := rand.New(rand.NewSource(7))
	// hit queries: random address inside a random stored prefix
	var st4hit, st4miss, st6hit hopStat
	n4, n6 := 0, 0
	for i := 0; i < 200000; i++ {
		p := pfxs[rng.Intn(len(pfxs))]
		a := addrInside(p, rng)
		if a.Is4() {
			if !s.instrContains4(be32(a.As4()), &st4hit) {
				t.Fatalf("miss on %v (%v)", a, p)
			}
			n4++
		} else {
			if !s.instrContains6(a, &st6hit) {
				t.Fatalf("v6 miss on %v (%v)", a, p)
			}
			n6++
		}
	}
	// miss queries: 240.0.0.0/4 space, guaranteed absent
	for i := 0; i < 100000; i++ {
		key := uint32(240+rng.Intn(15))<<24 | uint32(rng.Intn(1<<24))
		if s.instrContains4(key, &st4miss) {
			t.Fatal("unexpected hit")
		}
	}
	// also: misses *inside* 10/8 (partially covered => must descend)
	var st4missIn hopStat
	for i := 0; i < 200000; i++ {
		key := uint32(10)<<24 | uint32(rng.Intn(1<<24))
		s.instrContains4(key, &st4missIn)
	}
	// dump one hopStat: averages plus the hops histogram
	report := func(name string, st *hopStat) {
		fmt.Printf("\n%s: total=%d frontOnly=%d coverHit=%d leafHit=%d childMiss=%d avgNodeHops=%.4f depthMax=%d\n",
			name, st.total, st.frontOnly, st.coverHit, st.leafHit, st.childMiss,
			float64(st.nodeHops)/float64(st.total), st.depthMax)
		fmt.Printf("  frontCodes none/all/deeper = %v\n", st.frontCode)
		fmt.Printf("  hops histogram: ")
		for i, v := range st.byHops {
			if v != 0 {
				fmt.Printf("%d:%d(%.1f%%) ", i, v, 100*float64(v)/float64(st.total))
			}
		}
		fmt.Println()
	}
	report("IPv4 HIT", &st4hit)
	report("IPv4 MISS (240/4, out of trie)", &st4miss)
	report("IPv4 MISS inside 10/8", &st4missIn)
	report("IPv6 HIT", &st6hit)
	fmt.Printf("\nquery mix: v4=%d v6=%d\n", n4, n6)
}

// addrInside picks a random host inside p
// v4 or's random bits below the prefix length, v6 flips leftover bits
func addrInside(p netip.Prefix, rng *rand.Rand) netip.Addr {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		v := be32(a.As4())
		if bits < 32 {
			v |= rng.Uint32() >> uint(bits)
		}
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := a.As16()
	for i := bits; i < 128; i++ {
		if rng.Intn(2) == 1 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	return netip.AddrFrom16(b)
}

// ---- microbench to reproduce the ns/op ----

// BenchmarkZZContains times Contains on mixed/v4/v6/miss sets built from
// buildSpec. 1<<16 unique addrs, we wrap with i%m
func BenchmarkZZContains(b *testing.B) {
	var t testing.T
	pfxs, s := buildSpec(&t)
	rng := rand.New(rand.NewSource(7))
	var v4, v6, mixed []netip.Addr
	for i := 0; i < 1<<16; i++ {
		p := pfxs[rng.Intn(len(pfxs))]
		a := addrInside(p, rng)
		mixed = append(mixed, a)
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	var miss []netip.Addr
	for i := 0; i < 1<<16; i++ {
		miss = append(miss, netip.AddrFrom4([4]byte{byte(240 + rng.Intn(15)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}))
	}
	// run one sub-benchmark over a fixed address set
	run := func(name string, set []netip.Addr) {
		b.Run(name, func(b *testing.B) {
			var sink bool
			m := len(set)
			for i := 0; i < b.N; i++ {
				sink = s.Contains(set[i%m])
			}
			_ = sink
		})
	}
	run("mixed", mixed)
	run("v4", v4)
	run("v6", v6)
	run("miss", miss)
}

// ---- fibbench-identical workload ----

var v4dist = []struct{ bits, weight int }{
	{8, 1}, {9, 1}, {10, 2}, {11, 3}, {12, 6}, {13, 11}, {14, 20}, {15, 25},
	{16, 130}, {17, 25}, {18, 40}, {19, 70}, {20, 110}, {21, 120}, {22, 190},
	{23, 160}, {24, 600}, {32, 20},
}
var v6dist = []struct{ bits, weight int }{
	{20, 1}, {24, 2}, {28, 4}, {29, 30}, {30, 6}, {31, 5}, {32, 240},
	{33, 8}, {34, 10}, {35, 6}, {36, 60}, {38, 8}, {40, 90}, {44, 60},
	{47, 40}, {48, 380}, {56, 12}, {64, 30}, {128, 8},
}

// picker expands a bits/weight table into a flat slice we can rng.Intn
func picker(d []struct{ bits, weight int }) []int {
	var t []int
	for _, x := range d {
		for i := 0; i < x.weight; i++ {
			t = append(t, x.bits)
		}
	}
	return t
}

// genFib builds n prefixes with fibbench's length mix
// mix is the v6 fraction, seed is the rng. we reject dups via a map
func genFib(n int, mix float64, seed int64) []netip.Prefix {
	v4L, v6L := picker(v4dist), picker(v6dist)
	rng := rand.New(rand.NewSource(seed))
	seen := make(map[netip.Prefix]bool, n)
	out := make([]netip.Prefix, 0, n)
	for len(out) < n {
		var p netip.Prefix
		if rng.Float64() < mix {
			bits := v6L[rng.Intn(len(v6L))]
			var b [16]byte
			b[0] = 0x20 | byte(rng.Intn(2))
			for i := 1; i < len(b); i++ {
				b[i] = byte(rng.Intn(256))
			}
			p = netip.PrefixFrom(netip.AddrFrom16(b), bits).Masked()
		} else {
			bits := v4L[rng.Intn(len(v4L))]
			b := [4]byte{byte(1 + rng.Intn(222)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
			p = netip.PrefixFrom(netip.AddrFrom4(b), bits).Masked()
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// TestZZFib is the fibbench-shaped retained-size + hop dump
// 100k prefixes, census both tries, then instrument hits and 240/4 misses
func TestZZFib(t *testing.T) {
	pfxs := genFib(100000, 0.125, 1)
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	s := New()
	for _, p := range pfxs {
		s.Insert(p)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	fmt.Printf("FIBBENCH retained = %d bytes, %.3f B/pfx\n", after.HeapAlloc-before.HeapAlloc, float64(after.HeapAlloc-before.HeapAlloc)/100000.0)

	for name, root := range map[string]*setNode{"v4": &s.root4, "v6": &s.root6} {
		var c census
		c.visit(root, 0)
		nodeAlloc := (c.nodes - 1) * sizeclass(int(unsafe.Sizeof(setNode{})))
		childBytes, leafBytes, pfxBytes := 0, 0, 0
		// recur walks the trie adding size-classed slice capacities
		var recur func(n *setNode)
		recur = func(n *setNode) {
			if cap(n.children) > 0 {
				childBytes += sizeclass(cap(n.children) * 8)
			}
			if cap(n.leaves) > 0 {
				leafBytes += sizeclass(cap(n.leaves) * int(unsafe.Sizeof(setLeaf{})))
			}
			if cap(n.pfxIdx) > 0 {
				pfxBytes += sizeclass(cap(n.pfxIdx) * 2)
			}
			for _, ch := range n.children {
				recur(ch)
			}
		}
		recur(root)
		fmt.Printf("\n=== FIB %s ===\nnodes=%d leaves=%d pfxIdx=%d\nnodesByDepth=%v\nleavesByDepth=%v\npfxByDepth=%v\nzeroPfxNodes=%d\ncaps child=%d leaf=%d pfx=%d\nbytes: nodes=%d child=%d leaf=%d pfx=%d TOTAL=%d\n",
			name, c.nodes, c.leaves, c.pfx, c.nodesByD[:17], c.leavesByD[:17], c.pfxByD[:17], c.nodesWithNoPfx,
			c.childCap, c.leafCap, c.pfxCap, nodeAlloc, childBytes, leafBytes, pfxBytes,
			nodeAlloc+childBytes+leafBytes+pfxBytes)
	}

	// hops
	rng := rand.New(rand.NewSource(7))
	var st4, st6, stmiss hopStat
	for i := 0; i < 300000; i++ {
		p := pfxs[rng.Intn(len(pfxs))]
		a := addrInside(p, rng)
		if a.Is4() {
			if !s.instrContains4(be32(a.As4()), &st4) {
				t.Fatalf("v4 miss %v in %v", a, p)
			}
		} else {
			if !s.instrContains6(a, &st6) {
				t.Fatalf("v6 miss %v in %v", a, p)
			}
		}
	}
	for i := 0; i < 100000; i++ {
		key := uint32(240+rng.Intn(15))<<24 | uint32(rng.Intn(1<<24))
		s.instrContains4(key, &stmiss)
	}
	// dump hopStat for the fibbench mix
	rep := func(name string, st *hopStat) {
		fmt.Printf("\n%s: total=%d frontOnly=%d coverHit=%d leafHit=%d childMiss=%d avgNodeTouches=%.4f maxDepth=%d\n  frontCodes[none,all,deeper]=%v\n  hopHist: ",
			name, st.total, st.frontOnly, st.coverHit, st.leafHit, st.childMiss,
			float64(st.nodeHops)/float64(st.total), st.depthMax, st.frontCode)
		for i, v := range st.byHops {
			if v != 0 {
				fmt.Printf("%d:%.2f%% ", i, 100*float64(v)/float64(st.total))
			}
		}
		fmt.Println()
	}
	rep("FIB IPv4 HIT", &st4)
	rep("FIB IPv6 HIT", &st6)
	rep("FIB IPv4 MISS", &stmiss)
	runtime.KeepAlive(s)
}

// BenchmarkZZFib is BenchmarkZZContains but on genFib(100k) instead of buildSpec
func BenchmarkZZFib(b *testing.B) {
	pfxs := genFib(100000, 0.125, 1)
	s := New()
	for _, p := range pfxs {
		s.Insert(p)
	}
	rng := rand.New(rand.NewSource(7))
	var v4, v6, mixed, miss []netip.Addr
	for i := 0; i < 1<<16; i++ {
		p := pfxs[rng.Intn(len(pfxs))]
		a := addrInside(p, rng)
		mixed = append(mixed, a)
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
		miss = append(miss, netip.AddrFrom4([4]byte{byte(240 + rng.Intn(15)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}))
	}
	// run one sub-benchmark over a fixed address set
	run := func(name string, set []netip.Addr) {
		b.Run(name, func(b *testing.B) {
			var sink bool
			m := len(set)
			for i := 0; i < b.N; i++ {
				sink = s.Contains(set[i%m])
			}
			if sink {
			}
		})
	}
	run("mixed", mixed)
	run("v4", v4)
	run("v6", v6)
	run("miss", miss)
}
