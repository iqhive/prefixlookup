package artlpm

import (
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"

	"github.com/iqhive/prefixlookup/internal/art"
)

type nh uint32

// TestZZSizes dumps struct sizes/offsets so we can see if a layout change
// blew out the node or frontEntry. we print rather than assert because this
// is a probe, not a regression test
func TestZZSizes(t *testing.T) {
	fmt.Printf("artlpm: Sizeof(node[nh])=%d Alignof=%d\n", unsafe.Sizeof(node[nh]{}), unsafe.Alignof(node[nh]{}))
	var n node[nh]
	fmt.Printf("  offsets: childBits=%d children=%d pfxCount=%d pfx=%d leafBits=%d leaves=%d\n",
		unsafe.Offsetof(n.childBits), unsafe.Offsetof(n.children), unsafe.Offsetof(n.pfxCount),
		unsafe.Offsetof(n.pfx), unsafe.Offsetof(n.leafBits), unsafe.Offsetof(n.leaves))
	fmt.Printf("artlpm: Sizeof(leaf[nh])=%d Sizeof(prefixBlock[nh])=%d Sizeof(frontEntry[nh])=%d\n",
		unsafe.Sizeof(leaf[nh]{}), unsafe.Sizeof(prefixBlock[nh]{}), unsafe.Sizeof(frontEntry[nh]{}))
	fmt.Printf("artlpm: Sizeof(Table[nh])=%d Sizeof(Bitset256)=%d Sizeof(Bitset512)=%d\n",
		unsafe.Sizeof(Table[nh]{}), unsafe.Sizeof(art.Bitset256{}), unsafe.Sizeof(art.Bitset512{}))
	// pointer-ful node: 1 slice ptr + 1 pfx ptr + 1 slice ptr = 3 pointer words scanned
}

// genSet builds the exact fixed benchmark set described in the design task:
// 87.5k IPv4 inside 10/8 with lengths 8..32, 12.5k IPv6 inside 2001:db8::/32
// with lengths 32..128. seeded rng so we get the same prefixes every run
func genSet() []netip.Prefix {
	rng := rand.New(rand.NewSource(1))
	seen := make(map[netip.Prefix]bool, 100_000)
	out := make([]netip.Prefix, 0, 100_000)
	for len(out) < 87_500 {
		bits := 8 + rng.Intn(25) // 8..32
		var b [4]byte
		b[0] = 10
		b[1], b[2], b[3] = byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))
		p := netip.PrefixFrom(netip.AddrFrom4(b), bits).Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	for len(out) < 100_000 {
		bits := 32 + rng.Intn(97) // 32..128
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
	return out
}

// census walks n and tallies nodes/kids/leaves/prefix slots by depth
// recursive, we don't care, this is offline probe code
func (n *node[V]) census(d int, st *stats) {
	st.nodes++
	st.byDepth[d]++
	st.pfxSlots += int(n.pfxCount)
	if n.pfx != nil {
		st.pfxBlocks++
		st.pfxValCap += cap(n.pfx.values)
	}
	st.leaves += len(n.leaves)
	st.leafCap += cap(n.leaves)
	st.childCap += cap(n.children)
	nkids := n.childBits.Count()
	st.children += nkids
	if nkids == 0 && n.pfxCount == 0 && len(n.leaves) == 0 {
		st.emptyNodes++
	}
	var buf [256]uint8
	for _, oct := range n.childBits.All(buf[:0]) {
		n.children[n.childBits.Rank0(uint(oct))].census(d+1, st)
	}
}

// stats is the pile of counters census fills in
type stats struct {
	nodes, children, leaves, pfxSlots, pfxBlocks, emptyNodes int
	childCap, leafCap, pfxValCap                             int
	byDepth                                                  [17]int
}

// snap forces two GCs then returns HeapAlloc/HeapObjects
// two GCs because one isn't always enough to settle the heap
func snap() (uint64, uint64) {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc, m.HeapObjects
}

// bySizeLive returns exact live bytes computed from the size-class histogram,
// which is independent of HeapAlloc bookkeeping. we skip empty classes
func bySizeLive() (bytes uint64, objs uint64, hist map[uint32]uint64) {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	hist = make(map[uint32]uint64)
	for _, c := range m.BySize {
		live := c.Mallocs - c.Frees
		if live == 0 {
			continue
		}
		hist[c.Size] = live
		bytes += uint64(c.Size) * live
		objs += live
	}
	return bytes, objs, hist
}

// TestZZCensus builds the 100k-prefix set, snapshots heap before/after Insert
// and BuildFront, then walks both tries for a structural dump. prints only
func TestZZCensus(t *testing.T) {
	pfxs := genSet()
	b0, o0 := snap()
	s0, n0, _ := bySizeLive()
	tb := New[nh]()
	for i, p := range pfxs {
		tb.Insert(p, nh(i+1))
	}
	b1, o1 := snap()
	s1, n1, h1 := bySizeLive()
	noFront := b1 - b0
	tb.BuildFront()
	b2, o2 := snap()
	s2, n2, _ := bySizeLive()
	withFront := b2 - b0
	fmt.Printf("BySize live bytes: base=%d build=%d(+%d, %.2f B/pfx) front=%d(+%d, %.2f B/pfx)\n",
		s0, s1, s1-s0, float64(s1-s0)/100000.0, s2, s2-s0, float64(s2-s0)/100000.0)
	fmt.Printf("BySize live objs: base=%d build=%d(+%d) front=%d(+%d)\n", n0, n1, n1-n0, n2, n2-n0)
	fmt.Printf("BySize histogram after build: %v\n", h1)
	fmt.Printf("heapAlloc: base=%d afterBuild=%d afterFront=%d\n", b0, b1, b2)
	fmt.Printf("heapObjects: base=%d afterBuild=%d (+%d) afterFront=%d (+%d)\n", o0, o1, o1-o0, o2, o2-o1)

	var s4, s6 stats
	tb.root4.census(0, &s4)
	tb.root6.census(0, &s6)
	fmt.Printf("artlpm v4: %+v\n", s4)
	fmt.Printf("artlpm v6: %+v\n", s6)
	fmt.Printf("artlpm retained (no front) = %d B = %.2f B/pfx\n", noFront, float64(noFront)/float64(len(pfxs)))
	fmt.Printf("artlpm retained (with front) = %d B = %.2f B/pfx  (front alone %d B)\n",
		withFront, float64(withFront)/float64(len(pfxs)), withFront-noFront)
	fmt.Printf("size4=%d size6=%d\n", tb.Size4(), tb.Size6())
	runtime.KeepAlive(tb)
	runtime.KeepAlive(pfxs)
}
