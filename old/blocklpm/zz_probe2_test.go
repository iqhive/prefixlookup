package blocklpm

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// TestProbeV6BlockDepths walks the throwaway v6 build trie the same way
// compile6 does and prints how many 256-entry blocks land at each byte
// depth. That's the argument against a full 8-bit-stride v6 FIB: deep
// uniques get expensive fast. Also dumps the v4 L2/L3 block arithmetic
func TestProbeV6BlockDepths(t *testing.T) {
	routes := fixtureRoutes(100_000)
	root := new(build6Node)
	n6 := 0
	for _, r := range routes {
		p, ok := prefixentry.NormalizePrefix(r.Prefix)
		if !ok || p.Addr().Is4() {
			continue
		}
		n6++
		hi, lo := prefixentry.Addr6(p.Addr())
		insertCompiled6(root, compiled6Entry{hi, lo, uint8(p.Bits()), uint32(n6)})
	}
	byDepth := map[int]int{}
	// walk counts a block at this stride then recurses, mirroring compile6Slot
	var walk func(n *build6Node, stride int)
	walk = func(n *build6Node, stride int) {
		if n == nil {
			return
		}
		if len(n.child) == 0 || stride >= 16 {
			return
		}
		byDepth[stride]++
		for _, c := range n.child {
			walk(c, stride+1)
		}
	}
	// mirror compile6: root children expanded into v6Root, recursion starts at stride 2
	for _, c1 := range root.child {
		for _, c2 := range c1.child {
			walk(c2, 2)
		}
	}
	total := 0
	for d := 2; d < 16; d++ {
		total += byDepth[d]
		fmt.Printf("v6 blocks at byte-depth %2d (/%3d nodes): %7d  = %10d bytes\n", d, d*8, byDepth[d], byDepth[d]*1024)
	}
	fmt.Printf("v6 total blocks=%d bytes=%d  (v6 prefix count=%d -> %.0f B/v6pfx)\n",
		total, total*1024, n6, float64(total*1024)/float64(n6))

	// distinct /24 and /16 IPv4 block arithmetic
	seen := map[netip.Prefix]bool{}
	n16, n24 := map[uint32]bool{}, map[uint32]bool{}
	byLen := map[int]int{}
	for _, r := range routes {
		p, ok := prefixentry.NormalizePrefix(r.Prefix)
		if !ok || !p.Addr().Is4() || seen[p] {
			continue
		}
		seen[p] = true
		byLen[p.Bits()]++
		k := prefixentry.Addr4(p.Addr())
		if p.Bits() > 16 {
			n16[k>>16] = true
		}
		if p.Bits() > 24 {
			n24[k>>8] = true
		}
	}
	fmt.Printf("ipv4: distinct /16 needing L2=%d (=%d bytes), distinct /24 needing L3=%d (=%d bytes)\n",
		len(n16), len(n16)*1024, len(n24), len(n24)*1024)
}
