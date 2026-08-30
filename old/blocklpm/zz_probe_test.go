package blocklpm

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type nextHop uint32

// fixtureRoutes builds a mixed v4/v6 table of `size` plus default routes
// Deterministic-ish: every 8th route is v6. Used by the probe tests so we
// can print block stats against a known shape, not a real dump
func fixtureRoutes(size int) []prefixentry.Entry[nextHop] {
	routes := make([]prefixentry.Entry[nextHop], 0, size+2)
	routes = append(routes,
		prefixentry.Entry[nextHop]{netip.MustParsePrefix("0.0.0.0/0"), 1},
		prefixentry.Entry[nextHop]{netip.MustParsePrefix("::/0"), 2})
	for i := 0; i < size; i++ {
		if i&7 == 0 {
			a := [16]byte{0x20, 1, 0xd, 0xb8, byte(i >> 16), byte(i >> 8), byte(i)}
			bits := 32 + i%97
			routes = append(routes, prefixentry.Entry[nextHop]{netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked(), nextHop(i + 3)})
		} else {
			a := [4]byte{10 + byte(i>>20), byte(i >> 12), byte(i >> 4), byte(i << 4)}
			bits := 8 + i%25
			routes = append(routes, prefixentry.Entry[nextHop]{netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked(), nextHop(i + 3)})
		}
	}
	return routes
}

// TestProbeBlocks dumps compiled-FIB size stats for a 100k mixed table
// Not really a test - it's how we argued about L2/L3 block counts vs a
// pointer trie. KeepAlive so the compiler doesn't eat the table
func TestProbeBlocks(t *testing.T) {
	for _, size := range []int{100_000} {
		routes := fixtureRoutes(size)
		// dedup stats
		v4, v6 := 0, 0
		v4uniq := map[netip.Prefix]bool{}
		lenHist4 := map[int]int{}
		lenHist6 := map[int]int{}
		need2 := map[uint32]bool{}
		need3 := map[uint32]bool{}
		for _, r := range routes {
			p, _ := prefixentry.NormalizePrefix(r.Prefix)
			if v4uniq[p] {
				continue
			}
			v4uniq[p] = true
			if p.Addr().Is4() {
				v4++
				lenHist4[p.Bits()]++
				k := prefixentry.Addr4(p.Addr())
				if p.Bits() > 16 {
					need2[k>>16] = true
				}
				if p.Bits() > 24 {
					need3[k>>8] = true
				}
			} else {
				v6++
				lenHist6[p.Bits()]++
			}
		}
		var mBefore, mAfter runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&mBefore)
		tab, err := New(routes)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		runtime.ReadMemStats(&mAfter)
		fmt.Printf("=== size=%d totalEntries=%d uniquePrefixes=%d v4=%d v6=%d\n", size, len(routes), len(v4uniq), v4, v6)
		fmt.Printf("v4 len hist: %v\n", lenHist4)
		fmt.Printf("v6 len hist: %v\n", lenHist6)
		fmt.Printf("need2 (/16 blocks with >16 routes)=%d  need3 (/24 blocks with >24 routes)=%d\n", len(need2), len(need3))
		fmt.Printf("v4Root entries=%d bytes=%d\n", len(tab.v4Root), 4*len(tab.v4Root))
		fmt.Printf("v4Level2 entries=%d blocks=%d bytes=%d cap=%d capBytes=%d\n", len(tab.v4Level2), len(tab.v4Level2)/256, 4*len(tab.v4Level2), cap(tab.v4Level2), 4*cap(tab.v4Level2))
		fmt.Printf("v4Level3 entries=%d blocks=%d bytes=%d cap=%d capBytes=%d\n", len(tab.v4Level3), len(tab.v4Level3)/256, 4*len(tab.v4Level3), cap(tab.v4Level3), 4*cap(tab.v4Level3))
		fmt.Printf("v6Root entries=%d bytes=%d\n", len(tab.v6Root), 4*len(tab.v6Root))
		fmt.Printf("v6Blocks entries=%d blocks=%d bytes=%d cap=%d capBytes=%d\n", len(tab.v6Blocks), len(tab.v6Blocks)/256, 4*len(tab.v6Blocks), cap(tab.v6Blocks), 4*cap(tab.v6Blocks))
		fmt.Printf("values len=%d cap=%d bytes=%d\n", len(tab.values), cap(tab.values), 4*cap(tab.values))
		fmt.Printf("ForwardingBytes=%d (%.1f B/pfx)\n", tab.ForwardingBytes(), float64(tab.ForwardingBytes())/float64(size))
		fmt.Printf("sizeof(Table[uint32]) struct = %d\n", unsafe.Sizeof(*tab))
		retained := mAfter.HeapAlloc - mBefore.HeapAlloc
		fmt.Printf("retained heap = %d (%.1f B/pfx)\n", retained, float64(retained)/float64(size))
		runtime.KeepAlive(tab)
	}
}
