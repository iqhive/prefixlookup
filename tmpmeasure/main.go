package main

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/iqhive/prefixlookup/internal/addrkey"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// routeEntry is a stand-in for the payload we used to hang off each route so
// we can sizeof it next to netip / addrkey without pulling in the real table
type routeEntry[V any] struct {
	prefix netip.Prefix
	value  V
	parent uint32
	end    uint32
}

// main prints sizeof for the types we keep arguing about in reviews - unsafe
// Sizeof on zero values, then we touch a Prefix so the compiler doesn't
// dead-code the import of MustParsePrefix
func main() {
	fmt.Printf("netip.Addr            = %d bytes\n", unsafe.Sizeof(netip.Addr{}))
	fmt.Printf("netip.Prefix          = %d bytes\n", unsafe.Sizeof(netip.Prefix{}))
	fmt.Printf("addrkey.Key           = %d bytes\n", unsafe.Sizeof(addrkey.Key{}))
	fmt.Printf("addrkey.PrefixKey     = %d bytes\n", unsafe.Sizeof(addrkey.PrefixKey{}))
	fmt.Printf("prefixentry.Entry[u32]= %d bytes\n", unsafe.Sizeof(prefixentry.Entry[uint32]{}))
	fmt.Printf("routeEntry[uint32]    = %d bytes\n", unsafe.Sizeof(routeEntry[uint32]{}))
	fmt.Printf("routeEntry[any]       = %d bytes\n", unsafe.Sizeof(routeEntry[any]{}))
	var p netip.Prefix = netip.MustParsePrefix("10.0.0.0/8")
	_ = p // keep MustParsePrefix referenced so this file still compiles
}
