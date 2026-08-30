package tests_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/aromatt/netipds"
	"github.com/gaissmai/bart"
	"github.com/iqhive/prefixlookup/artlpm"
	"github.com/kentik/patricia"
	patricia32 "github.com/kentik/patricia/uint32_tree"
	iptrie "github.com/phemmer/go-iptrie"
	"github.com/yl2chen/cidranger"
	"tailscale.com/net/art"
)

// TestBenchmarkCompetitorsAgree is the "are we even measuring the same
// problem" check for the fibbench competitor set - tiny nested v4 + v6
// prefixes, a handful of hit/miss queries, every library stuffed the same
// way, then we demand they all match the oracle
//
// membership-only libs (netipds, cidranger) only get the bool; value libs
// get the uint32 payload too - kentik needs the v4 addr flattened via
// address4 because their API is the old uint32 host-order thing
func TestBenchmarkCompetitorsAgree(t *testing.T) {
	type entry struct {
		prefix netip.Prefix
		value  uint32
	}
	entries := []entry{
		{netip.MustParsePrefix("10.0.0.0/8"), 1},
		{netip.MustParsePrefix("10.1.0.0/16"), 2},
		{netip.MustParsePrefix("10.1.2.0/24"), 3},
		{netip.MustParsePrefix("2001:db8::/32"), 4},
		{netip.MustParsePrefix("2001:db8:1::/48"), 5},
	}
	queries := []netip.Addr{
		netip.MustParseAddr("10.1.2.3"),
		netip.MustParseAddr("10.1.9.9"),
		netip.MustParseAddr("10.9.9.9"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8:1::1"),
		netip.MustParseAddr("2001:db8:2::1"),
		netip.MustParseAddr("2001:4860::1"),
	}

	oracle := newOracle()
	current := artlpm.New[uint32]()
	bt := new(bart.Table[uint32])
	fast := new(bart.Fast[uint32])
	tailscale := new(art.Table[uint32])
	trie := iptrie.NewTrie()
	loader := iptrie.NewTrieLoader(trie)
	v4, v6 := patricia32.NewTreeV4(), patricia32.NewTreeV6()
	var setBuilder netipds.PrefixSetBuilder
	ranger := cidranger.NewPCTrieRanger()

	for _, item := range entries {
		oracle.insert(item.prefix, int(item.value))
		current.Insert(item.prefix, item.value)
		bt.Insert(item.prefix, item.value)
		fast.Insert(item.prefix, item.value)
		tailscale.Insert(item.prefix, item.value)
		loader.Insert(item.prefix, item.value)
		if err := setBuilder.Add(item.prefix); err != nil {
			t.Fatal(err)
		}
		_, network, err := net.ParseCIDR(item.prefix.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := ranger.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			t.Fatal(err)
		}
		if item.prefix.Addr().Is4() {
			v4.Set(patricia.NewIPv4Address(address4(item.prefix.Addr()), uint(item.prefix.Bits())), item.value)
		} else {
			addr := item.prefix.Addr().As16()
			v6.Set(patricia.NewIPv6Address(addr[:], uint(item.prefix.Bits())), item.value)
		}
	}
	set := setBuilder.PrefixSet()

	valueLookups := map[string]func(netip.Addr) (uint32, bool){
		"current-art":   current.Lookup,
		"bart":          bt.Lookup,
		"bart-fast":     fast.Lookup,
		"tailscale-art": tailscale.Get,
		"go-iptrie": func(addr netip.Addr) (uint32, bool) {
			value := trie.Find(addr)
			if value == nil {
				return 0, false
			}
			return value.(uint32), true
		},
		"kentik-patricia": func(addr netip.Addr) (uint32, bool) {
			if addr.Is4() {
				ok, value := v4.FindDeepestTag(patricia.NewIPv4Address(address4(addr), 32))
				return value, ok
			}
			value := addr.As16()
			ok, tag := v6.FindDeepestTag(patricia.NewIPv6Address(value[:], 128))
			return tag, ok
		},
	}
	for _, query := range queries {
		want, wantOK := oracle.lookup(query)
		for name, lookup := range valueLookups {
			got, ok := lookup(query)
			if ok != wantOK || ok && got != uint32(want) {
				t.Fatalf("%s Lookup(%s) = (%d,%v), want (%d,%v)", name, query, got, ok, want, wantOK)
			}
		}
		host := netip.PrefixFrom(query, query.BitLen())
		setOK := set.Encompasses(host) || set.OverlapsPrefix(host)
		if setOK != wantOK {
			t.Fatalf("netipds lookup %s = %v, want %v", query, setOK, wantOK)
		}
		rangerOK, err := ranger.Contains(net.IP(query.AsSlice()))
		if err != nil || rangerOK != wantOK {
			t.Fatalf("cidranger lookup %s = (%v,%v), want %v", query, rangerOK, err, wantOK)
		}
	}
}

// address4 packs a v4 netip.Addr into host-order uint32 for kentik/patricia -
// their constructor wants the old "first octet in the top byte" layout
func address4(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
