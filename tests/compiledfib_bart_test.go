package tests_test

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
)

// TestCompiledFibAgainstBART builds a mixed v4/v6 table (~2k prefixes plus
// both defaults) into compiledfib and into gaissmai/bart, then fires 10k
// random lookups and demands they agree
//
// we seed PCG(1,2) so this is reproducible, we mix families with i&3 so v6
// isn't starved, and we use bart as the independent oracle because compiledfib
// is a compiled snapshot - if we only compared against ourselves we'd miss a
// stride/default bug that both copies share
func TestCompiledFibAgainstBART(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	entries := []prefixentry.Entry[uint32]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("::/0"), Value: 2},
	}
	for i := uint32(3); i < 2003; i++ {
		if i&3 == 0 {
			// v6: smash 16 random bytes and a random prefix length
			var a [16]byte
			for j := range a {
				a[j] = byte(rng.Uint32())
			}
			entries = append(entries, prefixentry.Entry[uint32]{Prefix: netip.PrefixFrom(netip.AddrFrom16(a), int(rng.Uint32()%129)), Value: i})
		} else {
			a := [4]byte{byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())}
			entries = append(entries, prefixentry.Entry[uint32]{Prefix: netip.PrefixFrom(netip.AddrFrom4(a), int(rng.Uint32()%33)), Value: i})
		}
	}
	table, err := compiledfib.New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	oracle := new(bart.Table[uint32])
	for _, entry := range entries {
		oracle.Insert(entry.Prefix, entry.Value)
	}
	for i := 0; i < 10_000; i++ {
		var addr netip.Addr
		if i&3 == 0 {
			var a [16]byte
			for j := range a {
				a[j] = byte(rng.Uint32())
			}
			addr = netip.AddrFrom16(a)
		} else {
			a := [4]byte{byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())}
			addr = netip.AddrFrom4(a)
		}
		want, wantOK := oracle.Lookup(addr)
		if got, ok := table.Lookup(addr); got != want || ok != wantOK {
			t.Fatalf("Lookup(%s) = %d, %v; want %d, %v", addr, got, ok, want, wantOK)
		}
	}
}

// TestCompiledFibDuplicatePrefixLastWinsAndInvalidInput is the tiny contract
// check we don't want buried in the 2k-prefix random test - last insert for
// the same prefix must win, and a zero Prefix has to bounce as ErrBadIP
//
// we compile a two-entry list with the same 10/8 twice, probe 10.1.2.3, then
// feed New a zero prefix and match the sentinel error
func TestCompiledFibDuplicatePrefixLastWinsAndInvalidInput(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	table, err := compiledfib.New([]prefixentry.Entry[int]{{Prefix: prefix, Value: 1}, {Prefix: prefix, Value: 2}}, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3")); !ok || got != 2 {
		t.Fatalf("Lookup() = %d, %v; want 2, true", got, ok)
	}
	if _, err := compiledfib.New([]prefixentry.Entry[int]{{Prefix: netip.Prefix{}, Value: 1}}, routeupdate.Options{}); err != prefixentry.ErrBadIP {
		t.Fatalf("New() error = %v, want %v", err, prefixentry.ErrBadIP)
	}
}
