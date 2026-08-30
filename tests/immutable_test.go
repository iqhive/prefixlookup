package tests_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/compiledfib"
	"github.com/iqhive/prefixlookup/old/bitfrontlpm"
	"github.com/iqhive/prefixlookup/old/bitlpm"
	"github.com/iqhive/prefixlookup/old/bitwalk"
	"github.com/iqhive/prefixlookup/old/fiborderwalk"
	"github.com/iqhive/prefixlookup/old/lenlpm"
	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/routeupdate"
	"github.com/iqhive/prefixlookup/splitribfib"
)

type immutableFactory struct {
	name string
	new  func([]prefixentry.Entry[int]) (lookupTable, error)
}

// TestImmutableImplementationsAgainstOracle builds one random oracle (plus a
// last-wins duplicate 10/8) and feeds the same entry slice to every immutable
// constructor we still care about
//
// fiborderwalk and splitribfib return an extra id on Lookup so we wrap them
// in routeLookup - everyone else already matches lookupTable
func TestImmutableImplementationsAgainstOracle(t *testing.T) {
	factories := []immutableFactory{
		{"compiledfib", func(e []prefixentry.Entry[int]) (lookupTable, error) {
			return compiledfib.New(e, routeupdate.Options{})
		}},
		{"bitlpm", func(e []prefixentry.Entry[int]) (lookupTable, error) { return bitlpm.New(e) }},
		{"bitfrontlpm", func(e []prefixentry.Entry[int]) (lookupTable, error) { return bitfrontlpm.New(e) }},
		{"lenlpm", func(e []prefixentry.Entry[int]) (lookupTable, error) { return lenlpm.New(e) }},
		{"bitwalk", func(e []prefixentry.Entry[int]) (lookupTable, error) { return bitwalk.New(e) }},
		{"fiborderwalk", func(e []prefixentry.Entry[int]) (lookupTable, error) {
			table, err := fiborderwalk.New(e)
			if err != nil {
				return nil, err
			}
			return routeLookup{lookup: func(a netip.Addr) (int, bool) { _, v, ok := table.Lookup(a); return v, ok }}, nil
		}},
		{"splitribfib", func(e []prefixentry.Entry[int]) (lookupTable, error) {
			table, err := splitribfib.New(e, routeupdate.Options{})
			if err != nil {
				return nil, err
			}
			return routeLookup{lookup: func(a netip.Addr) (int, bool) { _, v, ok := table.Lookup(a); return v, ok }}, nil
		}},
	}
	want := randomOracle(501, 1400)
	entries := want.entries()
	duplicate := netip.MustParsePrefix("10.0.0.0/8")
	entries = append(entries,
		prefixentry.Entry[int]{Prefix: duplicate, Value: 7001},
		prefixentry.Entry[int]{Prefix: duplicate, Value: 7002},
	)
	want.insert(duplicate, 7002)
	for _, factory := range factories {
		t.Run(factory.name, func(t *testing.T) {
			table, err := factory.new(entries)
			if err != nil {
				t.Fatal(err)
			}
			verifyLookup(t, factory.name, table, want, 502, 8000)
		})
	}
}

type routeLookup struct{ lookup func(netip.Addr) (int, bool) }

// Lookup just forwards to the wrapped func - we need this so fiborderwalk /
// splitribfib can sit on lookupTable without dragging routeid into the oracle
func (r routeLookup) Lookup(addr netip.Addr) (int, bool) { return r.lookup(addr) }

// TestDecodedLookupPaths is the compiledfib specialised entry points -
// Lookup4 with a host-order uint32 and Lookup6 with the hi/lo split from
// prefixentry.Addr6 - tiny table so a wrong decode is obvious
func TestDecodedLookupPaths(t *testing.T) {
	entries := []prefixentry.Entry[int]{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Value: 1},
		{Prefix: netip.MustParsePrefix("10.1.2.0/24"), Value: 2},
		{Prefix: netip.MustParsePrefix("::/0"), Value: 3},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Value: 4},
	}
	table, err := compiledfib.New(entries, routeupdate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup4(0x0a010203); !ok || got != 2 {
		t.Fatalf("Lookup4 = (%d,%v)", got, ok)
	}
	hi, lo := prefixentry.Addr6(netip.MustParseAddr("2001:db8::1"))
	if got, ok := table.Lookup6(hi, lo); !ok || got != 4 {
		t.Fatalf("Lookup6 = (%d,%v)", got, ok)
	}
}
