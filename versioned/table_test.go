package versioned

import (
	"net/netip"
	"testing"
)

// prefix parses s or panics, keeps the tests readable
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr parses s or panics, same as prefix
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// TestTableModes runs Lookup, Supernets and Delete against FIB/RIB/Hybrid
// FIB must not walk supernets, the other two should see both covering prefixes
func TestTableModes(t *testing.T) {
	for _, mode := range []Mode{ModeFIB, ModeRIB, ModeHybrid} {
		s := New[string](mode)
		s.Update(func(w *Writer[string]) {
			w.Insert(prefix("10.0.0.0/8"), "a")
			w.Insert(prefix("10.1.0.0/16"), "b")
		})
		if got, ok := s.Lookup(addr("10.1.2.3")); !ok || got != "b" {
			t.Fatalf("mode %d Lookup = (%q, %v)", mode, got, ok)
		}
		count := 0
		s.Supernets(addr("10.1.2.3"), func(netip.Prefix, string) bool { count++; return true })
		if mode == ModeFIB && count != 0 {
			t.Fatalf("ModeFIB returned %d supernets", count)
		}
		if mode != ModeFIB && count != 2 {
			t.Fatalf("mode %d returned %d supernets", mode, count)
		}
		if !s.Delete(prefix("10.1.0.0/16")) || s.Size() != 1 {
			t.Fatalf("mode %d deletion failed", mode)
		}
	}
}
