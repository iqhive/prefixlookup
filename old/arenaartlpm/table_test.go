package arenaartlpm

import (
	"net/netip"
	"testing"
)

// prefix is a test helper that panics on a bad CIDR string. Fine here
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// addr is a test helper that panics on a bad address string
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestTableRebuild is the check that Rebuild actually pays for itself:
// delete leaves dead space, Rebuild zeros Dead, lookups still match, and
// the copy doesn't alias the original (inserting into the rebuild
// doesn't show up on the source)
func TestTableRebuild(t *testing.T) {
	c := New[int]()
	for i, p := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"} {
		c.Insert(prefix(p), i)
	}
	c.Delete(prefix("10.1.0.0/16"))
	if c.Dead() == 0 {
		t.Fatal("Delete did not account dead space")
	}
	r := c.Rebuild()
	if r.Dead() != 0 || r.Size() != c.Size() {
		t.Fatalf("rebuilt state: size=%d dead=%d", r.Size(), r.Dead())
	}
	for _, a := range []string{"10.1.1.1", "192.0.2.1", "2001:db8::1"} {
		gv, gok := c.Lookup(addr(a))
		rv, rok := r.Lookup(addr(a))
		if gv != rv || gok != rok {
			t.Errorf("rebuilt Lookup(%s) differs", a)
		}
	}
	r.Insert(prefix("203.0.113.0/24"), 99)
	if _, ok := c.Get(prefix("203.0.113.0/24")); ok {
		t.Fatal("rebuild aliases original")
	}
}
