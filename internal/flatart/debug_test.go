package flatart

import (
	"net/netip"
	"testing"
)

// TestDefaultRouteFallback isolates the inherited-default path: every query
// must fall back to the covering default when nothing longer matches, at
// every stride kind the compiler can emit
func TestDefaultRouteFallback(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		query    string
		want     uint32
	}{
		{"v6 default only", []string{"::/0"}, "e623:3ef1::1", 1},
		{"v6 default plus far subtree", []string{"::/0", "2001:db8::/32"}, "e623:3ef1::1", 1},
		{"v6 default plus same byte0 leaf", []string{"::/0", "e600::/16"}, "e623:3ef1::1", 1},
		{"v6 default plus same byte0 stop", []string{"::/0", "e600::/16", "e610::/16"}, "e623:3ef1::1", 1},
		{"v6 deep node covers", []string{"::/0", "e623:3ef1::/32", "e623:3ef2::/32", "e624::/16"}, "e623:3ef1::1", 2},
		{"v6 deep node misses", []string{"::/0", "e623:3ef1::/32", "e623:3ef2::/32", "e624::/16"}, "e623:3ef5::1", 1},
		{"v6 covering /16 wins", []string{"::/0", "e623::/16"}, "e623:3ef1::1", 2},
		{"v4 default only", []string{"0.0.0.0/0"}, "10.1.2.3", 1},
		{"v4 default plus stop", []string{"0.0.0.0/0", "10.1.0.0/24", "10.1.1.0/24"}, "10.1.2.3", 1},
		{"v4 default plus node", []string{"0.0.0.0/0", "10.1.0.0/25", "10.1.0.128/25", "10.1.1.0/24"}, "10.1.2.3", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder(Options{Exact: true})
			for i, s := range tc.prefixes {
				if !b.Insert(netip.MustParsePrefix(s), uint32(i+1)) {
					t.Fatalf("insert %s rejected", s)
				}
			}
			ix, refOf, err := b.Build()
			if err != nil {
				t.Fatal(err)
			}
			addr := netip.MustParseAddr(tc.query)
			got := refOf[ix.Lookup(addr)]
			if got != tc.want {
				t.Fatalf("Lookup(%s) = %d, want %d (stops=%d nodes=%d leaf4=%d leaf6=%d)",
					tc.query, got, tc.want, len(ix.stops), len(ix.nodes), len(ix.leaf4), len(ix.leaf6))
			}
			if !ix.Contains(addr) {
				t.Fatalf("Contains(%s) = false, want true", tc.query)
			}
		})
	}
}
