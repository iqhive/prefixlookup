package rangematch_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/prefixentry"
	"github.com/iqhive/prefixlookup/rangematch"
)

// TestSetMergesAndMatches checks adjacent /9s collapse to one range and that
// the union still matches - we New() a handful of prefixes then poke Match
func TestSetMergesAndMatches(t *testing.T) {
	set, err := rangematch.New([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/9"), netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("2001:db8::/127"), netip.MustParsePrefix("2001:db8::2/127"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// two /9s should become 10.0.0.0/8; two /127s should become /126
	if set.Ranges() != 2 {
		t.Fatalf("Ranges() = %d, want 2", set.Ranges())
	}
	for _, text := range []string{"10.255.255.255", "2001:db8::3"} {
		if !set.Match(netip.MustParseAddr(text)) {
			t.Errorf("Match(%s) = false", text)
		}
	}
	for _, text := range []string{"11.0.0.1", "2001:db8::4"} {
		if set.Match(netip.MustParseAddr(text)) {
			t.Errorf("Match(%s) = true", text)
		}
	}
}

// TestRejectsInvalidPrefix makes sure a zero Prefix doesn't sneak in - New
// should bounce it as ErrBadIP from prefixentry.NormalizePrefix
func TestRejectsInvalidPrefix(t *testing.T) {
	_, err := rangematch.New([]netip.Prefix{{}})
	if err != prefixentry.ErrBadIP {
		t.Fatalf("New error = %v, want %v", err, prefixentry.ErrBadIP)
	}
}
