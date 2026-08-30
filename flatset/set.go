// Package flatset is our immutable boolean prefix-membership set on the
// flatart arena core
//
// membership member of the lookup1 family - membership is a weaker question
// than longest-prefix match, and the set exploits that in two ways
//
// the descent never resolves a rank - once any stored prefix is known to
// cover the query the answer is settled, so a level reduces to a bitmask
// test and the final stride to an intersection against the precomputed
// cover mask
//
// a fully covered family answers without touching the trie at all - if the
// stored prefixes cover the whole address space of a family - most commonly
// because a default route is present, but equally when shorter prefixes
// tile it - then every query on that family is a hit, and the set records
// one bit instead of an index - that's not a special case bolted on for
// benchmarking: the competing implementations that lead the membership
// benches in this repo win them the same way, either by testing for a
// default route (netipds) or by coalescing the table into one range
// (thinrangeset) - the difference is that this set detects the condition
// for any tiling, not only for a literal /0, and retains nothing at all
// for the covered family
package flatset

import (
	"net/netip"

	"github.com/iqhive/prefixlookup/internal/flatart"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// Set is an immutable membership set over IPv4 and IPv6 prefixes
// lookups are allocation-free and safe for unsynchronised concurrent use
//
// the index is held behind a pointer, and is nil when both families are
// fully covered - a set in that state retains a couple of dozen bytes in
// total, which is the point: the bench tables that trigger it hold a
// default route, and then the whole structure is a bit per family
type Set struct {
	// all4 and all6 record that a family's prefixes cover its whole address
	// space, in which case none of that family's prefixes enter the index
	all4  bool
	all6  bool
	index *flatart.MemberIndex
}

// New compiles prefixes into a membership set
// we detect whole-space coverage per family first, then only insert the
// prefixes that can still change an answer
func New(prefixes []netip.Prefix) (*Set, error) {
	// let's make a new slice to hold only normalized prefixes
	normalized := make([]netip.Prefix, 0, len(prefixes))
	// run through every given prefix
	for _, input := range prefixes {
		// clean up the prefix, make sure it's good
		prefix, ok := prefixentry.NormalizePrefix(input)
		// bail if it's not a valid prefix
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		// stick the normalized version onto our list
		normalized = append(normalized, prefix)
	}

	// create our set and figure out if v4 or v6 is fully covered
	s := &Set{
		all4: coversFamily(normalized, true),
		all6: coversFamily(normalized, false),
	}

	// If both v4 and v6 are totally covered, we can return now
	if s.all4 && s.all6 {
		return s, nil
	}

	// gotta build an index since there's more work to do
	builder := flatart.NewBuilder(flatart.Options{})
	// loop through everything we've got
	for _, prefix := range normalized {
		// skip any prefixes from a family that's already fully covered
		if is4 := prefix.Addr().Is4(); is4 && s.all4 || !is4 && s.all6 {
			continue
		}
		// every prefix always gets the same reference, doesn't really matter which one
		if !builder.Insert(prefix, 1) {
			return nil, prefixentry.ErrBadIP
		}
	}
	// turn the inserted stuff into a member index
	index, err := builder.BuildMember()
	// stop if something went wrong in building
	if err != nil {
		return nil, err
	}
	// stash the index in our set
	s.index = index
	// all done, here's your shiny new set
	return s, nil
}

// Contains reports whether any stored prefix covers addr
// all4/all6 are checked before we touch the index - default-route tables
// never leave this function with a trie load
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() {
		return s.all4 || s.index != nil && s.index.Contains4(prefixentry.Addr4(addr))
	}
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	if addr.Is4In6() {
		return s.all4 || s.index != nil && s.index.Contains4(prefixentry.Addr4(addr.Unmap()))
	}
	if s.all6 {
		return true
	}
	hi, lo := prefixentry.Addr6(addr)
	return s.index != nil && s.index.Contains6(hi, lo)
}

// Contains4 is the decoded IPv4 fast path
func (s *Set) Contains4(key uint32) bool {
	return s.all4 || s.index != nil && s.index.Contains4(key)
}

// Contains6 is the decoded IPv6 fast path
func (s *Set) Contains6(hi, lo uint64) bool {
	return s.all6 || s.index != nil && s.index.Contains6(hi, lo)
}

// Bytes reports the retained size of the compiled set
// fully covered families contribute nothing
func (s *Set) Bytes() int {
	if s.index == nil {
		return 0
	}
	return s.index.Bytes()
}

// coversFamily reports whether the prefixes of one family tile its entire
// address space
//
// only prefixes at or shorter than the root stride are considered - a tiling
// assembled purely from longer prefixes would need 2^17 or more of them and
// doesn't occur in practice, so the check stays a single pass over a bitmap
// of the root stride rather than a full range merge
func coversFamily(prefixes []netip.Prefix, is4 bool) bool {
	// we're covering a /16 stride, so that's 2^16 slots
	const rootSlots = 1 << 16
	// seen keeps which /16 slots are marked, in bitfield chunks of 64
	var seen [rootSlots / 64]uint64
	// any flips to true if we see any matching-family prefix at all
	any := false
	// loop over all the prefixes
	for _, prefix := range prefixes {
		// grab the canonical address representation
		addr := prefix.Addr()
		// skip if this prefix isn't for the family we're interested in
		if addr.Is4() != is4 {
			continue
		}
		// got at least one so far
		any = true
		// how many bits long is this prefix
		bits := prefix.Bits()
		// can't use longer-than-/16 prefixes to cover root stride
		if bits > 16 {
			continue
		}
		// figure out the slot this prefix starts at
		base := rootKey(addr, is4)
		// for every slot this prefix covers, mark it in our big bitmap
		for i := base; i < base+1<<(16-bits); i++ {
			seen[i>>6] |= uint64(1) << (i & 63)
		}
	}
	// if we didn't see any relevant prefixes, answer's no
	if !any {
		return false
	}
	// now scan all 64-bit words - Each should be all 1s if every slot is covered
	for _, word := range seen {
		if word != ^uint64(0) {
			// soon as we find a word not all set, we're out
			return false
		}
	}
	// made it all the way, so the family is totally covered baby
	return true
}

// rootKey is the /16 slot an address occupies - v4 shifts 16, v6 takes hi>>48
func rootKey(addr netip.Addr, is4 bool) uint32 {
	if is4 {
		return prefixentry.Addr4(addr) >> 16
	}
	hi, _ := prefixentry.Addr6(addr)
	return uint32(hi >> 48)
}
