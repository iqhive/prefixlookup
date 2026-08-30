// Package addrkey normalises netip addresses into the fixed-size byte keys the
// trie implementations consume, with no heap allocation
//
// # The IPv4/IPv6 separation question
//
// The legacy tree stores IPv4 underneath the IPv4-mapped ::ffff:0:0/96 branch
// of a single 128-bit trie, and keeps a rootV4 shortcut pointer so IPv4 lookups
// skip the first 96 levels - that costs 96 eagerly-allocated nodes in every
// tree, and it makes deletion of an IPv6 prefix able to invalidate the IPv4
// shortcut (see the rootV4 rebuild dance in the legacy deleteNode path)
//
// We separate the families into two independent tries instead - the concern
// raised about separation is cache behaviour, so it's worth being precise
// about why separation *improves* rather than harms locality:
//
//   - The two tries are reached through two fields of the same parent struct,
//     which occupy the same cache line; selecting a family is one predictable,
//     perfectly-predicted branch on Addr.Is4, not a memory access
//   - A shared trie forces IPv4 and IPv6 nodes to interleave in the same
//     allocation arena; separation lets an IPv4-only deployment - which is the
//     overwhelmingly common case - have a working set containing zero IPv6
//     nodes, so its resident footprint shrinks and its cache hit rate rises
//   - The 96 shared spine nodes in the unified design are pure overhead: they
//     hold no values and exist only to be skipped
//
// The measured result is in the benchmark suite; separation is a win at every
// table size we've tested
package addrkey

import "net/netip"

// Key is a normalised address: a 16-byte buffer plus the number of significant
// bytes (4 for IPv4, 16 for IPv6) - it's a value type and never escapes to the
// heap in the lookup path
type Key struct {
	Octets [16]byte
	Len    uint8 // 4 or 16
	Is4    bool
}

// FromAddr normalises an address into a Key - we Unmap IPv4-in-IPv6 so
// ::ffff:1.2.3.4 and 1.2.3.4 are the same key (the legacy string parser got
// this wrong), then copy As4/As16 into Octets
func FromAddr(a netip.Addr) (Key, bool) {
	var k Key
	if !a.IsValid() {
		return k, false
	}
	if a.Is4In6() {
		// treat mapped v6 as v4 so we don't grow a 96-bit spine
		a = a.Unmap()
	}
	if a.Is4() {
		k.Octets = [16]byte{}
		b := a.As4()
		// only the first 4 bytes are live, Len tells the trie to stop there
		k.Octets[0], k.Octets[1], k.Octets[2], k.Octets[3] = b[0], b[1], b[2], b[3]
		k.Len = 4
		k.Is4 = true
		return k, true
	}
	k.Octets = a.As16()
	k.Len = 16
	return k, true
}

// PrefixKey is a normalised prefix: a masked address plus its bit length
type PrefixKey struct {
	Key
	Bits uint8 // 0..32 for IPv4, 0..128 for IPv6
}

// FromPrefix normalises a prefix, masking off any bits below Bits so that
// 10.1.2.3/24 and 10.1.2.0/24 are the same key - mapped v6 with bits>=96 is
// treated as the embedded v4 (bits-=96), shorter mapped prefixes we reject
func FromPrefix(p netip.Prefix) (PrefixKey, bool) {
	var pk PrefixKey
	if !p.IsValid() {
		return pk, false
	}
	a := p.Addr()
	bits := uint8(p.Bits())
	if a.Is4In6() {
		a = a.Unmap()
		// a /96..128 on a mapped address is the embedded IPv4 bits
		if bits >= 96 {
			bits -= 96
		} else {
			// shorter than /96 on a mapped addr is nonsense, don't guess
			return pk, false
		}
	}
	k, ok := FromAddr(a)
	if !ok {
		return pk, false
	}
	if int(bits) > int(k.Len)*8 {
		// bits past the family width, reject rather than wrapping
		return pk, false
	}
	pk.Key = k
	pk.Bits = bits
	// knock the host bits off so the key is canonical
	pk.mask()
	return pk, true
}

// mask zeroes every bit past the prefix length - keep the partial octet via
// AND, then zero the remaining bytes out to Len so the key is canonical
func (pk *PrefixKey) mask() {
	n := int(pk.Bits)
	full := n >> 3
	if rem := n & 7; rem != 0 {
		// keep the leading rem bits of the partial octet
		pk.Octets[full] &= ^byte(0xff >> rem)
		full++
	}
	for i := full; i < int(pk.Len); i++ {
		pk.Octets[i] = 0
	}
}

// Addr rebuilds a netip.Addr from the key - As4 from the first four bytes if
// Is4, otherwise the whole 16-byte buffer
func (k Key) Addr() netip.Addr {
	if k.Is4 {
		// only the first four bytes are live
		return netip.AddrFrom4([4]byte{k.Octets[0], k.Octets[1], k.Octets[2], k.Octets[3]})
	}
	return netip.AddrFrom16(k.Octets)
}

// Prefix rebuilds a netip.Prefix from the key - Addr() plus Bits, no remasking
func (pk PrefixKey) Prefix() netip.Prefix {
	// already masked at FromPrefix, don't remask
	return netip.PrefixFrom(pk.Key.Addr(), int(pk.Bits))
}
