// Package prefixentry is the tiny shared bits we got sick of pasting into every table
//
// just a prefix plus a value, plus the normalise/unpack helpers we were copying
// around until someone finally extracted them
package prefixentry

import (
	"errors"
	"net/netip"
)

// ErrBadIP is what we hand back when the prefix is junk or has a zone
var ErrBadIP = errors.New("bad IP address or mask")

// Entry is one prefix and whatever we stuffed next to it
// builders take a slice of these, last write wins if you pass dups
type Entry[V any] struct {
	Prefix netip.Prefix
	Value  V
}

// NormalizePrefix checks the prefix is usable and knocks the host bits off
// we reject zones because mixing zoned addrs into a table silently wrecks hierarchy walks
// identifier stays American because that's the old name, comments say normalise
func NormalizePrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	// zones and invalids are out, Masked() does the host-bit chop
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// Addr4 packs an IPv4 addr into a host-endian-looking uint32 in network byte order
// we use this everywhere we want to index arrays off the address
func Addr4(addr netip.Addr) uint32 {
	a := addr.As4()
	// octet 0 is the high byte, same as you'd write it
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

// Addr6 splits an IPv6 addr into two uint64s, high then low, network byte order
// saves everyone doing the same 16-byte unpack
func Addr6(addr netip.Addr) (uint64, uint64) {
	a := addr.As16()
	// first 8 bytes
	hi := uint64(a[0])<<56 | uint64(a[1])<<48 | uint64(a[2])<<40 | uint64(a[3])<<32 |
		uint64(a[4])<<24 | uint64(a[5])<<16 | uint64(a[6])<<8 | uint64(a[7])
	// back 8
	lo := uint64(a[8])<<56 | uint64(a[9])<<48 | uint64(a[10])<<40 | uint64(a[11])<<32 |
		uint64(a[12])<<24 | uint64(a[13])<<16 | uint64(a[14])<<8 | uint64(a[15])
	return hi, lo
}

// Bit6 pulls one bit out of a split IPv6 addr
// depth 0 is the MSB of hi, depth 64 is the MSB of lo
func Bit6(hi, lo uint64, depth int) uint64 {
	if depth < 64 {
		// still in the high word
		return hi & (uint64(1) << (63 - depth))
	}
	// low word, same idea
	return lo & (uint64(1) << (127 - depth))
}

// IPv4Mask is a network-byte-order mask with `bits` leading ones
// bits==0 is a special case because shifting a uint32 by 32 is undefined-ish in Go
func IPv4Mask(bits int) uint32 {
	if bits == 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}
