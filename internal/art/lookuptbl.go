package art

import "math/bits"

// lookupTbl[host] has a 1 for every ART prefix-index on the path from
// HostIdx(host) up to the root - we AND this with a node's prefix bitset in
// LpmTop / IntersectsOctet so the walk becomes a few word ops
var lookupTbl [MaxChildren]Bitset512

// init precomputes lookupTbl - for each host octet we start at HostIdx and
// shift toward the root, setting bits, so the table is ready before any lookup
func init() {
	for host := range lookupTbl {
		for i := HostIdx(uint8(host)); i > 0; i >>= 1 {
			lookupTbl[host][i>>6] |= 1 << (i & 63)
		}
	}
}

// LpmTop is the table-driven Lpm for a stride-8 host octet - AND against
// lookupTbl[octet], then bits.Len64-1 on the highest non-zero word so the
// longest (largest-index) match wins - unrolled 7..0 because it's the lookup hot path
func (b *Bitset512) LpmTop(octet uint8) (idx uint, ok bool) {
	m := &lookupTbl[octet]
	// word 7 first: those indexes are the most specific (hosts live at 256..511)
	if w := b[7] & m[7]; w != 0 {
		return 7<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[6] & m[6]; w != 0 {
		return 6<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[5] & m[5]; w != 0 {
		return 5<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[4] & m[4]; w != 0 {
		return 4<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[3] & m[3]; w != 0 {
		return 3<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[2] & m[2]; w != 0 {
		return 2<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[1] & m[1]; w != 0 {
		return 1<<6 + uint(bits.Len64(w)) - 1, true
	}
	if w := b[0] & m[0]; w != 0 {
		return uint(bits.Len64(w)) - 1, true
	}
	return 0, false
}

// IntersectsOctet is true if any ART ancestor of octet is set in b - AND each
// word with lookupTbl[octet] and OR the lot, no need to recover an index
func (b *Bitset512) IntersectsOctet(octet uint8) bool {
	m := &lookupTbl[octet]
	return b[0]&m[0]|b[1]&m[1]|b[2]&m[2]|b[3]&m[3]|
		b[4]&m[4]|b[5]&m[5]|b[6]&m[6]|b[7]&m[7] != 0
}
