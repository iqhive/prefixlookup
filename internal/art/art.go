// Package art provides the shared primitives used by every nradix
// implementation: stride-8 ART (Allotment Routing Table) index arithmetic and
// the popcount-compressed bitsets that back the node representation
package art

import "math/bits"

const (
	Stride      = 8
	MaxPrefixes = 512
	MaxChildren = 256
)

// PfxToIdx maps a stride-8 prefix (octet, pfxLen) onto the ART allotment index -
// we shift the significant bits down and OR in 1<<pfxLen so length is in the
// high bit and different lengths never collide
func PfxToIdx(octet uint8, pfxLen uint8) uint {
	return uint(octet>>(Stride-pfxLen)) | (1 << pfxLen)
}

// HostIdx is the ART index for a full 8-bit host - octet in the low bits with
// MaxChildren (256) set so hosts sit in slots 256..511, above all prefixes
func HostIdx(octet uint8) uint { return uint(octet) | MaxChildren }

// IdxToPfx inverts PfxToIdx - pfxLen is bits.Len(idx)-1 (that 1<<pfxLen we
// planted), then we shift the leftover payload back up into an octet
func IdxToPfx(idx uint) (octet uint8, pfxLen uint8) {
	pfxLen = uint8(bits.Len(idx)) - 1
	octet = uint8(idx&((1<<pfxLen)-1)) << (Stride - pfxLen)
	return octet, pfxLen
}

// IdxRange returns the inclusive [first,last] host octets covered by idx - we
// decode to (octet, pfxLen) then OR in the host-bit mask 0xff>>pfxLen
func IdxRange(idx uint) (first, last uint8) {
	octet, pfxLen := IdxToPfx(idx)
	return octet, octet | byte(0xff>>pfxLen)
}

// Bitset512 is 512 bits as 8 uint64s - ART prefix slots (0..511)
type Bitset512 [8]uint64

// Test reports whether bit i is set - word i>>6, mask 1<<(i&63)
func (b *Bitset512) Test(i uint) bool { return b[i>>6]&(1<<(i&63)) != 0 }

// Set stamps bit i via OR into its word
func (b *Bitset512) Set(i uint)       { b[i>>6] |= 1 << (i & 63) }

// Clear drops bit i via AND-NOT - we don't care if it wasn't set
func (b *Bitset512) Clear(i uint)     { b[i>>6] &^= 1 << (i & 63) }

// Count is popcount across all 8 words - unrolled because 512 bits is tiny
func (b *Bitset512) Count() int {
	return bits.OnesCount64(b[0]) + bits.OnesCount64(b[1]) +
		bits.OnesCount64(b[2]) + bits.OnesCount64(b[3]) +
		bits.OnesCount64(b[4]) + bits.OnesCount64(b[5]) +
		bits.OnesCount64(b[6]) + bits.OnesCount64(b[7])
}

// IsEmpty is true when every word is zero - OR them together, one compare
func (b *Bitset512) IsEmpty() bool {
	return b[0]|b[1]|b[2]|b[3]|b[4]|b[5]|b[6]|b[7] == 0
}

// Rank0 is the popcount of bits strictly below i - full words then a masked
// partial on the word that holds i (the usual succinct-index rank)
func (b *Bitset512) Rank0(i uint) int {
	w := i >> 6
	r := 0
	for k := uint(0); k < w; k++ {
		r += bits.OnesCount64(b[k])
	}
	return r + bits.OnesCount64(b[w]&((uint64(1)<<(i&63))-1))
}

// Lpm walks the ART ancestor chain from host toward the root and returns the
// first set bit - that's the longest matching prefix index, or ok=false
func (b *Bitset512) Lpm(host uint) (idx uint, ok bool) {
	if b[host>>6]&(1<<(host&63)) != 0 {
		return host, true // exact host slot
	}
	for i := host >> 1; i > 0; i >>= 1 {
		if b[i>>6]&(1<<(i&63)) != 0 {
			return i, true
		}
	}
	return 0, false
}

// Intersects is true if any ancestor of host (including host) is set - same
// walk as Lpm but we only need a bool so we don't return the index
func (b *Bitset512) Intersects(host uint) bool {
	for i := host; i > 0; i >>= 1 {
		if b[i>>6]&(1<<(i&63)) != 0 {
			return true
		}
	}
	return false
}

// All appends every set-bit index to dst - word loop + trailing-zero extract
// and clear-lowest-bit (Kernighan) so we skip zeros for free
func (b *Bitset512) All(dst []uint) []uint {
	for w := uint(0); w < 8; w++ {
		word := b[w]
		for word != 0 {
			dst = append(dst, w<<6+uint(bits.TrailingZeros64(word)))
			word &= word - 1 // knock off the bit we just yielded
		}
	}
	return dst
}

// Bitset256 is 256 bits as 4 uint64s - child / cover slots (0..255)
type Bitset256 [4]uint64

// Test reports whether bit i is set - same word/mask split as Bitset512
func (b *Bitset256) Test(i uint) bool { return b[i>>6]&(1<<(i&63)) != 0 }

// Set stamps bit i via OR
func (b *Bitset256) Set(i uint)       { b[i>>6] |= 1 << (i & 63) }

// Clear drops bit i via AND-NOT
func (b *Bitset256) Clear(i uint)     { b[i>>6] &^= 1 << (i & 63) }

// Count is popcount of the 4 words - unrolled, four OnesCount64s
func (b *Bitset256) Count() int {
	return bits.OnesCount64(b[0]) + bits.OnesCount64(b[1]) +
		bits.OnesCount64(b[2]) + bits.OnesCount64(b[3])
}

// IsEmpty ORs the four words - cheaper than a Count()==0 on the hot path
func (b *Bitset256) IsEmpty() bool { return b[0]|b[1]|b[2]|b[3] == 0 }

// Rank0 is popcount strictly below i - we unroll the 0..3 word prefix instead
// of looping because four words is the whole set
func (b *Bitset256) Rank0(i uint) int {
	w := i >> 6
	var r int
	if w > 0 {
		r += bits.OnesCount64(b[0])
	}
	if w > 1 {
		r += bits.OnesCount64(b[1])
	}
	if w > 2 {
		r += bits.OnesCount64(b[2])
	}
	return r + bits.OnesCount64(b[w]&((uint64(1)<<(i&63))-1))
}

// All appends every set child/cover index as uint8 - same Kernighan walk as
// Bitset512.All but the dest is bytes because 256 fits
func (b *Bitset256) All(dst []uint8) []uint8 {
	for w := uint(0); w < 4; w++ {
		word := b[w]
		for word != 0 {
			dst = append(dst, uint8(w<<6+uint(bits.TrailingZeros64(word))))
			word &= word - 1 // knock off the bit we just yielded
		}
	}
	return dst
}
