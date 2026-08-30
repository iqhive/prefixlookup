package fibbench

import (
	"math"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

// length weights, occupancy, mix and IPv6 /16 identity follow the August 2026
// collector dump in ~/mrts (1,140,111 IPv4 and 261,370 IPv6 unique prefixes)
//
// IPv4 keeps the dump's mean of ~30.7 prefixes per occupied /16 but draws a
// heavy-tailed per-/16 count (median 7, a 28% singleton share, max ~433) and
// places homes in consecutive runs - IPv6 uses the dump's 65 RIR /16s rather
// than a uniform sample of 2000::/3, with the dump's /32+/48 mix and tail
// lengths - mix is the dump's 18.65% IPv6; genPrefixes emits exactly
// round(n*mix) IPv6 prefixes rather than Bernoulli-sampling them
var v4LengthDistribution = []struct {
	bits   int
	weight int
}{
	{8, 1}, {9, 1}, {10, 3}, {11, 9}, {12, 26}, {13, 52}, {14, 105}, {15, 190},
	{16, 1229}, {17, 759}, {18, 1227}, {19, 2360}, {20, 4261}, {21, 5071},
	{22, 10517}, {23, 10769}, {24, 63320},
	{25, 13}, {26, 13}, {27, 13}, {28, 12}, {29, 17}, {30, 10}, {31, 3}, {32, 19},
}

var v6LengthDistribution = []struct {
	bits   int
	weight int
}{
	{16, 1}, {19, 1}, {20, 5}, {21, 1}, {22, 2}, {23, 2}, {24, 19},
	{25, 5}, {26, 7}, {27, 7}, {28, 62}, {29, 2187}, {30, 281}, {31, 143},
	{32, 10401}, {33, 2229}, {34, 2124}, {35, 751}, {36, 3671}, {37, 501},
	{38, 1053}, {39, 715}, {40, 9258}, {41, 697}, {42, 1169}, {43, 559},
	{44, 10146}, {45, 1703}, {46, 2306}, {47, 3579}, {48, 46285},
	{50, 1}, {51, 1}, {52, 11}, {55, 1}, {56, 33}, {63, 1}, {64, 78},
	{80, 1}, {112, 1}, {118, 1}, {123, 2}, {124, 1}, {125, 1}, {128, 2},
}

const (
	// dfzPrefixCount and dfzV6Mix are the unique-prefix count and IPv6 share of
	// the August 2026 collector dump (1,140,111 IPv4 + 261,370 IPv6)
	dfzPrefixCount  = 1_401_481
	dfzV6Mix        = 0.1865
	v4PerOccupied16 = 30.69
	v6Occupied16s   = 65
	v4NestProb      = 0.54
	v6NestProb      = 0.57
	v4HomeSpace     = 222 * 256
)

// buildLengthPicker flattens a (bits, weight) table into a slice we can
// Intn() into - crude but we only build it once at init, so who cares
func buildLengthPicker(dist []struct {
	bits   int
	weight int
}) []int {
	var table []int
	for _, d := range dist {
		for range d.weight {
			table = append(table, d.bits)
		}
	}
	return table
}

var (
	v4Lengths = buildLengthPicker(v4LengthDistribution)
	v6Lengths = buildLengthPicker(v6LengthDistribution)
)

// v4HomeCount is how many occupied /16s we want for n4 prefixes - dump mean
// is ~30.7 per home, then we knock off the ~0.065% extra /16s that short
// prefixes mask into so the post-mask mean stays honest
func v4HomeCount(n4 int) int {
	if n4 <= 0 {
		return 0
	}
	h := int(math.Round(float64(n4) / v4PerOccupied16))
	// prefixes shorter than /16 mask into a parent /16 that is often not
	// already a home (~0.065% extra occupied /16s in the dump) - drop that
	// many homes so the post-mask mean stays near v4PerOccupied16
	h -= int(math.Round(float64(n4) * 0.00065))
	if h < 1 {
		h = 1
	}
	if h > n4 {
		h = n4
	}
	if h > v4HomeSpace {
		h = v4HomeSpace
	}
	return h
}

// v6HomeCount is min(n6, 65) - the dump only occupies 65 RIR /16s, so a
// small table just uses that many homes rather than inventing more
func v6HomeCount(n6 int) int {
	if n6 <= 0 {
		return 0
	}
	if n6 < v6Occupied16s {
		return n6
	}
	return v6Occupied16s
}

// homeKey packs a /16 identity into a uint16 so we can de-dupe in a map
func homeKey(h [2]byte) uint16 {
	return uint16(h[0])<<8 | uint16(h[1])
}

// idxToV4Home maps 0..v4HomeSpace-1 onto 1.0/16 through 222.255/16 - we skip
// 0/8 because that's the default-route neighbourhood and looks weird as a home
func idxToV4Home(i int) [2]byte {
	return [2]byte{byte(1 + i/256), byte(i % 256)}
}

// sampleV4RunLen draws a consecutive-/16 run length - usually a short
// geometric (~1/6.8 continue, cap 80), rarely a long span (0.8% chance, up
// to 328) because the dump has those clumpy RIR allocations
func sampleV4RunLen(rng *rand.Rand, remaining int) int {
	if remaining <= 1 {
		return remaining
	}
	var n int
	if rng.Float64() < 0.008 {
		span := remaining
		if span > 328 {
			span = 328
		}
		if span > 20 {
			n = 20 + rng.Intn(span-19)
		} else {
			n = span
		}
	} else {
		n = 1
		for n < remaining && n < 80 && rng.Float64() > 1.0/6.8 {
			n++
		}
	}
	if n > remaining {
		n = remaining
	}
	return n
}

// sampleV4Homes paints n distinct /16 homes as consecutive runs in the
// 1.0–222.255 space - we reject overlaps, and after 64 collisions we fall
// back to run=1 so we don't loop forever on a packed table
func sampleV4Homes(rng *rand.Rand, n int) [][2]byte {
	homes := make([][2]byte, 0, n)
	seen := make(map[uint16]struct{}, n)
	free := func(start, run int) bool {
		for k := 0; k < run; k++ {
			h := idxToV4Home((start + k) % v4HomeSpace)
			if _, ok := seen[homeKey(h)]; ok {
				return false
			}
		}
		return true
	}
	attempts := 0
	for len(homes) < n {
		run := sampleV4RunLen(rng, n-len(homes))
		start := rng.Intn(v4HomeSpace)
		if !free(start, run) {
			attempts++
			if attempts > 64 {
				run = 1
				if !free(start, 1) {
					start = rng.Intn(v4HomeSpace)
					continue
				}
			} else {
				continue
			}
		}
		attempts = 0
		for k := 0; k < run && len(homes) < n; k++ {
			h := idxToV4Home((start + k) % v4HomeSpace)
			seen[homeKey(h)] = struct{}{}
			homes = append(homes, h)
		}
	}
	return homes
}

// v6RIR16s is the 65 occupied IPv6 /16s in the dump, excluding ::/0 - we
// hard-code the ranges rather than sampling 2000::/3 because a uniform
// sample looks nothing like the DFZ
func v6RIR16s() [][2]byte {
	out := make([][2]byte, 0, v6Occupied16s)
	addRange := func(base uint16, n int) {
		for i := 0; i < n; i++ {
			v := base + uint16(i)
			out = append(out, [2]byte{byte(v >> 8), byte(v)})
		}
	}
	addRange(0x2000, 4)
	addRange(0x2400, 16)
	addRange(0x2600, 10)
	out = append(out,
		[2]byte{0x26, 0x10}, [2]byte{0x26, 0x20},
		[2]byte{0x26, 0x31}, [2]byte{0x26, 0x32}, [2]byte{0x26, 0x70},
	)
	addRange(0x2800, 7)
	addRange(0x2a00, 21)
	out = append(out, [2]byte{0x2c, 0x0e}, [2]byte{0x2c, 0x0f})
	return out
}

// v6OctetShare is the dump's relative weight for each RIR /8 so we can
// rank v6 homes when we assign occupancy - 0x24 (APNIC-ish) is fattest
func v6OctetShare(oct byte) int {
	switch oct {
	case 0x24:
		return 312
	case 0x2a:
		return 217
	case 0x26:
		return 201
	case 0x28:
		return 141
	case 0x20:
		return 113
	case 0x2c:
		return 16
	default:
		return 1
	}
}

// sampleV6Homes shuffles the RIR /16 pool and takes n - if we need the
// whole pool we still shuffle so occupancy ranking isn't insertion-order
func sampleV6Homes(rng *rand.Rand, n int) [][2]byte {
	pool := v6RIR16s()
	if n >= len(pool) {
		rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		return pool
	}
	rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	return pool[:n]
}

// sampleV4Occ draws a per-/16 occupancy from the dump's heavy-tailed
// histogram - ~28% singletons, median 7, a fat tail out to ~433
func sampleV4Occ(rng *rand.Rand) int {
	u := rng.Float64()
	switch {
	case u < 0.2833:
		return 1
	case u < 0.4676:
		return 2 + rng.Intn(4)
	case u < 0.5591:
		return 6 + rng.Intn(5)
	case u < 0.6579:
		return 11 + rng.Intn(10)
	case u < 0.7837:
		return 21 + rng.Intn(30)
	case u < 0.9041:
		return 51 + rng.Intn(50)
	case u < 0.9958:
		return 101 + int(149*math.Pow(rng.Float64(), 3))
	default:
		return 251 + rng.Intn(183)
	}
}

// lerpLog interpolates log-space between v0 and v1 - we use it for the v6
// occupancy tail so we don't get a linear pile-up in the middle of a
// range that's actually log-distributed in the dump
func lerpLog(t float64, v0, v1 int) int {
	if t <= 0 {
		return v0
	}
	if t >= 1 {
		return v1
	}
	return int(math.Round(math.Exp(math.Log(float64(v0)) + t*(math.Log(float64(v1))-math.Log(float64(v0))))))
}

// sampleV6Occ is the v6 occupancy histogram - most /16s are huge (thousands
// of prefixes), a few are tiny; the default branch log-lerps through the
// dump's observed buckets
func sampleV6Occ(rng *rand.Rand) int {
	u := rng.Float64()
	switch {
	case u < 0.046:
		return 1
	case u < 0.108:
		return 2 + rng.Intn(4)
	case u < 0.154:
		return 6 + rng.Intn(5)
	case u < 0.169:
		return 51 + rng.Intn(50)
	case u < 0.215:
		return 101 + rng.Intn(150)
	default:
		t := (u - 0.215) / 0.785
		switch {
		case t < 0.36:
			return lerpLog(t/0.36, 251, 2265)
		case t < 0.68:
			return lerpLog((t-0.36)/0.32, 2265, 4604)
		case t < 0.87:
			return lerpLog((t-0.68)/0.19, 4604, 9359)
		case t < 0.936:
			return lerpLog((t-0.87)/0.066, 9359, 11646)
		case t < 0.987:
			return lerpLog((t-0.936)/0.051, 11646, 29507)
		default:
			return lerpLog((t-0.987)/0.013, 29507, 29677)
		}
	}
}

// assignOccupancy samples a raw occupancy per home, then rescales so they
// sum to n (minimum 1 each) - for v6 we rank homes by RIR octet share and
// pair the fattest samples with the fattest /8s, because APNIC isn't the
// same size as AFRINIC
func assignOccupancy(rng *rand.Rand, homes [][2]byte, n int, is6 bool) []int {
	h := len(homes)
	raw := make([]int, h)
	sum := 0
	for i := range raw {
		if is6 {
			raw[i] = sampleV6Occ(rng)
		} else {
			raw[i] = sampleV4Occ(rng)
		}
		sum += raw[i]
	}
	if is6 && h > 1 {
		idx := make([]int, h)
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool {
			wa, wb := v6OctetShare(homes[idx[a]][0]), v6OctetShare(homes[idx[b]][0])
			if wa != wb {
				return wa > wb
			}
			return idx[a] < idx[b]
		})
		sort.Slice(raw, func(i, j int) bool { return raw[i] > raw[j] })
		placed := make([]int, h)
		for rank, homeIdx := range idx {
			placed[homeIdx] = raw[rank]
		}
		raw = placed
		sum = 0
		for _, v := range raw {
			sum += v
		}
	}
	out := make([]int, h)
	assigned := 0
	for i := range out {
		out[i] = int(math.Round(float64(raw[i]) * float64(n) / float64(sum)))
		if out[i] < 1 {
			out[i] = 1
		}
		assigned += out[i]
	}
	adjust := func(delta int) {
		for assigned != n {
			best := 0
			if delta < 0 {
				for i := 1; i < h; i++ {
					if out[i] > out[best] {
						best = i
					}
				}
				if out[best] <= 1 {
					return
				}
			} else {
				for i := 1; i < h; i++ {
					if out[i] >= out[best] {
						best = i
					}
				}
			}
			out[best] += delta
			assigned += delta
		}
	}
	if assigned > n {
		adjust(-1)
	} else if assigned < n {
		adjust(1)
	}
	return out
}

// randomizeBits flips bits in [from, to) of b independently - that's how we
// fill the host portion of a prefix under a parent without copying the
// parent's extra bits
func randomizeBits(b []byte, from, to int, rng *rand.Rand) {
	for i := from; i < to && i < 8*len(b); i++ {
		bit := byte(1 << (7 - i%8))
		if rng.Intn(2) == 1 {
			b[i/8] |= bit
		} else {
			b[i/8] &^= bit
		}
	}
}

// makePrefix builds one prefix inside `home` at `bits`, optionally nesting
// under a random shorter parent from `parents` (v4NestProb / v6NestProb) so
// we get covering chains like the dump, not a flat bag of /24s
func makePrefix(rng *rand.Rand, home [2]byte, bits int, is6 bool, parents []netip.Prefix) netip.Prefix {
	nest := v4NestProb
	from := 16
	if is6 {
		nest = v6NestProb
	}
	parentBits := from
	var addr4 [4]byte
	var addr6 [16]byte
	addr4[0], addr4[1] = home[0], home[1]
	addr6[0], addr6[1] = home[0], home[1]
	if bits > from && len(parents) > 0 && rng.Float64() < nest {
		nCand := 0
		var pick netip.Prefix
		for _, p := range parents {
			if p.Bits() < bits && p.Bits() >= from {
				nCand++
				if rng.Intn(nCand) == 0 {
					pick = p
				}
			}
		}
		if nCand > 0 {
			parentBits = pick.Bits()
			if is6 {
				addr6 = pick.Addr().As16()
			} else {
				addr4 = pick.Addr().As4()
			}
		}
	}
	if is6 {
		randomizeBits(addr6[:], parentBits, bits, rng)
		return netip.PrefixFrom(netip.AddrFrom16(addr6), bits).Masked()
	}
	if bits < 16 {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{home[0], home[1], 0, 0}), bits).Masked()
	}
	randomizeBits(addr4[:], parentBits, bits, rng)
	return netip.PrefixFrom(netip.AddrFrom4(addr4), bits).Masked()
}

// placePrefix retries makePrefix until we get an unseen prefix - after 12
// collisions we start lengthening (the dump does that when a /24 is taken),
// and we only try once for <=/16 because those collide in a tiny space
func placePrefix(rng *rand.Rand, home [2]byte, bits int, is6 bool, parents []netip.Prefix, seen map[netip.Prefix]bool) (netip.Prefix, bool) {
	maxBits := 32
	if is6 {
		maxBits = 128
	}
	tries := 48
	if bits <= 16 {
		tries = 1
	}
	for try := 0; try < tries; try++ {
		bts := bits
		if try > 12 {
			bts = bits + try - 12
			if bts > maxBits {
				bts = maxBits
			}
		}
		p := makePrefix(rng, home, bts, is6, parents)
		if !seen[p] {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// fillHomes walks each home, draws occ[i] lengths from the family picker,
// sorts short-to-long so parents exist before children, and placePrefix's
// them - failed placements get a few random-length retries then we skip
func fillHomes(rng *rand.Rand, homes [][2]byte, occ []int, is6 bool, seen map[netip.Prefix]bool, out []netip.Prefix) []netip.Prefix {
	picker := v4Lengths
	if is6 {
		picker = v6Lengths
	}
	for i, home := range homes {
		lengths := make([]int, occ[i])
		for j := range lengths {
			lengths[j] = picker[rng.Intn(len(picker))]
		}
		sort.Ints(lengths)
		parents := make([]netip.Prefix, 0, occ[i])
		for _, bits := range lengths {
			p, ok := placePrefix(rng, home, bits, is6, parents, seen)
			if !ok {
				for try := 0; !ok && try < 16; try++ {
					p, ok = placePrefix(rng, home, picker[rng.Intn(len(picker))], is6, parents, seen)
				}
			}
			if !ok {
				continue
			}
			seen[p] = true
			parents = append(parents, p)
			out = append(out, p)
		}
	}
	return out
}

// topUp pads out to exactly n after fillHomes came up short (collisions /
// skipped homes) - random home + random length, and if we're really stuck
// we forceHost a unique /32 or /128 so genPrefixes never returns the wrong
// count
func topUp(rng *rand.Rand, n int, homes [][2]byte, is6 bool, seen map[netip.Prefix]bool, out []netip.Prefix) []netip.Prefix {
	if len(homes) == 0 {
		return out
	}
	picker := v4Lengths
	if is6 {
		picker = v6Lengths
	}
	guard := 0
	for len(out) < n {
		home := homes[rng.Intn(len(homes))]
		bits := picker[rng.Intn(len(picker))]
		p, ok := placePrefix(rng, home, bits, is6, nil, seen)
		if !ok {
			guard++
			if guard > n*8 {
				p = forceHost(home, is6, seen, uint32(len(out)))
				if seen[p] {
					continue
				}
			} else {
				continue
			}
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// forceHost is the last-ditch unique host prefix inside `home` - we stuff
// seq into the last two octets and bump until unseen
func forceHost(home [2]byte, is6 bool, seen map[netip.Prefix]bool, seq uint32) netip.Prefix {
	if is6 {
		var b [16]byte
		b[0], b[1] = home[0], home[1]
		b[14] = byte(seq >> 8)
		b[15] = byte(seq)
		p := netip.PrefixFrom(netip.AddrFrom16(b), 128).Masked()
		for seen[p] {
			seq++
			b[14] = byte(seq >> 8)
			b[15] = byte(seq)
			p = netip.PrefixFrom(netip.AddrFrom16(b), 128).Masked()
		}
		return p
	}
	a := [4]byte{home[0], home[1], byte(seq >> 8), byte(seq)}
	p := netip.PrefixFrom(netip.AddrFrom4(a), 32).Masked()
	for seen[p] {
		seq++
		a[2], a[3] = byte(seq>>8), byte(seq)
		p = netip.PrefixFrom(netip.AddrFrom4(a), 32).Masked()
	}
	return p
}

// genFamily is the per-family pipeline: pick homes, assign occupancy, fill,
// top up - that's one v4 or v6 bag of exactly n prefixes
func genFamily(rng *rand.Rand, n int, is6 bool) []netip.Prefix {
	if n <= 0 {
		return nil
	}
	var homes [][2]byte
	if is6 {
		homes = sampleV6Homes(rng, v6HomeCount(n))
	} else {
		homes = sampleV4Homes(rng, v4HomeCount(n))
	}
	occ := assignOccupancy(rng, homes, n, is6)
	seen := make(map[netip.Prefix]bool, n)
	out := fillHomes(rng, homes, occ, is6, seen, make([]netip.Prefix, 0, n))
	return topUp(rng, n, homes, is6, seen, out)
}

// genPrefixes is what the benches call - n prefixes, mix is the v6 fraction
// (dfzV6Mix for "pretend we're the DFZ"), seed for reproducibility
//
// we round the v6 count rather than Bernoulli each prefix so a 200k table
// always has the same family split for a given mix
func genPrefixes(n int, mix float64, seed int64) []netip.Prefix {
	rng := rand.New(rand.NewSource(seed))
	n6 := int(math.Round(float64(n) * mix))
	if n6 > n {
		n6 = n
	}
	n4 := n - n6
	out := make([]netip.Prefix, 0, n)
	out = append(out, genFamily(rng, n4, false)...)
	out = append(out, genFamily(rng, n6, true)...)
	return out
}

// genQueriesUniform picks a random stored prefix and a random addr inside
// it - every prefix equally likely, so the working set is the whole table
// (the cache-hostile case)
func genQueriesUniform(pfxs []netip.Prefix, n int, seed int64) []netip.Addr {
	rng := rand.New(rand.NewSource(seed))
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = addrIn(pfxs[rng.Intn(len(pfxs))], rng)
	}
	return out
}

// genQueriesZipf is the forwarding-plane shape - Zipf(s=1.1) over prefixes
// then a random host inside, so a small hot set stays in cache
func genQueriesZipf(pfxs []netip.Prefix, n int, seed int64) []netip.Addr {
	rng := rand.New(rand.NewSource(seed))
	z := rand.NewZipf(rng, 1.1, 1, uint64(len(pfxs)-1))
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = addrIn(pfxs[z.Uint64()], rng)
	}
	return out
}

// genQueriesMiss draws addrs in 240/4 (CLASS-E) so they miss a DFZ-shaped
// table - that's the ACL/filter "no match" path
func genQueriesMiss(n int, seed int64) []netip.Addr {
	rng := rand.New(rand.NewSource(seed))
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = netip.AddrFrom4([4]byte{byte(240 + rng.Intn(15)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
	return out
}

// addrIn randomises the host bits of p - v4 via a mask on the flattened
// uint32, v6 by flipping remaining bits independently (same idea as
// realAddrIn, kept local so the generator doesn't depend on realtable)
func addrIn(p netip.Prefix, rng *rand.Rand) netip.Addr {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		v := flat4(a)
		if bits < 32 {
			v |= rng.Uint32() & (uint32(math.MaxUint32) >> uint(bits))
		}
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := a.As16()
	for i := bits; i < 128; i++ {
		if rng.Intn(2) == 1 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	return netip.AddrFrom16(b)
}

// TestGenPrefixesShape is the "did we actually model the dump" check - we
// generate a full-table-sized bag plus 200k v4-only and v6-only, then assert
// occupancy mean, /24 share, singleton share, RIR /16 count, /32+/48 mix
//
// if this fails the benches are still "a" workload, just not the DFZ one we
// claimed, so don't skip it when you change the sampler
func TestGenPrefixesShape(t *testing.T) {
	cases := []struct {
		name string
		n    int
		mix  float64
		seed int64
	}{
		{"full table", dfzPrefixCount, dfzV6Mix, 3},
		{"200k v4-only", 200_000, 0, 9},
		{"200k v6-only", 200_000, 1, 9},
	}
	rirOctet := map[byte]bool{0x20: true, 0x24: true, 0x26: true, 0x28: true, 0x2a: true, 0x2c: true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pfxs := genPrefixes(c.n, c.mix, c.seed)
			if len(pfxs) != c.n {
				t.Fatalf("got %d prefixes, want %d", len(pfxs), c.n)
			}
			want6 := int(math.Round(float64(c.n) * c.mix))
			if want6 > c.n {
				want6 = c.n
			}
			var n4, n6, n24, nLong, nShort, n32, n48 int
			v4occ := map[uint16]int{}
			v6occ := map[uint16]int{}
			for _, p := range pfxs {
				a := p.Addr()
				bits := p.Bits()
				if a.Is4() {
					n4++
					b := a.As4()
					v4occ[uint16(b[0])<<8|uint16(b[1])]++
					switch {
					case bits == 24:
						n24++
					case bits > 24:
						nLong++
					case bits <= 16:
						nShort++
					}
				} else {
					n6++
					b := a.As16()
					v6occ[uint16(b[0])<<8|uint16(b[1])]++
					if bits == 32 {
						n32++
					}
					if bits == 48 {
						n48++
					}
					if !rirOctet[b[0]] {
						t.Errorf("IPv6 prefix %v outside dump RIR /8s", p)
					}
				}
			}
			if n6 != want6 {
				t.Errorf("IPv6 count = %d, want %d (exact mix)", n6, want6)
			}
			if n4 > 0 {
				per16 := float64(n4) / float64(len(v4occ))
				share24 := 100 * float64(n24) / float64(n4)
				shareLong := 100 * float64(nLong) / float64(n4)
				shareShort := 100 * float64(nShort) / float64(n4)
				counts := make([]int, 0, len(v4occ))
				singletons := 0
				maxOcc := 0
				for _, occ := range v4occ {
					counts = append(counts, occ)
					if occ == 1 {
						singletons++
					}
					if occ > maxOcc {
						maxOcc = occ
					}
				}
				sort.Ints(counts)
				p50 := counts[len(counts)/2]
				t.Logf("IPv4 n=%d occupied/16=%d per/16=%.1f p50=%d max=%d singletons=%.1f%% /24=%.1f%% >24=%.2f%% <=16=%.1f%%",
					n4, len(v4occ), per16, p50, maxOcc, 100*float64(singletons)/float64(len(v4occ)), share24, shareLong, shareShort)
				if per16 < 27 || per16 > 34 {
					t.Errorf("IPv4 prefixes per occupied /16 = %.1f, want ~30.7", per16)
				}
				if share24 < 60 || share24 > 67 {
					t.Errorf("IPv4 /24 share = %.1f%%, want ~63.3%%", share24)
				}
				if shareLong > 0.4 {
					t.Errorf("IPv4 >24 share = %.2f%%, want ~0.1%%", shareLong)
				}
				if shareShort < 1.0 || shareShort > 2.2 {
					t.Errorf("IPv4 /16-or-shorter share = %.1f%%, want ~1.6%%", shareShort)
				}
				if n4 >= 50_000 {
					if p50 > 20 {
						t.Errorf("IPv4 occupancy p50 = %d, want a dump-like tail well below the mean (~7)", p50)
					}
					if 100*float64(singletons)/float64(len(v4occ)) < 15 {
						t.Errorf("IPv4 singleton /16 share = %.1f%%, want ~28%%", 100*float64(singletons)/float64(len(v4occ)))
					}
					if maxOcc < 80 {
						t.Errorf("IPv4 occupancy max = %d, want a long tail (dump max 433)", maxOcc)
					}
				}
			}
			if n6 > 0 {
				share32 := 100 * float64(n32) / float64(n6)
				share48 := 100 * float64(n48) / float64(n6)
				t.Logf("IPv6 n=%d occupied/16=%d /32=%.1f%% /48=%.1f%%", n6, len(v6occ), share32, share48)
				if c.mix > 0 && (len(v6occ) < 60 || len(v6occ) > 70) && n6 >= v6Occupied16s {
					t.Errorf("IPv6 occupied /16s = %d, want %d RIR blocks", len(v6occ), v6Occupied16s)
				}
				if n6 >= 10_000 {
					if share32 < 7 || share32 > 14 {
						t.Errorf("IPv6 /32 share = %.1f%%, want ~10.4%%", share32)
					}
					if share48 < 40 || share48 > 52 {
						t.Errorf("IPv6 /48 share = %.1f%%, want ~46.3%%", share48)
					}
				}
			}
		})
	}
}
