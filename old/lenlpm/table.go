// Package lenlpm is the "just binary-search each length" table. Tiny
// retained footprint, miserable lookup: we probe every populated length
// longest-first. We kept it as a memory floor; nobody should use this
// as a FIB
package lenlpm

import (
	"net/netip"
	"sort"

	"github.com/iqhive/prefixlookup/prefixentry"
)

type row4 struct{ key, value uint32 }
type row6 struct {
	hi, lo uint64
	value  uint32
}

// Table stores only canonical prefixes, payload indexes, and populated prefix
// lengths. It minimises retained memory at the cost of binary searches. Fine
// for tiny tables, hopeless once you've got more than a handful of lengths
type Table[V any] struct {
	v4     [33][]row4
	v6     [129][]row6
	v4Bits []uint8
	v6Bits []uint8
	values []V
}

// New builds an immutable compact prefix table. Bucket by length, sort each
// bucket, last-wins-dedup, then record which lengths actually have rows so
// Lookup doesn't scan empty buckets
func New[V any](entries []prefixentry.Entry[V]) (*Table[V], error) {
	t := &Table[V]{values: make([]V, 1, len(entries)+1)}
	for _, entry := range entries {
		prefix, ok := prefixentry.NormalizePrefix(entry.Prefix)
		if !ok {
			return nil, prefixentry.ErrBadIP
		}
		t.values = append(t.values, entry.Value)
		value, bits := uint32(len(t.values)-1), prefix.Bits()
		if prefix.Addr().Is4() {
			t.v4[bits] = append(t.v4[bits], row4{prefixentry.Addr4(prefix.Addr()), value})
		} else {
			hi, lo := prefixentry.Addr6(prefix.Addr())
			t.v6[bits] = append(t.v6[bits], row6{hi, lo, value})
		}
	}
	// longest-first so Lookup can just range v4Bits
	for bits := 32; bits >= 0; bits-- {
		if len(t.v4[bits]) == 0 {
			continue
		}
		sort.Slice(t.v4[bits], func(i, j int) bool { return t.v4[bits][i].key < t.v4[bits][j].key })
		t.v4[bits] = dedupe4(t.v4[bits])
		t.v4Bits = append(t.v4Bits, uint8(bits))
	}
	for bits := 128; bits >= 0; bits-- {
		if len(t.v6[bits]) == 0 {
			continue
		}
		sort.Slice(t.v6[bits], func(i, j int) bool {
			a, b := t.v6[bits][i], t.v6[bits][j]
			return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo
		})
		t.v6[bits] = dedupe6(t.v6[bits])
		t.v6Bits = append(t.v6Bits, uint8(bits))
	}
	return t, nil
}

// dedupe4 collapses equal keys in a sorted v4 bucket, keeping the later
// (higher index) value so last-insert-wins matches the other tables
func dedupe4(rows []row4) []row4 {
	out := rows[:0]
	for _, r := range rows {
		if n := len(out); n > 0 && out[n-1].key == r.key {
			if r.value > out[n-1].value {
				out[n-1].value = r.value
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// dedupe6 is dedupe4 for the 128-bit key split across hi/lo
func dedupe6(rows []row6) []row6 {
	out := rows[:0]
	for _, r := range rows {
		if n := len(out); n > 0 && out[n-1].hi == r.hi && out[n-1].lo == r.lo {
			if r.value > out[n-1].value {
				out[n-1].value = r.value
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// Lookup performs LPM by probing only prefix lengths present in the table,
// longest first. Mask the key, binary-search that length's row. We bailed
// on this as a FIB because the miss path pays every length
func (t *Table[V]) Lookup(addr netip.Addr) (V, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		var zero V
		return zero, false
	}
	if addr.Is4() {
		key := prefixentry.Addr4(addr)
		for _, b := range t.v4Bits {
			bits := int(b)
			masked := key & prefixentry.IPv4Mask(bits)
			rows := t.v4[bits]
			i := sort.Search(len(rows), func(i int) bool { return rows[i].key >= masked })
			if i < len(rows) && rows[i].key == masked {
				return t.values[rows[i].value], true
			}
		}
	} else {
		hi, lo := prefixentry.Addr6(addr)
		for _, b := range t.v6Bits {
			bits := int(b)
			mh, ml := hi, lo
			if bits < 64 {
				mh &= ^uint64(0) << (64 - bits)
				ml = 0
			} else if bits < 128 {
				ml &= ^uint64(0) << (128 - bits)
			}
			rows := t.v6[bits]
			i := sort.Search(len(rows), func(i int) bool { return rows[i].hi > mh || rows[i].hi == mh && rows[i].lo >= ml })
			if i < len(rows) && rows[i].hi == mh && rows[i].lo == ml {
				return t.values[rows[i].value], true
			}
		}
	}
	var zero V
	return zero, false
}

// Prefixes returns the number of canonical prefix rows retained. After
// dedupe this is the actual stored set, not the input length
func (t *Table[V]) Prefixes() int {
	n := 0
	for _, rows := range t.v4 {
		n += len(rows)
	}
	for _, rows := range t.v6 {
		n += len(rows)
	}
	return n
}
