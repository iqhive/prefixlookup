package tests_test

import (
	"net/netip"
	"testing"

	"github.com/iqhive/prefixlookup/artlpm"
	"github.com/iqhive/prefixlookup/groupartset"
	"github.com/iqhive/prefixlookup/old/arenaartlpm"
	"github.com/iqhive/prefixlookup/old/artwalk"
	"github.com/iqhive/prefixlookup/old/latticeartset"
)

type fuzzOp struct {
	kind        byte
	addr        netip.Addr
	bits, value int
}

// decodeOps unpacks the fuzzer byte soup into a short op list - we take 7
// bytes per op, cap at 300 so a huge seed doesn't run forever, and fold
// kind into insert/delete/lookup
//
// v4 vs v6 is data[1]&1; v6 only gets 4 entropy bytes tiled across 16 so
// the corpus stays compact - bits are taken from data[2] modulo 33/129
func decodeOps(data []byte) []fuzzOp {
	ops := make([]fuzzOp, 0, len(data)/7)
	for len(data) >= 7 && len(ops) < 300 {
		op := fuzzOp{kind: data[0] % 3, value: int(data[2])}
		if data[1]&1 == 0 {
			op.addr = netip.AddrFrom4([4]byte{data[3], data[4], data[5], data[6]})
			op.bits = int(data[2] % 33)
		} else {
			var bytes [16]byte
			for i := range bytes {
				bytes[i] = data[3+i%4]
			}
			bytes[15] = data[5]
			op.addr, op.bits = netip.AddrFrom16(bytes), int(data[2]%129)
		}
		ops = append(ops, op)
		data = data[7:]
	}
	return ops
}

// FuzzImplementationsAgree is the cross-impl fuzz: decode ops, play them on
// artlpm / latticeartset / groupartset / artwalk / arenaartlpm plus the
// oracle, and fail on any delete/lookup/size disagreement
//
// we seed a handful of hand-written corpora (v4, v6, defaults, ascii junk)
// so go-fuzz has somewhere to start - at the end we Rebuild the compact
// table and re-lookup every remaining prefix, because that's the path that
// used to hide stale dead slots
func FuzzImplementationsAgree(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 0, 8, 10, 0, 0, 0, 0, 0, 16, 10, 1, 0, 0, 2, 0, 32, 10, 1, 2, 3},
		{0, 1, 64, 32, 1, 13, 184, 2, 1, 128, 32, 1, 13, 184},
		{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		[]byte("01Aaaaa01Baaaa210aaaa0000"),
		[]byte("0100000010000100000000001000"),
		[]byte("0010200001010000100001010000"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		table, set, set5, rib, compact, want := artlpm.New[int](), latticeartset.New(), groupartset.New(), artwalk.New[int](), arenaartlpm.New[int](), newOracle()
		for _, op := range decodeOps(data) {
			prefix := netip.PrefixFrom(op.addr, op.bits).Masked()
			switch op.kind {
			case 0:
				table.Insert(prefix, op.value)
				set.Insert(prefix)
				set5.Insert(prefix)
				rib.Insert(prefix, op.value)
				compact.Insert(prefix, op.value)
				want.insert(prefix, op.value)
			case 1:
				expected := want.delete(prefix)
				if table.Delete(prefix) != expected || set.Delete(prefix) != expected || set5.Delete(prefix) != expected || rib.Delete(prefix) != expected || compact.Delete(prefix) != expected {
					t.Fatalf("Delete(%v) disagreed", prefix)
				}
			case 2:
				value, ok := want.lookup(op.addr)
				for name, implementation := range map[string]lookupTable{"table": table, "rib": rib, "compact": compact} {
					got, gotOK := implementation.Lookup(op.addr)
					if gotOK != ok || ok && got != value {
						t.Fatalf("%s Lookup(%v) = (%d,%v), want (%d,%v)", name, op.addr, got, gotOK, value, ok)
					}
				}
				if set.Contains(op.addr) != ok {
					t.Fatalf("set Contains(%v) != %v", op.addr, ok)
				}
				if set5.Contains(op.addr) != ok {
					t.Fatalf("set5 Contains(%v) != %v", op.addr, ok)
				}
			}
		}
		rebuilt := compact.Rebuild()
		if table.Size() != len(want.values) || set.Size() != len(want.values) || set5.Size() != len(want.values) || rib.Size() != len(want.values) || rebuilt.Size() != len(want.values) {
			t.Fatal("final sizes disagree")
		}
		for prefix := range want.values {
			value, ok := want.lookup(prefix.Addr())
			if got, gotOK := rebuilt.Lookup(prefix.Addr()); gotOK != ok || ok && got != value {
				t.Fatalf("rebuilt Lookup(%v) disagreed", prefix.Addr())
			}
		}
	})
}
