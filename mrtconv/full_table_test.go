package mrtconv

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// mrtRecord wraps body in a 12-byte TABLE_DUMP_V2 header so ParseMRT sees a
// real-looking stream - we stamp type 13, the subtype, and the body length
func mrtRecord(sub uint16, body []byte) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], 0)
	binary.BigEndian.PutUint16(hdr[4:6], mrtTypeTableDumpV2)
	binary.BigEndian.PutUint16(hdr[6:8], sub)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(body)))
	return append(hdr, body...)
}

// ribBody builds a RIB-Entry payload: 4-byte seq, prefix bits, truncated addr,
// then a dummy entry-count plus zeroed peer slots we never look at
func ribBody(bits int, addr []byte, entries int) []byte {
	body := make([]byte, 0, 5+len(addr)+2+entries*8)
	body = append(body, 0, 0, 0, 0)
	body = append(body, byte(bits))
	body = append(body, addr...)
	body = append(body, byte(entries>>8), byte(entries))
	for range entries {
		body = append(body, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	return body
}

// TestParseMRT feeds a toy MRT stream (peer-index + two v4 RIBs + one v6) and
// checks we skip the peer table, honour family, and keep insertion order
func TestParseMRT(t *testing.T) {
	var stream []byte
	stream = append(stream, mrtRecord(mrtPeerIndexTable, make([]byte, 8))...)
	stream = append(stream, mrtRecord(mrtRIBIPv4Unicast, ribBody(24, []byte{10, 0, 0}, 1))...)
	stream = append(stream, mrtRecord(mrtRIBIPv4Unicast, ribBody(8, []byte{10}, 2))...)
	stream = append(stream, mrtRecord(mrtRIBIPv6Unicast, ribBody(32, []byte{0x20, 0x01, 0x0d, 0xb8}, 2))...)

	v4, err := ParseMRT(bytes.NewReader(stream), 4)
	if err != nil {
		t.Fatal(err)
	}
	wantV4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	if len(v4) != len(wantV4) {
		t.Fatalf("v4 got %d prefixes, want %d", len(v4), len(wantV4))
	}
	for i := range wantV4 {
		if v4[i] != wantV4[i] {
			t.Errorf("v4[%d] = %s, want %s", i, v4[i], wantV4[i])
		}
	}

	v6, err := ParseMRT(bytes.NewReader(stream), 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(v6) != 1 || v6[0] != netip.MustParsePrefix("2001:db8::/32") {
		t.Fatalf("v6 got %v, want [2001:db8::/32]", v6)
	}
}

// writeTemp dumps tbl via Write into a temp file and returns the path - Helper
// so fatals attribute to the caller
func writeTemp(t *testing.T, tbl *Table) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "table.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(f, tbl); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRoundTrip Write()s a mixed table then Load()s it back - we compare both
// families elementwise so a swapped record length would blow up immediately
func TestRoundTrip(t *testing.T) {
	in := &Table{
		V4: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		V6: []netip.Prefix{
			netip.MustParsePrefix("::/0"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	}
	path := writeTemp(t, in)

	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.V4) != len(in.V4) || len(out.V6) != len(in.V6) {
		t.Fatalf("got %d/%d, want %d/%d", len(out.V4), len(out.V6), len(in.V4), len(in.V6))
	}
	for i := range in.V4 {
		if out.V4[i] != in.V4[i] {
			t.Errorf("v4[%d] = %s, want %s", i, out.V4[i], in.V4[i])
		}
	}
	for i := range in.V6 {
		if out.V6[i] != in.V6[i] {
			t.Errorf("v6[%d] = %s, want %s", i, out.V6[i], in.V6[i])
		}
	}
}

// TestReader walks Next until exhausted, then checks Entries() on a fresh Open
// assigns 1-based uint32 values - we also confirm a spent reader yields nothing
func TestReader(t *testing.T) {
	in := &Table{
		V4: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")},
		V6: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}
	path := writeTemp(t, in)

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if got := r.Count(); got != 3 {
		t.Fatalf("Count = %d, want 3", got)
	}

	var got []netip.Prefix
	for {
		p, ok := r.Next()
		if !ok {
			break
		}
		got = append(got, p)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(got) != len(want) {
		t.Fatalf("iterated %d prefixes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix[%d] = %s, want %s", i, got[i], want[i])
		}
	}

	entries := r.Entries()
	if len(entries) != 0 {
		t.Fatalf("Entries after exhaustion = %d, want 0", len(entries))
	}

	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	entries = r2.Entries()
	if len(entries) != 3 {
		t.Fatalf("Entries = %d, want 3", len(entries))
	}
	if entries[0].Value != 1 || entries[2].Value != 3 {
		t.Fatalf("values = %d,%d, want 1,3", entries[0].Value, entries[2].Value)
	}
	if entries[0].Prefix != want[0] || entries[2].Prefix != want[2] {
		t.Fatalf("entry prefixes = %s,%s, want %s,%s", entries[0].Prefix, entries[2].Prefix, want[0], want[2])
	}
}
