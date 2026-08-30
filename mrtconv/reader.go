package mrtconv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"github.com/iqhive/prefixlookup/prefixentry"
)

// Reader maps a compact binary table and yields its prefixes with a single
// forward pass and no intermediate allocations beyond the returned values - this
// is the fast path a benchmark suite uses to load a full table into memory
type Reader struct {
	data   []byte
	off    int
	v4Left int
	v6Left int
	unmap  func() error
}

// Open maps the binary table at path and validates its header - mmapFile then
// parseHeader; if the header's junk we unmap immediately so the caller isn't
// left holding a mapping
func Open(path string) (*Reader, error) {
	data, unmap, err := mmapFile(path)
	if err != nil {
		return nil, err
	}
	r := &Reader{data: data, unmap: unmap}
	if err := r.parseHeader(); err != nil {
		unmap()
		return nil, err
	}
	return r, nil
}

// parseHeader checks magic/version and reads the two counts so Next can slice
// records without bounds panics - we also verify the file is long enough for
// the declared body
func (r *Reader) parseHeader() error {
	if len(r.data) < tableHeaderLen {
		return errors.New("truncated table header")
	}
	if string(r.data[0:8]) != string(tableMagic[:]) {
		return errors.New("bad table magic")
	}
	if r.data[8] != tableVersion {
		return fmt.Errorf("unsupported table version %d", r.data[8])
	}
	// counts sit at 16 and 24; we trust them only after the length check below
	r.v4Left = int(binary.BigEndian.Uint64(r.data[16:24]))
	r.v6Left = int(binary.BigEndian.Uint64(r.data[24:32]))
	need := tableHeaderLen + r.v4Left*v4RecordLen + r.v6Left*v6RecordLen
	if len(r.data) < need {
		return errors.New("truncated table body")
	}
	r.off = tableHeaderLen
	return nil
}

// Count returns prefixes not yet consumed - just v4Left+v6Left, no scan
func (r *Reader) Count() int { return r.v4Left + r.v6Left }

// Next returns the next prefix, IPv4 first then IPv6 - we slice a fixed-size
// record off data, bump off, and decode addr+bits in place; false once empty
func (r *Reader) Next() (netip.Prefix, bool) {
	if r.v4Left > 0 {
		rec := r.data[r.off : r.off+v4RecordLen]
		r.off += v4RecordLen
		r.v4Left--
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{rec[0], rec[1], rec[2], rec[3]}), int(rec[4])), true
	}
	if r.v6Left > 0 {
		// v6 after v4 so a single Count/Entries walk is family-sorted
		rec := r.data[r.off : r.off+v6RecordLen]
		r.off += v6RecordLen
		r.v6Left--
		var a [16]byte
		copy(a[:], rec[0:16])
		return netip.PrefixFrom(netip.AddrFrom16(a), int(rec[16])), true
	}
	return netip.Prefix{}, false
}

// ReadAll consumes the remaining prefixes and returns them split by family - we
// preallocate from the leftover counts then Next() into each slice
func (r *Reader) ReadAll() *Table {
	v4 := make([]netip.Prefix, r.v4Left)
	for i := range v4 {
		v4[i], _ = r.Next()
	}
	v6 := make([]netip.Prefix, r.v6Left)
	for i := range v6 {
		v6[i], _ = r.Next()
	}
	return &Table{V4: v4, V6: v6}
}

// Entries consumes the remaining prefixes and returns them paired with
// sequential uint32 values, matching the shape the benchmark tables consume -
// Count() sizes the slice, then we Next and stamp Value = i+1
func (r *Reader) Entries() []prefixentry.Entry[uint32] {
	out := make([]prefixentry.Entry[uint32], r.Count())
	for i := range out {
		p, _ := r.Next()
		out[i] = prefixentry.Entry[uint32]{Prefix: p, Value: uint32(i + 1)}
	}
	return out
}

// Close releases the memory mapping - nil unmap means already closed or we
// never mapped (empty file); we nil it after so a second Close is a no-op
func (r *Reader) Close() error {
	if r.unmap == nil {
		return nil
	}
	err := r.unmap()
	r.unmap = nil
	return err
}

// mmapFile opens path and MAP_SHARED PROT_READs the whole file - empty files
// skip mmap and return a no-op closer; we close the fd after mmap because the
// mapping holds the pages on its own
func mmapFile(path string) ([]byte, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if st.Size() == 0 {
		// empty file isn't worth mapping; Close still wants a func
		return nil, func() error { return nil }, nil
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	// unmap closes over data; the fd is already deferred-closed
	return data, func() error { return syscall.Munmap(data) }, nil
}
