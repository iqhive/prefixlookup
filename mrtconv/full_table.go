// Package mrtconv converts MRT TABLE_DUMP_V2 RIB dumps into a compact binary
// table that a benchmark suite can load directly into memory without re-parsing
// the (multi-gigabyte) MRT stream or its BGP attributes
//
// The binary format is a flat, fixed-record layout so a loader can map the file
// and decode prefixes with a single pass and no per-record parsing:
//
//	offset  size  field
//	0       8     magic "MRTTBL01"
//	8       1     version (1)
//	9       7     reserved
//	16      8     v4 prefix count (big-endian)
//	24      8     v6 prefix count (big-endian)
//	32      8*v4  v4 records: [4]byte addr, uint8 bits, 3 bytes pad
//	...     24*v6 v6 records: [16]byte addr, uint8 bits, 7 bytes pad
package mrtconv

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
)

const (
	mrtTypeTableDumpV2 = 13
	mrtPeerIndexTable  = 1
	mrtRIBIPv4Unicast  = 2
	mrtRIBIPv6Unicast  = 4
	mrtRIBIPv4AddPath  = 6
	mrtRIBIPv6AddPath  = 8
)

var tableMagic = [8]byte{'M', 'R', 'T', 'T', 'B', 'L', '0', '1'}

const (
	tableVersion   = 1
	tableHeaderLen = 32
	v4RecordLen    = 8
	v6RecordLen    = 24
)

// Table holds the unique prefixes we pulled out of a full BGP table dump
type Table struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// Prefixes concatenates every prefix in the table, IPv4 first then IPv6 - we
// pre-size the dest so it's one alloc then two appends
func (t *Table) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(t.V4)+len(t.V6))
	out = append(out, t.V4...)
	out = append(out, t.V6...)
	return out
}

// ParseMRT reads an MRT TABLE_DUMP_V2 stream and returns the unique prefixes
// of the given address family (4 or 6) - we walk 12-byte headers, skip anything
// that isn't a unicast RIB, and dedupe via a map so Add-Path dupes don't land twice
func ParseMRT(r io.Reader, family int) ([]netip.Prefix, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	hdr := make([]byte, 12)

	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		typ := binary.BigEndian.Uint16(hdr[4:6])
		sub := binary.BigEndian.Uint16(hdr[6:8])
		length := binary.BigEndian.Uint32(hdr[8:12])

		if typ != mrtTypeTableDumpV2 {
			// not a RIB dump - skip the payload and keep walking
			if err := discard(br, int64(length)); err != nil {
				return nil, err
			}
			continue
		}

		switch sub {
		case mrtPeerIndexTable:
			// peer table is useless to us, we only want prefixes
			if err := discard(br, int64(length)); err != nil {
				return nil, err
			}
		case mrtRIBIPv4Unicast, mrtRIBIPv4AddPath:
			if family != 4 {
				if err := discard(br, int64(length)); err != nil {
					return nil, err
				}
				continue
			}
			p, err := parseRIB(br, length, 4)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		case mrtRIBIPv6Unicast, mrtRIBIPv6AddPath:
			if family != 6 {
				if err := discard(br, int64(length)); err != nil {
					return nil, err
				}
				continue
			}
			p, err := parseRIB(br, length, 6)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		default:
			// multicast / unknown subtypes - chuck the body
			if err := discard(br, int64(length)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// parseRIB extracts the single prefix carried by a RIB record body of length
// bytes - we pull sequence + prefix-len + addr bytes, then discard the rest
// (peer entries / attributes) so we never have to parse BGP
func parseRIB(br *bufio.Reader, length uint32, family int) (netip.Prefix, error) {
	var seq [4]byte
	if _, err := io.ReadFull(br, seq[:]); err != nil {
		return netip.Prefix{}, err
	}
	var bitsB [1]byte
	if _, err := io.ReadFull(br, bitsB[:]); err != nil {
		return netip.Prefix{}, err
	}
	bits := int(bitsB[0])
	nbytes := (bits + 7) / 8 // prefix is packed, not a full addr
	maxBytes := 4
	if family == 6 {
		maxBytes = 16
	}
	if bits < 0 || nbytes > maxBytes {
		return netip.Prefix{}, fmt.Errorf("bad prefix length %d for family %d", bits, family)
	}

	var pfx [16]byte
	if _, err := io.ReadFull(br, pfx[:nbytes]); err != nil {
		return netip.Prefix{}, err
	}

	rest := int64(length) - 5 - int64(nbytes) // seq(4)+bits(1)+addr
	if rest < 0 {
		return netip.Prefix{}, errors.New("short RIB record")
	}
	if err := discard(br, rest); err != nil {
		return netip.Prefix{}, err
	}

	if family == 4 {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{pfx[0], pfx[1], pfx[2], pfx[3]}), bits).Masked(), nil
	}
	return netip.PrefixFrom(netip.AddrFrom16(pfx), bits).Masked(), nil
}

// discard skips n bytes on br - bufio.Discard is the fast path; n<=0 is a no-op
func discard(br *bufio.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	_, err := br.Discard(int(n))
	return err
}

// Write serialises the table in the compact binary format - header with magic
// + counts, then packed v4 records (8 bytes) then v6 (24 bytes), one flush at
// the end so we're not syscalling per prefix
func Write(w io.Writer, t *Table) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	var hdr [tableHeaderLen]byte
	copy(hdr[0:8], tableMagic[:])
	hdr[8] = tableVersion
	binary.BigEndian.PutUint64(hdr[16:24], uint64(len(t.V4)))
	binary.BigEndian.PutUint64(hdr[24:32], uint64(len(t.V6)))
	if _, err := bw.Write(hdr[:]); err != nil {
		return err
	}

	var rec [v6RecordLen]byte // reuse the bigger buffer for both families
	for _, p := range t.V4 {
		a := p.Addr().As4()
		copy(rec[0:4], a[:])
		rec[4] = byte(p.Bits())
		if _, err := bw.Write(rec[:v4RecordLen]); err != nil {
			return err
		}
	}
	for _, p := range t.V6 {
		a := p.Addr().As16()
		copy(rec[0:16], a[:])
		rec[16] = byte(p.Bits())
		if _, err := bw.Write(rec[:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// Load maps a compact binary table produced by Write and decodes its prefixes -
// Open + ReadAll + Close, that's the whole loader
func Load(path string) (*Table, error) {
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.ReadAll(), nil
}

// Convert reads the v4 and v6 MRT dumps and writes the combined binary table -
// parse each family separately then Write so the output is what Load expects
func Convert(v4Path, v6Path, outPath string) error {
	v4, err := loadMRTFile(v4Path, 4)
	if err != nil {
		return fmt.Errorf("v4: %w", err)
	}
	v6, err := loadMRTFile(v6Path, 6)
	if err != nil {
		return fmt.Errorf("v6: %w", err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return Write(f, &Table{V4: v4, V6: v6})
}

// loadMRTFile opens path and runs ParseMRT for family - tiny wrapper so Convert
// doesn't duplicate the open/close boilerplate
func loadMRTFile(path string, family int) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMRT(f, family)
}
