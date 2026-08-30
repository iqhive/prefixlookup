// Command mrtconv converts MRT TABLE_DUMP_V2 RIB dumps into the compact binary
// table that the benchmark suite loads directly, and reports what is in one
//
// Converting once matters because the dumps are gigabytes of BGP attributes that
// the benchmarks don't need; the binary form is a flat record per prefix, so
// loading a full table is a single pass over about 15 MB
//
// Usage:
//
//	mrtconv -v4 v4-rib -v6 v6-rib -o full-table.bin
//	mrtconv -stat full-table.bin
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"

	"github.com/iqhive/prefixlookup/mrtconv"
)

// main is the CLI: -stat dumps a histogram, otherwise we Convert then report
// so you can see whether the write actually looks like a table
func main() {
	var (
		v4Path = flag.String("v4", "", "path to the IPv4 MRT TABLE_DUMP_V2 dump")
		v6Path = flag.String("v6", "", "path to the IPv6 MRT TABLE_DUMP_V2 dump")
		out    = flag.String("o", "", "path to write the compact binary table to")
		stat   = flag.String("stat", "", "report the contents of a compact binary table")
	)
	flag.Parse()

	switch {
	case *stat != "":
		if err := report(*stat); err != nil {
			fail(err)
		}
	case *v4Path != "" || *v6Path != "":
		if *out == "" {
			fail(fmt.Errorf("-o is required when converting"))
		}
		if err := mrtconv.Convert(*v4Path, *v6Path, *out); err != nil {
			fail(err)
		}
		// dump the histogram so we can eyeball whether Convert worked
		if err := report(*out); err != nil {
			fail(err)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// fail prints err to stderr and dies with status 1 - we don't want a stack
func fail(err error) {
	fmt.Fprintln(os.Stderr, "mrtconv:", err)
	os.Exit(1)
}

// report prints the prefix-length histogram and the stride occupancy that
// determine how a trie compiles the table - Load the file then describe each family
func report(path string) error {
	table, err := mrtconv.Load(path)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", path)
	fmt.Printf("  IPv4 prefixes: %d\n", len(table.V4))
	fmt.Printf("  IPv6 prefixes: %d\n", len(table.V6))
	describe("IPv4", table.V4, 32)
	describe("IPv6", table.V6, 128)
	return nil
}

// describe dumps a length histogram (top 12) plus how many /8 and /16 blocks
// are occupied - we tally bits() into a slice and the top 16 bits into maps
func describe(family string, prefixes []netip.Prefix, maxBits int) {
	if len(prefixes) == 0 {
		return
	}
	lengths := make([]int, maxBits+1)
	slash8 := make(map[uint32]int)
	slash16 := make(map[uint32]int)
	for _, prefix := range prefixes {
		lengths[prefix.Bits()]++
		top := topBits(prefix.Addr())
		slash8[top>>8]++   // /8 occupancy
		slash16[top]++     // /16 occupancy - this is the root stride
	}

	fmt.Printf("  %s length histogram (top 12 by count):\n", family)
	type row struct{ bits, count int }
	rows := make([]row, 0, maxBits+1)
	for bits, count := range lengths {
		if count != 0 {
			rows = append(rows, row{bits, count})
		}
	}
	// fattest prefix-lengths first - we only print the top 12
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })
	for i, r := range rows {
		if i == 12 {
			break
		}
		fmt.Printf("    /%-3d %8d  %5.2f%%\n", r.bits, r.count, 100*float64(r.count)/float64(len(prefixes)))
	}
	fmt.Printf("  %s occupied /8 blocks: %d of 256\n", family, len(slash8))
	fmt.Printf("  %s occupied /16 blocks: %d of 65536\n", family, len(slash16))
	fmt.Printf("  %s mean prefixes per occupied /16: %.2f\n", family, float64(len(prefixes))/float64(len(slash16)))
}

// topBits returns the leading 16 bits of an address, which is the root stride
// the trie implementations index on - v4 takes bytes 0..1, v6 likewise
func topBits(addr netip.Addr) uint32 {
	if addr.Is4() {
		b := addr.As4()
		return uint32(b[0])<<8 | uint32(b[1])
	}
	b := addr.As16()
	return uint32(b[0])<<8 | uint32(b[1])
}
