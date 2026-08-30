// Command benchtables converts a fibbench benchmark-results file into the
// performance tables used by the top-level README.md.
//
// Parsing and markdown rendering come from the benchtables package; this
// command holds the grouping and aggregation logic that maps each README
// column onto fibbench's sub-benchmarks:
//
//   - Small scale reads  BenchmarkComparativeParallel/1000/x1 (ns/op)
//   - Large scale reads  BenchmarkComparativeParallel/1000000/x32 (Mlookups/s)
//   - Internet routing   average of BenchmarkRealTable/uniform and
//     BenchmarkRealTable/zipf (ns/op)
//   - Read/Write         BenchmarkMixedReadWrite/100000-to-1 (read-ns metric)
//   - Batch writes       average of BenchmarkUpdateBatches/Batch16 and
//     BenchmarkUpdateBatches/Batch256 (ns/op)
//   - Load writes        average of BenchmarkConvergenceStorm/<impl>/Atomic
//     and BenchmarkConvergenceStorm/<impl>/Individual
//   - Traversal          average of BenchmarkTraversal/Supernets/<impl> and
//     BenchmarkTraversal/Subnets/<impl>
//   - Memory             boolean rows: BenchmarkMembershipMemory/Min
//     (retained-B) plus BenchmarkMembershipMemory/Scale/1000000
//     (retained-B/prefix); value rows:
//     BenchmarkMemory/100000 plus BenchmarkRealTableMemory
//
// The bart-lite-direct and bart-table-direct adapters share the memory of
// bart-lite and bart-table respectively, so their Memory cells read those
// implementations' memory benchmarks.
//
// Best values are bolded: the top three per read column in the Boolean
// Membership table (the rest use the single best), the single best per column
// elsewhere, and in the No Default Route table anything within 5% of the best.
// In the concurrent-readers table the fastest boolean set and the fastest
// value LPM are bolded.
//
// Rows are then ordered by how many cells they carry in bold (most first),
// with ties broken left to right: values within withinThreshold of each
// other count as tied and the next column decides. The concurrent-readers
// table keeps its fixed two-column layout instead.
//
// Usage:
//
//	benchtables fibbench/benchmark-results-5s.txt
//	benchtables -out tables.md fibbench/benchmark-results.txt
//	cat results.txt | benchtables -
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/iqhive/prefixlookup/benchtables"
)

// ---------------------------------------------------------------------------
// column cells
// ---------------------------------------------------------------------------

func nsCell(r benchtables.Results, path ...string) benchtables.Cell {
	v, ok := r.NS(path...)
	return benchtables.TimeCell(v, ok)
}

func rateCell(r benchtables.Results, path ...string) benchtables.Cell {
	v, ok := r.Metric("Mlookups/s", path...)
	return benchtables.RateCell(v, ok)
}

func metricTimeCell(r benchtables.Results, metric string, path ...string) benchtables.Cell {
	v, ok := r.Metric(metric, path...)
	return benchtables.TimeCell(v, ok)
}

func retainedCell(r benchtables.Results, path ...string) benchtables.Cell {
	v, ok := r.Metric("retained-B/prefix", path...)
	return benchtables.FloatCell(v, ok)
}

// internetCell averages the uniform and Zipf real-table lookups.
func internetCell(r benchtables.Results, impl string) benchtables.Cell {
	v, ok := r.AvgNS(
		[]string{"RealTable", "uniform", impl},
		[]string{"RealTable", "zipf", impl},
	)
	return benchtables.TimeCell(v, ok)
}

// batchCell averages the 16- and 256-route update batches.
func batchCell(r benchtables.Results, impl string) benchtables.Cell {
	v, ok := r.AvgNS(
		[]string{"UpdateBatches", "Batch16", impl},
		[]string{"UpdateBatches", "Batch256", impl},
	)
	return benchtables.TimeCell(v, ok)
}

// loadCell averages the atomic and per-route convergence storms.
func loadCell(r benchtables.Results, impl string) benchtables.Cell {
	v, ok := r.AvgNS(
		[]string{"ConvergenceStorm", impl, "Atomic"},
		[]string{"ConvergenceStorm", impl, "Individual"},
	)
	return benchtables.TimeCell(v, ok)
}

// traversalCell averages the supernet and subnet walks.
func traversalCell(r benchtables.Results, impl string) benchtables.Cell {
	v, ok := r.AvgNS(
		[]string{"Traversal", "Supernets", impl},
		[]string{"Traversal", "Subnets", impl},
	)
	return benchtables.TimeCell(v, ok)
}

const (
	memBoolean = iota // MembershipMemory/Min + Scale/1000000
	memValue          // Memory/100000 + RealTableMemory
)

// implRow describes one table row: the implementation key in the benchmark
// output, its display name, which memory benchmark feeds the Memory cell,
// and the implementation key for those memory benchmarks (the bart-*-direct
// adapters alias bart-* there).
type implRow struct {
	impl    string
	display string
	mem     int
	memKey  string // empty means same as impl
}

func (r implRow) memoryKey() string {
	if r.memKey == "" {
		return r.impl
	}
	return r.memKey
}

// memCell pairs two retained-memory measurements: the collapsed minimum and
// the 1M-fixture bytes-per-prefix for boolean rows, the 100k fixture and the
// real BGP dump for value rows. Both halves must be present.
func memCell(r benchtables.Results, spec implRow) benchtables.Cell {
	key := spec.memoryKey()
	var a, b float64
	var ok bool
	if spec.mem == memBoolean {
		a, ok = r.Metric("retained-B", "MembershipMemory", "Min", key)
		if ok {
			b, ok = r.Metric("retained-B/prefix", "MembershipMemory", "Scale", "1000000", key)
		}
	} else {
		a, ok = r.Metric("retained-B/prefix", "Memory", "100000", key)
		if ok {
			b, ok = r.Metric("retained-B/prefix", "RealTableMemory", key)
		}
	}
	if !ok {
		return benchtables.Cell{Text: benchtables.Missing}
	}
	return benchtables.Cell{
		Text:  benchtables.FormatFloat(a) + " + " + benchtables.FormatFloat(b) + " B/pfx",
		Value: a + b,
		OK:    true,
	}
}

// stdCells builds the seven data columns shared by the Boolean Membership,
// Value Lookup and Hierarchy Traversal tables.
func stdCells(r benchtables.Results, spec implRow) []benchtables.Cell {
	return []benchtables.Cell{
		nsCell(r, "ComparativeParallel", "1000", "x1", spec.impl),
		rateCell(r, "ComparativeParallel", "1000000", "x32", spec.impl),
		internetCell(r, spec.impl),
		metricTimeCell(r, "read-ns", "MixedReadWrite", "100000-to-1", spec.impl),
		batchCell(r, spec.impl),
		loadCell(r, spec.impl),
		memCell(r, spec),
	}
}

// ---------------------------------------------------------------------------
// table specs
// ---------------------------------------------------------------------------

var membershipSpecs = []implRow{
	{"dirset", "`dirset`", memBoolean, ""},
	{"dirlpm", "`dirlpm` (value)", memValue, ""},
	{"parityset", "`parityset`", memBoolean, ""},
	{"thinrangeset", "`thinrangeset`", memBoolean, ""},
	{"flatset", "`flatset`", memBoolean, ""},
	{"flatwalk", "`flatwalk` (tree)", memValue, ""},
	{"groupartset", "`groupartset`", memBoolean, ""},
	{"artset", "`artset`", memBoolean, ""},
	{"bart-lite-direct", "`bart-lite-direct`", memBoolean, "bart-lite"},
	{"range-match", "`range-match`", memBoolean, ""},
	{"soarangeset", "`soarangeset`", memBoolean, ""},
	{"bart-lite", "`bart-lite`", memBoolean, ""},
	{"netipds", "`netipds`", memBoolean, ""},
	{"cidranger", "`cidranger`", memBoolean, ""},
}

var lpmSpecs = []implRow{
	{"dirlpm", "`dirlpm`", memValue, ""},
	{"compiled-fib", "`compiled-fib`", memValue, ""},
	{"slotlpm", "`slotlpm`", memValue, ""},
	{"flatlpm", "`flatlpm`", memValue, ""},
	{"flatwalk", "`flatwalk` (tree)", memValue, ""},
	{"steplpm", "`steplpm`", memValue, ""},
	{"bart-fast", "`bart-fast`", memValue, ""},
	{"bart-table-direct", "`bart-table-direct`", memValue, "bart-table"},
	{"arenaartlpm", "`arenaartlpm`", memValue, ""},
	{"artlpm", "`artlpm`", memValue, ""},
	{"versioned-hybrid", "`versioned-hybrid`", memValue, ""},
	{"versioned-fib", "`versioned-fib`", memValue, ""},
	{"versioned-rib", "`versioned-rib`", memValue, ""},
	{"tailscale-art", "`tailscale-art`", memValue, ""},
	{"kentik-patricia", "`kentik-patricia`", memValue, ""},
	{"go-iptrie", "`go-iptrie`", memValue, ""},
}

var hierarchySpecs = []implRow{
	{"flatwalk", "`flatwalk`", memValue, ""},
	{"aosart", "`aosart`", memValue, ""},
	{"split-rib-fib", "`split-rib-fib`", memValue, ""},
	{"soaart", "`soaart`", memValue, ""},
	{"preorder2", "`preorder2`", memValue, ""},
	{"fiborderwalk", "`fiborderwalk`", memValue, ""},
	{"bart-table", "`bart-table`", memValue, ""},
	{"orderwalk", "`orderwalk`", memValue, ""},
	{"artwalk", "`artwalk`", memValue, ""},
}

var realTableSpecs = []implRow{
	{"dirlpm", "`dirlpm`", memValue, ""},
	{"compiled-fib", "`compiled-fib`", memValue, ""},
	{"flatlpm", "`flatlpm`", memValue, ""},
	{"flatwalk", "`flatwalk`", memValue, ""},
	{"slotlpm", "`slotlpm`", memValue, ""},
	{"steplpm", "`steplpm`", memValue, ""},
	{"arenaartlpm", "`arenaartlpm`", memValue, ""},
	{"orderwalk", "`orderwalk`", memValue, ""},
	{"aosart", "`aosart`", memValue, ""},
	{"soaart", "`soaart`", memValue, ""},
	{"artlpm", "`artlpm`", memValue, ""},
	{"bart-table", "BART Table", memValue, ""},
	{"bart-fast", "BART Fast", memValue, ""},
	{"tailscale-art", "Tailscale ART", memValue, ""},
}

var noDefaultSpecs = []implRow{
	{"dirset", "`dirset`", memBoolean, ""},
	{"flatset", "`flatset`", memBoolean, ""},
	{"groupartset", "`groupartset`", memBoolean, ""},
	{"parityset", "`parityset`", memBoolean, ""},
	{"artset", "`artset`", memBoolean, ""},
	{"bart-lite-direct", "BART Lite (direct)", memBoolean, "bart-lite"},
	{"thinrangeset", "`thinrangeset`", memBoolean, ""},
	{"netipds", "`netipds`", memBoolean, ""},
	{"cidranger", "`cidranger`", memBoolean, ""},
}

// parallelSide is one entry of the two-column concurrent-readers table.
// isSet splits the rows into boolean sets and value LPMs so the fastest of
// each class can be highlighted.
type parallelSide struct {
	impl    string
	display string
	isSet   bool
}

var parallelLeft = []parallelSide{
	{"dirset", "`dirset`", true},
	{"flatset", "`flatset`", true},
	{"parityset", "`parityset`", true},
	{"groupartset", "`groupartset`", true},
	{"dirlpm", "`dirlpm`", false},
	{"compiled-fib", "`compiled-fib`", false},
}

var parallelRight = []parallelSide{
	{"flatlpm", "`flatlpm`", false},
	{"orderwalk", "`orderwalk`", false},
	{"flatwalk", "`flatwalk`", false},
	{"slotlpm", "`slotlpm`", false},
	{"steplpm", "`steplpm`", false},
	{"soaart", "`soaart`", false},
}

var stdHeader = []string{
	"Implementation", "Small scale reads", "Large scale reads",
	"Internet routing", "Read/Write", "Batch writes", "Load writes", "Memory",
}

var hierarchyHeader = append([]string{"Implementation", "Traversal"}, stdHeader[1:]...)

var realTableHeader = []string{
	"Implementation", "Zipf", "Uniform", "IPv4", "IPv6", "Retained B/prefix",
}

var noDefaultHeader = []string{"Implementation", "Uniform", "IPv4", "IPv6"}

var parallelHeader = []string{
	"Implementation", "Mlookups/s", "Implementation", "Mlookups/s",
}

// ---------------------------------------------------------------------------
// table builders
// ---------------------------------------------------------------------------

// withinThreshold is the defined ranking tie tolerance: values within 8% of
// each other count as tied, both when bolding statistical ties and when
// breaking row-order ties column by column.
const withinThreshold = 1.08

func buildTable(r benchtables.Results, header []string, specs []implRow,
	cellsFor func(implRow) []benchtables.Cell) *benchtables.Table {
	t := &benchtables.Table{Header: header}
	for _, spec := range specs {
		cells := cellsFor(spec)
		if benchtables.Row(cells).HasData() {
			t.AddRow(cells...)
		}
	}
	return t
}

// membershipTable bolds the top three per read column; the write and memory
// columns highlight only the single best.
func membershipTable(r benchtables.Results) *benchtables.Table {
	t := buildTable(r, stdHeader, membershipSpecs, func(spec implRow) []benchtables.Cell {
		return append([]benchtables.Cell{benchtables.NewTextCell(spec.display)}, stdCells(r, spec)...)
	})
	for col := 1; col <= 4; col++ {
		t.BoldTopN(col, 3)
	}
	for col := 5; col <= 7; col++ {
		t.BoldTopN(col, 1)
	}
	t.SortByRank(withinThreshold)
	return t
}

func lpmTable(r benchtables.Results) *benchtables.Table {
	t := buildTable(r, stdHeader, lpmSpecs, func(spec implRow) []benchtables.Cell {
		return append([]benchtables.Cell{benchtables.NewTextCell(spec.display)}, stdCells(r, spec)...)
	})
	for col := 1; col <= 7; col++ {
		t.BoldTopN(col, 1)
	}
	t.SortByRank(withinThreshold)
	return t
}

func hierarchyTable(r benchtables.Results) *benchtables.Table {
	t := buildTable(r, hierarchyHeader, hierarchySpecs, func(spec implRow) []benchtables.Cell {
		return append(
			[]benchtables.Cell{benchtables.NewTextCell(spec.display), traversalCell(r, spec.impl)},
			stdCells(r, spec)...,
		)
	})
	for col := 1; col <= 8; col++ {
		t.BoldTopN(col, 1)
	}
	t.SortByRank(withinThreshold)
	return t
}

func realTable(r benchtables.Results) *benchtables.Table {
	t := buildTable(r, realTableHeader, realTableSpecs, func(spec implRow) []benchtables.Cell {
		return []benchtables.Cell{
			benchtables.NewTextCell(spec.display),
			nsCell(r, "RealTable", "zipf", spec.impl),
			nsCell(r, "RealTable", "uniform", spec.impl),
			nsCell(r, "RealTable", "v4-only", spec.impl),
			nsCell(r, "RealTable", "v6-only", spec.impl),
			retainedCell(r, "RealTableMemory", spec.memoryKey()),
		}
	})
	for col := 1; col <= 5; col++ {
		t.BoldTopN(col, 1)
	}
	t.SortByRank(withinThreshold)
	return t
}

// noDefaultTable bolds anything within the defined threshold of each
// column's best (so statistical ties share the highlight) and then
// rank-orders the rows.
func noDefaultTable(r benchtables.Results) *benchtables.Table {
	t := buildTable(r, noDefaultHeader, noDefaultSpecs, func(spec implRow) []benchtables.Cell {
		return []benchtables.Cell{
			benchtables.NewTextCell(spec.display),
			nsCell(r, "RealTableNoDefault", "uniform", spec.impl),
			nsCell(r, "RealTableNoDefault", "v4-only", spec.impl),
			nsCell(r, "RealTableNoDefault", "v6-only", spec.impl),
		}
	})
	for col := 1; col <= 3; col++ {
		t.BoldWithinTolerance(col, withinThreshold)
	}
	t.SortByRank(withinThreshold)
	return t
}

// parallelTable lays the selected implementations out in two halves, each
// sorted by throughput, with the fastest boolean set and the fastest value
// LPM across both halves bolded.
func parallelTable(r benchtables.Results) *benchtables.Table {
	type entry struct {
		display string
		value   float64
		isSet   bool
		bold    bool
	}
	collect := func(specs []parallelSide) []entry {
		var out []entry
		for _, spec := range specs {
			if v, ok := r.Metric("Mlookups/s", "RealTableParallel", spec.impl); ok {
				out = append(out, entry{display: spec.display, value: v, isSet: spec.isSet})
			}
		}
		sort.SliceStable(out, func(a, b int) bool { return out[a].value > out[b].value })
		return out
	}
	left, right := collect(parallelLeft), collect(parallelRight)
	var bestSet, bestLPM *entry
	for _, side := range [][]entry{left, right} {
		for i := range side {
			e := &side[i]
			if e.isSet && (bestSet == nil || e.value > bestSet.value) {
				bestSet = e
			}
			if !e.isSet && (bestLPM == nil || e.value > bestLPM.value) {
				bestLPM = e
			}
		}
	}
	if bestSet != nil {
		bestSet.bold = true
	}
	if bestLPM != nil {
		bestLPM.bold = true
	}
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	if n == 0 {
		return &benchtables.Table{Header: parallelHeader}
	}
	t := &benchtables.Table{Header: parallelHeader}
	for i := 0; i < n; i++ {
		cells := make([]benchtables.Cell, 4)
		for j, side := range [][]entry{left, right} {
			if i < len(side) {
				e := side[i]
				text := strconv.FormatFloat(e.value, 'f', 1, 64)
				if e.bold {
					text = "**" + text + "**"
				}
				cells[j*2] = benchtables.NewTextCell(e.display)
				cells[j*2+1] = benchtables.NewTextCell(text)
			} else {
				cells[j*2] = benchtables.NewTextCell(" ")
				cells[j*2+1] = benchtables.NewTextCell(" ")
			}
		}
		t.AddRow(cells...)
	}
	return t
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

func writeSection(w io.Writer, heading, intro string, t *benchtables.Table, footnotes ...string) {
	if len(t.Rows) == 0 {
		return
	}
	fmt.Fprintln(w, heading)
	fmt.Fprintln(w)
	if intro != "" {
		fmt.Fprintln(w, intro)
		fmt.Fprintln(w)
	}
	t.Render(w)
	fmt.Fprintln(w)
	for _, note := range footnotes {
		fmt.Fprintln(w, note)
		fmt.Fprintln(w)
	}
}

func writeAll(w io.Writer, r benchtables.Results) {
	writeSection(w, "### Boolean Membership", "", membershipTable(r))
	writeSection(w, "### Value Lookup (LPM)", "", lpmTable(r))
	writeSection(w, "### Hierarchy Traversal", "", hierarchyTable(r),
		"*Traversal is the average of `BenchmarkTraversal/Supernets` and `BenchmarkTraversal/Subnets`.*")
	writeSection(w,
		"### Real Table Performance (1,401,481 prefixes: 1.14M IPv4, 261k IPv6)",
		"", realTable(r))
	writeSection(w, "### Real Table Boolean Lookups (No Default Route)",
		"With `0.0.0.0/0` and `::/0` removed, lookups can no longer short-circuit on full-space coverage:",
		noDefaultTable(r))
	writeSection(w, "### 32 Concurrent Readers (Full Table)",
		"From `BenchmarkRealTableParallel`, across a 65,536-address working set with no cache locality:",
		parallelTable(r))
}

// requiredBenchmarks are the sub-benchmark groups the tables draw from;
// missing ones mean missing columns, so they are reported on stderr.
var requiredBenchmarks = []string{
	"ComparativeParallel", "ConvergenceStorm", "MembershipMemory", "Memory",
	"MixedReadWrite", "RealTable", "RealTableMemory", "RealTableNoDefault",
	"RealTableParallel", "Traversal", "UpdateBatches",
}

func warnMissing(r benchtables.Results, stderr io.Writer) {
	present := map[string]bool{}
	for path := range r {
		present[strings.SplitN(path, "/", 2)[0]] = true
	}
	var absent []string
	for _, name := range requiredBenchmarks {
		if !present[name] {
			absent = append(absent, "Benchmark"+name)
		}
	}
	if len(absent) > 0 {
		fmt.Fprintf(stderr, "benchtables: no results for %s; the cells they feed show %s\n",
			strings.Join(absent, ", "), benchtables.Missing)
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func run(stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	flags := flag.NewFlagSet("benchtables", flag.ExitOnError)
	outPath := flags.String("out", "", "write the tables to this file instead of stdout")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: benchtables [-out file] results.txt")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return fmt.Errorf("exactly one results file is required (use - for stdin)")
	}

	var input io.Reader
	if path := flags.Arg(0); path == "-" {
		input = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}

	results := benchtables.Parse(input)
	if len(results) == 0 {
		return fmt.Errorf("no benchmark results found in %s", flags.Arg(0))
	}

	var output io.Writer = stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		output = f
	}

	warnMissing(results, stderr)
	writeAll(output, results)
	return nil
}

func main() {
	if err := run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "benchtables:", err)
		os.Exit(1)
	}
}
