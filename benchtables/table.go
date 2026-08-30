package benchtables

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// Missing is the placeholder shown for cells with no data.
const Missing = "-"

// Cell is one table cell: display text plus the ranking value used for
// sorting and bolding. Higher is true when a bigger value ranks better.
type Cell struct {
	Text   string
	Value  float64
	OK     bool
	Higher bool
}

// Row is one table row.
type Row []Cell

// NewTextCell returns a non-ranking cell, e.g. an implementation name.
func NewTextCell(text string) Cell { return Cell{Text: text} }

// TimeCell renders a nanosecond value with FormatTime.
func TimeCell(ns float64, ok bool) Cell {
	if !ok {
		return Cell{Text: Missing}
	}
	return Cell{Text: FormatTime(ns), Value: ns, OK: true}
}

// RateCell renders a rate with FormatRate; bigger ranks better.
func RateCell(v float64, ok bool) Cell {
	if !ok {
		return Cell{Text: Missing}
	}
	return Cell{Text: FormatRate(v), Value: v, OK: true, Higher: true}
}

// FloatCell renders a plain value with FormatFloat.
func FloatCell(v float64, ok bool) Cell {
	if !ok {
		return Cell{Text: Missing}
	}
	return Cell{Text: FormatFloat(v), Value: v, OK: true}
}

// HasData reports whether any cell carries a value.
func (r Row) HasData() bool {
	for _, c := range r {
		if c.OK {
			return true
		}
	}
	return false
}

// Table is a markdown table: a header row plus data rows.
type Table struct {
	Header []string
	Rows   []Row
}

// AddRow appends a row.
func (t *Table) AddRow(cells ...Cell) {
	t.Rows = append(t.Rows, Row(cells))
}

// BoldTopN bolds the n best values in a column; cells without data never
// rank.
func (t *Table) BoldTopN(col, n int) {
	ranked := make([]int, 0, len(t.Rows))
	for i := range t.Rows {
		if t.Rows[i][col].OK {
			ranked = append(ranked, i)
		}
	}
	sort.SliceStable(ranked, func(x, y int) bool {
		a, b := t.Rows[ranked[x]][col], t.Rows[ranked[y]][col]
		if a.Higher {
			return a.Value > b.Value
		}
		return a.Value < b.Value
	})
	if len(ranked) > n {
		ranked = ranked[:n]
	}
	for _, i := range ranked {
		c := &t.Rows[i][col]
		c.Text = "**" + c.Text + "**"
	}
}

// BoldWithinTolerance bolds every value within factor of the column best
// (e.g. 1.05 for 5%), so statistical ties share the highlight.
func (t *Table) BoldWithinTolerance(col int, factor float64) {
	var best float64
	var higher bool
	found := false
	for i := range t.Rows {
		c := t.Rows[i][col]
		if !c.OK {
			continue
		}
		better := !found || (c.Higher && c.Value > best) || (!c.Higher && c.Value < best)
		if better {
			best, higher, found = c.Value, c.Higher, true
		}
	}
	if !found {
		return
	}
	for i := range t.Rows {
		c := &t.Rows[i][col]
		if !c.OK || c.Higher != higher {
			continue
		}
		good := c.Value <= best*factor
		if c.Higher {
			good = c.Value >= best/factor
		}
		if good {
			c.Text = "**" + c.Text + "**"
		}
	}
}

// SortByRank orders rows by how many cells they carry in bold (most first),
// then breaks ties down the columns from left to right: values within tol of
// each other count as tied and the next column decides, with better values
// first and cells carrying no data ranking last. Name cells hold no data, so
// they are skipped automatically.
func (t *Table) SortByRank(tol float64) {
	sort.SliceStable(t.Rows, func(a, b int) bool {
		x, y := t.Rows[a], t.Rows[b]
		if nx, ny := boldCount(x), boldCount(y); nx != ny {
			return nx > ny
		}
		return rankBefore(x, y, tol)
	})
}

// boldCount counts the cells a row has in bold.
func boldCount(r Row) int {
	n := 0
	for _, c := range r {
		if len(c.Text) > 4 && strings.HasPrefix(c.Text, "**") && strings.HasSuffix(c.Text, "**") {
			n++
		}
	}
	return n
}

// rankBefore walks two rows column by column, treating values within tol of
// each other as tied and letting the next column decide. It reports whether x
// ranks before y.
func rankBefore(x, y Row, tol float64) bool {
	for i := range x {
		a, b := x[i], y[i]
		switch {
		case a.OK && b.OK:
			hi, lo := a.Value, b.Value
			if hi < lo {
				hi, lo = lo, hi
			}
			if hi <= lo*tol {
				continue
			}
			if a.Higher {
				return a.Value > b.Value
			}
			return a.Value < b.Value
		case a.OK:
			return true
		case b.OK:
			return false
		}
	}
	return false
}

// Render writes the table as aligned markdown: padded columns with a dash
// row sized to match the header.
func (t *Table) Render(w io.Writer) {
	widths := make([]int, len(t.Header))
	for i, h := range t.Header {
		widths[i] = utf8.RuneCountInString(h)
	}
	texts := make([][]string, len(t.Rows))
	for i, r := range t.Rows {
		texts[i] = make([]string, len(t.Header))
		for j, c := range r {
			texts[i][j] = c.Text
			if n := utf8.RuneCountInString(c.Text); n > widths[j] {
				widths[j] = n
			}
		}
	}
	writeLine := func(cells []string) {
		var b strings.Builder
		b.WriteString("|")
		for j, text := range cells {
			pad := widths[j] - utf8.RuneCountInString(text)
			b.WriteString(" ")
			b.WriteString(text)
			if pad > 0 {
				b.WriteString(strings.Repeat(" ", pad))
			}
			b.WriteString(" |")
		}
		fmt.Fprintln(w, b.String())
	}
	writeLine(t.Header)
	dashes := make([]string, len(t.Header))
	for i := range dashes {
		dashes[i] = strings.Repeat("-", widths[i])
	}
	writeLine(dashes)
	for _, text := range texts {
		writeLine(text)
	}
}
