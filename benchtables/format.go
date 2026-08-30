package benchtables

import (
	"math"
	"strconv"
)

// FormatFloat mirrors the decimal-count rules of go test's own metric
// printing, so values taken straight from parsed output keep their printed
// form ("5.398", "65.80", "16.00", "2126").
func FormatFloat(x float64) string {
	y := math.Abs(x)
	dec := 7
	switch {
	case y == 0 || y >= 999.95:
		dec = 0
	case y >= 99.995:
		dec = 1
	case y >= 9.9995:
		dec = 2
	case y >= 0.99995:
		dec = 3
	case y >= 0.099995:
		dec = 4
	case y >= 0.0099995:
		dec = 5
	case y >= 0.00099995:
		dec = 6
	}
	return strconv.FormatFloat(x, 'f', dec, 64)
}

// FormatFixed renders a unit-converted value with two decimals below 100,
// one below 1000 and none after that.
func FormatFixed(x float64) string {
	dec := 2
	switch {
	case x >= 1000:
		dec = 0
	case x >= 100:
		dec = 1
	}
	return strconv.FormatFloat(x, 'f', dec, 64)
}

// FormatTime renders a nanosecond value with an auto-scaled unit (ns, μs,
// ms, s). Values below a millisecond keep go test's printed precision;
// larger values use FormatFixed.
func FormatTime(ns float64) string {
	switch {
	case ns < 1e3:
		return FormatFloat(ns) + " ns"
	case ns < 1e6:
		return FormatFloat(ns/1e3) + " μs"
	case ns < 1e9:
		return FormatFixed(ns/1e6) + " ms"
	default:
		return FormatFixed(ns/1e9) + " s"
	}
}

// FormatRate renders a per-second rate in millions with one decimal.
func FormatRate(m float64) string {
	return strconv.FormatFloat(m, 'f', 1, 64) + " M/s"
}
