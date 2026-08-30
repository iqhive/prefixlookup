// Package benchtables parses go test -bench output and renders the results
// as markdown comparison tables.
//
// Result lines are recognised by their Benchmark... name prefix, with the
// trailing -GOMAXPROCS suffix removed, so output from partial, reordered or
// repeated (-count) runs parses the same way as a complete single run:
// banners, PASS/ok lines and non-numeric lines are ignored, and when the
// same sub-benchmark appears more than once the last result wins.
package benchtables

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Results maps each sub-benchmark path (Benchmark prefix and -GOMAXPROCS
// suffix removed, e.g. "ComparativeParallel/1000000/x32/dirset") to its
// reported metrics.
type Results map[string]map[string]float64

var gomaxprocsSuffix = regexp.MustCompile(`-\d+$`)

// Parse reads go test -bench output and returns the result lines it
// contains, keyed by sub-benchmark path.
func Parse(r io.Reader) Results {
	results := Results{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		name := strings.TrimPrefix(fields[0], "Benchmark")
		name = gomaxprocsSuffix.ReplaceAllString(name, "")
		if _, err := strconv.ParseInt(fields[1], 10, 64); err != nil {
			continue // e.g. "signal: terminated"
		}
		metrics := make(map[string]float64, 4)
		rest := fields[2:]
		for i := 0; i+1 < len(rest); i += 2 {
			if v, err := strconv.ParseFloat(rest[i], 64); err == nil {
				metrics[rest[i+1]] = v
			}
		}
		results[name] = metrics
	}
	return results
}

// Metric returns the value of one reported metric for a sub-benchmark.
func (r Results) Metric(metric string, path ...string) (float64, bool) {
	metrics, ok := r[strings.Join(path, "/")]
	if !ok {
		return 0, false
	}
	v, ok := metrics[metric]
	return v, ok
}

// NS returns the ns/op value of a sub-benchmark.
func (r Results) NS(path ...string) (float64, bool) {
	return r.Metric("ns/op", path...)
}

// AvgNS returns the average of the ns/op values that are present; ok is
// false only when none of them are.
func (r Results) AvgNS(paths ...[]string) (float64, bool) {
	var sum float64
	var n int
	for _, path := range paths {
		if v, ok := r.Metric("ns/op", path...); ok {
			sum += v
			n++
		}
	}
	if n == 0 {
		return 0, false
	}
	return sum / float64(n), true
}
