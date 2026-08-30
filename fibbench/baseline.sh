#!/usr/bin/env bash
# baseline.sh is the older shorter set we used when we were still arguing about flatset/flatlpm/flatwalk
# kept around because the acceptance numbers in baseline.txt were taken with this exact list

set -u
cd "$(dirname "$0")"

OUT="${1:-baseline.txt}"
BT="${BENCHTIME:-2s}"
: >"$OUT"

# run tees one bench regex into the log
run() {
  echo "### $1" | tee -a "$OUT"
  go test -run '^$' -bench "$1" -benchtime "$BT" -count=1 -timeout 4h 2>&1 | tee -a "$OUT"
  echo "SECTION_DONE $1"
}

run 'BenchmarkMemory/100000/'
run 'BenchmarkScaleSweep/100000/'
run 'BenchmarkFamilyMixes/(v4-only|v6-only)/'
run 'BenchmarkQueryDistributions/uniform/'
run 'BenchmarkTraversal/'
run 'BenchmarkMixedReadWrite/10000000-to-1/'
run 'BenchmarkComparativeParallel/1000000/x32/'
echo "ALL_SECTIONS_DONE"
