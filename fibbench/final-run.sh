#!/usr/bin/env bash
# final-run.sh is the shorter acceptance set we actually stare at before calling a change done
# nominated benches plus the real-table lot, default implementations trimmed to the ones we care about

set -u
cd "$(dirname "$0")"
OUT="${1:-final-results.txt}"
BT="${BENCHTIME:-1s}"
CNT="${COUNT:-3}"
IMPLS="flatset,dirset,flatlpm,dirlpm,flatwalk,orderwalk,bart-table,bart-fast,bart-lite,bart-lite-direct,bart-table-direct,compiled-fib,fiborderwalk,split-rib-fib,groupartset,range-match,thinrangeset,netipds"
# wipe the out file, we append as we go
: >"$OUT"

# run is one go test -bench invocation, teed into the log
# SECTION_DONE is so you can grep progress without reading the whole file
run() {
  echo "### $1" | tee -a "$OUT"
  PREFIXLOOKUP_IMPLEMENTATIONS="$IMPLS" \
    go test -run '^$' -bench "$1" -benchtime "$BT" -count="$CNT" -timeout 6h 2>&1 | tee -a "$OUT"
  echo "SECTION_DONE $1"
}

run 'BenchmarkMemory/100000/'
run 'BenchmarkScaleSweep/100000/'
run 'BenchmarkFamilyMixes/(v4-only|v6-only)/'
run 'BenchmarkQueryDistributions/uniform/'
run 'BenchmarkTraversal/'
run 'BenchmarkMixedReadWrite/10000000-to-1/'
run 'BenchmarkComparativeParallel/1000000/x32/'
run 'BenchmarkRealTable$'
run 'BenchmarkRealTableNoDefault'
run 'BenchmarkRealTableMemory'
echo "ALL_SECTIONS_DONE"
