#!/usr/bin/env bash

# run-bench.sh drives the full fibbench suite and writes a results file
# we nohup ourselves so you can close the terminal, progress is leaf-weighted because
# some Benchmark* functions explode into hundreds of subtests

set -euo pipefail

RESULTS_FILE=${RESULTS_FILE:-benchmark-results.txt}
BENCHTIME=${BENCHTIME:-5s}
COUNT=${COUNT:-1}
STARTUP_SECONDS_PER_GROUP=${STARTUP_SECONDS_PER_GROUP:-25}
# benches overshoot benchtime by ~12% on average: the min-1-iteration rule blows
# past the target for slow benchmarks, plus setup/calibration.
BENCHTIME_OVERSHOOT_NUM=${BENCHTIME_OVERSHOOT_NUM:-112}
BENCHTIME_OVERSHOOT_DEN=${BENCHTIME_OVERSHOOT_DEN:-100}

# Memory benchmarks (tests containing "memory", case-insensitive) finish faster
# per leaf because they measure heap footprint with fewer warmup/iteration cycles.
# Apply a multiplier factor to scale down their per-leaf time estimate.
MEMORY_BIAS_NUM=${MEMORY_BIAS_NUM:-52}
MEMORY_BIAS_DEN=${MEMORY_BIAS_DEN:-100}
IMPLEMENTATIONS=${IMPLEMENTATIONS:-default}

# default is the cut we actually look at, full dumps everything including the slow ones
if [[ $IMPLEMENTATIONS != default && $IMPLEMENTATIONS != full ]]; then
    printf 'IMPLEMENTATIONS must be default or full, got %s\n' "$IMPLEMENTATIONS" >&2
    exit 2
fi
export PREFIXLOOKUP_IMPLEMENTATIONS=$IMPLEMENTATIONS

# format_duration prints seconds as HH:MM:SS
# we clamp negatives because the ETA can go weird before the first group finishes
format_duration() {
    local seconds=$1
    # don't print negative time, looks daft
    ((seconds < 0)) && seconds=0
    printf '%02d:%02d:%02d' "$((seconds / 3600))" "$(((seconds % 3600) / 60))" "$((seconds % 60))"
}

# duration_milliseconds turns a go benchtime string into ms
# handles ns/us/ms/s/m/h, anything else comes back as "invalid"
duration_milliseconds() {
    local duration=$1
    awk -v value="$duration" '
        BEGIN {
            if (value ~ /^[0-9]+([.][0-9]+)?ns$/) { sub(/ns$/, "", value); print int(value / 1000000 + 0.5); exit }
            if (value ~ /^[0-9]+([.][0-9]+)?us$/) { sub(/us$/, "", value); print int(value / 1000 + 0.5); exit }
            if (value ~ /^[0-9]+([.][0-9]+)?ms$/) { sub(/ms$/, "", value); print int(value + 0.5); exit }
            if (value ~ /^[0-9]+([.][0-9]+)?s$/)  { sub(/s$/,  "", value); print int(value * 1000 + 0.5); exit }
            if (value ~ /^[0-9]+([.][0-9]+)?m$/)  { sub(/m$/,  "", value); print int(value * 60000 + 0.5); exit }
            if (value ~ /^[0-9]+([.][0-9]+)?h$/)  { sub(/h$/,  "", value); print int(value * 3600000 + 0.5); exit }
            print "invalid"
        }
    '
}

# run_all is the actual suite: discover Benchmark* names, weigh them by leaf count, run one group at a time
run_all() {
    local benchtime_ms
    benchtime_ms=$(duration_milliseconds "$BENCHTIME")
    if [[ $benchtime_ms == invalid ]]; then
        printf 'Unsupported BENCHTIME value: %s\n' "$BENCHTIME" >&2
        exit 2
    fi

    # go test -list dumps names plus some junk, keep the Benchmark* lines only
    mapfile -t benchmarks < <(
        go test ./... -list '^Benchmark' |
            while IFS= read -r line; do
                [[ $line == Benchmark* ]] && printf '%s\n' "$line"
            done |
            sort -u
    )

    # the suite prints BENCHMARK_COUNT lines when PREFIXLOOKUP_BENCHMARK_MANIFEST=1
    # that's how we know Traversal has 18 leaves and FIB has a mountain of them
    declare -A leaf_counts=()
    while read -r marker name count; do
        [[ $marker == BENCHMARK_COUNT ]] || continue
        leaf_counts["$name"]=$count
    done < <(PREFIXLOOKUP_BENCHMARK_MANIFEST=1 go test . -run '^$' -count=1 -v | \
        while IFS= read -r line; do
            [[ $line == BENCHMARK_COUNT* ]] && printf '%s\n' "$line"
        done)

    local group_total=${#benchmarks[@]}
    local test_total=0
    local weight_total_ms=0
    # benchtime overshoot factor plus a startup allowance per group (one go test
    # process per group, not per leaf)
    local per_test_ms=$((benchtime_ms * BENCHTIME_OVERSHOOT_NUM / BENCHTIME_OVERSHOOT_DEN))
    local group_overhead_ms=$((STARTUP_SECONDS_PER_GROUP * 1000))
    local benchmark count
    for benchmark in "${benchmarks[@]}"; do
        count=${leaf_counts[$benchmark]:-1}
        local leaf_ms=$per_test_ms
        if [[ ${benchmark,,} == *memory* ]]; then
            leaf_ms=$((leaf_ms * MEMORY_BIAS_NUM / MEMORY_BIAS_DEN))
        fi
        test_total=$((test_total + count * COUNT))
        weight_total_ms=$((weight_total_ms + group_overhead_ms + count * COUNT * leaf_ms))
    done

    local suite_started=$SECONDS
    local groups_done=0
    local tests_done=0
    local weight_done_ms=0

    printf 'Prefix Lookup benchmark suite (leaf-weighted progress)\n'
    printf 'Started: %s\n' "$(date --iso-8601=seconds)"
    printf 'Groups: %d | leaf tests: %d | implementations: %s | benchtime: %s | count: %s | overshoot: %d/%d | mem bias: %d/%d | startup allowance: %ss/group\n' \
        "$group_total" "$test_total" "$IMPLEMENTATIONS" "$BENCHTIME" "$COUNT" \
        "$BENCHTIME_OVERSHOOT_NUM" "$BENCHTIME_OVERSHOOT_DEN" \
        "$MEMORY_BIAS_NUM" "$MEMORY_BIAS_DEN" "$STARTUP_SECONDS_PER_GROUP"
    printf 'Initial minimum estimate: %s\n\n' "$(format_duration "$((weight_total_ms / 1000))")"

    for index in "${!benchmarks[@]}"; do
        benchmark=${benchmarks[$index]}
        count=${leaf_counts[$benchmark]:-1}
        local group_tests=$((count * COUNT))
        local leaf_ms=$per_test_ms
        if [[ ${benchmark,,} == *memory* ]]; then
            leaf_ms=$((leaf_ms * MEMORY_BIAS_NUM / MEMORY_BIAS_DEN))
        fi
        local group_weight_ms=$((group_overhead_ms + group_tests * leaf_ms))
        local elapsed=$((SECONDS - suite_started))
        local remaining_weight_ms=$((weight_total_ms - weight_done_ms))
        local eta_seconds=$((remaining_weight_ms / 1000))
        if ((weight_done_ms > 0 && elapsed > 0)); then
            local observed_eta=$((elapsed * remaining_weight_ms / weight_done_ms))
            # never report less than the remaining leaf-weighted floor
            ((observed_eta > eta_seconds)) && eta_seconds=$observed_eta
        fi

        printf '\n[%d/%d groups] %s\n' "$((index + 1))" "$group_total" "$benchmark"
        printf '  group leaf tests=%d | tests done=%d left=%d total=%d\n' \
            "$group_tests" "$tests_done" "$((test_total - tests_done))" "$test_total"
        printf '  elapsed=%s | weighted ETA=%s\n' \
            "$(format_duration "$elapsed")" "$(format_duration "$eta_seconds")"
        printf '%s\n' '--------------------------------------------------------------------------------'

        # one Benchmark* name at a time so a crash doesn't nuke the whole log
        go test ./... -run '^$' -bench "^${benchmark}$" -benchmem \
            -benchtime="$BENCHTIME" -count="$COUNT"

        groups_done=$((groups_done + 1))
        tests_done=$((tests_done + group_tests))
        weight_done_ms=$((weight_done_ms + group_weight_ms))
        elapsed=$((SECONDS - suite_started))
        remaining_weight_ms=$((weight_total_ms - weight_done_ms))
        eta_seconds=0
        if ((weight_done_ms > 0 && remaining_weight_ms > 0)); then
            eta_seconds=$((remaining_weight_ms / 1000))
            local observed_eta=$((elapsed * remaining_weight_ms / weight_done_ms))
            ((observed_eta > eta_seconds)) && eta_seconds=$observed_eta
        fi
        printf '[complete] groups=%d/%d | tests=%d/%d | left=%d | elapsed=%s | ETA=%s\n' \
            "$groups_done" "$group_total" "$tests_done" "$test_total" \
            "$((test_total - tests_done))" "$(format_duration "$elapsed")" \
            "$(format_duration "$eta_seconds")"
    done

    printf '\nCompleted all %d groups and %d leaf tests in %s at %s\n' \
        "$group_total" "$test_total" "$(format_duration "$((SECONDS - suite_started))")" \
        "$(date --iso-8601=seconds)"
}

# --worker is us re-executing under nohup
if [[ ${1:-} == --worker ]]; then
    run_all
    exit 0
fi

# rotate the previous results so we don't clobber a run we still wanted
if [[ -e $RESULTS_FILE ]]; then
    mv "$RESULTS_FILE" "${RESULTS_FILE}.$(date +%Y%m%d-%H%M%S)"
fi

script_path=$(realpath "$0")
# detach so the suite keeps going if the ssh session dies
nohup env RESULTS_FILE="$RESULTS_FILE" BENCHTIME="$BENCHTIME" COUNT="$COUNT" \
    STARTUP_SECONDS_PER_GROUP="$STARTUP_SECONDS_PER_GROUP" \
    BENCHTIME_OVERSHOOT_NUM="$BENCHTIME_OVERSHOOT_NUM" BENCHTIME_OVERSHOOT_DEN="$BENCHTIME_OVERSHOOT_DEN" \
    MEMORY_BIAS_NUM="$MEMORY_BIAS_NUM" MEMORY_BIAS_DEN="$MEMORY_BIAS_DEN" \
    IMPLEMENTATIONS="$IMPLEMENTATIONS" \
    bash "$script_path" --worker >"$RESULTS_FILE" 2>&1 &
pid=$!

printf 'Benchmark PID: %d\n' "$pid"
printf 'Results: %s\n' "$RESULTS_FILE"
printf 'Monitor with: tail -f %q\n' "$RESULTS_FILE"
