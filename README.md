# Prefix Lookup

Go packages for IPv4 and IPv6 prefix lookups. The packages grew out of several internal systems built over a number of years and are now available as open source.

There is more than one package because the same trie shape did not suit every workload. Some systems needed very fast lookups, others needed to keep memory use low across hundreds of VRFs. Some dealt with frequent route changes in the control plane, and others needed to walk parent and child relationships as well as perform forwarding lookups.

In practice, the structure that worked well for one job often created problems somewhere else. The result is a collection of packages, each aimed at a different set of trade-offs.

The benchmarks (some of which took just as long as some implementations to get right) focus on problems that showed up in real systems: memory pressure, lookup slowdowns at scale, frequent route flaps and writer contention affecting the data plane etc.

> [!NOTE]
> **Source release only (no Git history).** The internal repository history contained private tooling and references, so it has not been included. Any dates mentioned in the code are approximate.
> **x86 focus** These have been written for our high-performance application that are almost exclusively run on x86-64 Linux servers and as such the focus for us has been optimising for this platform exclusively - i.e. these are not optimised for other architectures, but we're happy to accept PRs for other architectures if they're not going to degrade x86-64 performance.
---

## Quick Reference / TL;DR

* **Boolean membership (Set):** Use `dirset` for IPv4, or `flatset` for IPv6 and sparse sets.
* **Longest Prefix Match (Values/FIB):** Use `dirlpm` when you need route values.
* **Hierarchy traversal (Subnets/Supernets):** Use `flatwalk` when parent and child relationships matter.

---

## Implementations

### Families

* **Flat:** Compiled arena ART (`internal/flatart`). Packages share one index structure and differ mainly in how they store the result.
* **Step:** The address space is stored as discrete intervals, or as a compiled ART when the hierarchy itself is needed.
* **Dir:** Aimed at full BGP tables. For IPv4, dense areas are expanded so a lookup is a direct array index rather than another trie walk.
* **Pointer:** Mutable stride-8 ART tries with an IPv4 `/16` front table. They suit in-place changes, either in a single-threaded caller or behind a lock owned by the caller. Earlier membership variants tried lattice intersection; coverage bitmaps were kept because they cost less than walking the lattice during lookups.
* **Bit:** Bit-at-a-time tries from before the move to stride-8 layouts. One node per bit, so depth follows prefix length.
* **Range:** Merged address intervals. Variants differ in how the interval words are packed; `thinrangeset` is the smallest of the three.
* **Block:** Leaf-pushed 256-entry blocks. Lookups index a block rather than descending a trie.
* **Array:** One sorted array per prefix length, probed longest-first.
* **Compose:** A compiled FIB paired with a separate hierarchy sidecar (bit trie or preorder catalogue). These experiments fed `preorder2`, `compiledfib`, and `splitribfib`.

| Package       | Family  | Description / Architecture                      |
| ------------- | ------- | ----------------------------------------------- |
| `aosart`      | Step    | Pointer-free ART (array-of-structs + ranks)     |
| `artlpm`      | Pointer | Mutable pointer ART returning route values      |
| `artset`      | Pointer | Mutable pointer ART with coverage bitsets       |
| `dirlpm`      | Dir     | DIR-24-8 for IPv4 + arena ART for IPv6          |
| `dirset`      | Dir     | 2-bit `/24` table for IPv4 + arena ART for IPv6 |
| `flatlpm`     | Flat    | Arena-backed ART for value LPM                  |
| `flatset`     | Flat    | Arena-backed ART for boolean membership         |
| `flatwalk`    | Flat    | Arena-backed ART with preorder catalogue        |
| `groupartset` | Pointer | Same as `artset`, using interleaved bit-groups  |
| `orderwalk`   | Dir     | Preorder catalogue with `/16` front index       |
| `parityset`   | Step    | Union ranges with boundary parity checks        |
| `slotlpm`     | Step    | Step function with inline `/16` ranges          |
| `soaart`      | Step    | Pointer-free ART (struct-of-arrays)             |
| `steplpm`     | Step    | Collapsed step-function FIB                     |

### Archived Implementations (`old/`)

Older versions are kept under `old/`. They are still useful for equivalence tests and for a few older wrappers.

| Package          | Family  | Description / Architecture                                |
| ---------------- | ------- | --------------------------------------------------------- |
| `arenaartlpm`    | Flat    | Pointer-free ART using shared relocatable arenas          |
| `arenaartset`    | Pointer | Arena-pooled nodes with sorted index lattice              |
| `artwalk`        | Pointer | Mutable pointer ART with parent links                     |
| `bitfrontlpm`    | Bit     | `/16` front table resuming a bit trie at depth 16         |
| `bitlpm`         | Bit     | Arena bit-at-a-time trie for value LPM                    |
| `bitwalk`        | Bit     | Bit trie with parent pointers                             |
| `blocklpm`       | Block   | Leaf-pushed 256-entry blocks (IPv4/IPv6)                  |
| `coverartset`    | Pointer | Mutable ART with precomputed coverage bitmaps             |
| `fibbitwalk`     | Compose | Compiled FIB with an independent bit-trie RIB             |
| `fiborderwalk`   | Compose | Compiled FIB with preorder catalogue                      |
| `latticeartset`  | Pointer | Mutable ART calculating coverage via lattice intersection |
| `lenlpm`         | Array   | Sorted arrays per prefix length, probed longest-first     |
| `rangeset`       | Range   | Merged ranges with a 2-bit `/16` classifier               |
| `soarangeset`    | Range   | Merged ranges split into parallel arrays                  |
| `thinrangeset`   | Range   | Range intervals eliding zero-valued low words             |

---

## Performance Summary

Benchmarks were run on an AMD EPYC with `-benchtime=5s` and `-benchtime=60s`. The complete run at 60s takes over 24 hours and at 5s takes roughly 3.5 hours and 5s has shown to be enough to show a reliable statistic gap between implementations. The runs covered the various performance and failure modes including 36 lookup adapters, 40 memory factories and 1,766 tests.

### Boolean Membership

| Implementation     | Small scale reads | Large scale reads | Internet routing | Read/Write   | Batch writes| Load writes | Memory                  |
| ------------------ | ----------------- | ----------------- | ---------------- | ------------ | ------------| ----------- | ----------------------- |
| `flatset`          | **15.97 ns**      | **198.3 M/s**     | **5.000 ns**     | **5.366 ns** | 2.31 ms| 143.3 ms    | **32.00 + 5.576 B/pfx** |
| `dirset`           | **11.43 ns**      | **254.4 M/s**     | **5.043 ns**     | **4.479 ns** | 5.86 ms| 440.6 ms    | 112.0 + 9.111 B/pfx     |
| `parityset`        | 25.15 ns          | 186.5 M/s         | **4.756 ns**     | **4.325 ns** | **6.008 μs**| **8.97 ms** | 352.0 + 3.826 B/pfx     |
| `dirlpm` (value)   | **11.63 ns**      | **194.2 M/s**     | 27.42 ns         | 18.75 ns     | 27.32 μs| 1.84 s      | 68.89 + 34.55 B/pfx     |
| `groupartset`      | 23.21 ns          | 159.6 M/s         | 12.94 ns         | 13.04 ns     | 7.40 ms| 322.2 ms    | 18448 + 23.12 B/pfx     |
| `artset`           | 25.27 ns          | 151.3 M/s         | 14.01 ns         | 14.95 ns     | 7.88 ms| 353.2 ms    | 18432 + 21.24 B/pfx     |
| `thinrangeset`     | 27.58 ns          | 151.1 M/s         | 13.59 ns         | 12.36 ns     | 9.63 ms| 386.4 ms    | 208.0 + 2.949 B/pfx     |
| `soarangeset`      | 27.33 ns          | 148.4 M/s         | 12.95 ns         | 12.65 ns     | 10.14 ms| 400.7 ms    | 16560 + 2.949 B/pfx     |
| `range-match`      | 26.93 ns          | 151.2 M/s         | 13.00 ns         | 12.23 ns     | 10.47 ms| 415.0 ms    | 73776 + 13.56 B/pfx     |
| `bart-lite-direct` | 26.20 ns          | 130.4 M/s         | 6.802 ns         | 6.289 ns     | 4.30 ms| 163.1 ms    | 320.0 + 27.16 B/pfx     |
| `flatwalk` (tree)  | 25.98 ns          | 127.4 M/s         | 48.12 ns         | 37.23 ns     | 65.24 ms| 2.88 s      | 19.32 + 25.76 B/pfx     |
| `bart-lite`        | 29.46 ns          | 116.4 M/s         | 11.18 ns         | 13.44 ns     | 5.22 ms| 205.1 ms    | 320.0 + 27.16 B/pfx     |
| `netipds`          | 50.86 ns          | 66.8 M/s          | 8.110 ns         | 7.839 ns     | 20.08 ms| 640.7 ms    | 112.0 + 51.85 B/pfx     |
| `cidranger`        | 99.20 ns          | 43.0 M/s          | 36.36 ns         | 38.72 ns     | 334.6 ms| 12.23 s     | 640.0 + 403.1 B/pfx     |

`dirlpm` and `flatwalk` also return route values rather than booleans (`flatwalk` also is traversable). They are included here to make the membership, forwarding paths and traversal easier to compare.

For boolean checks, a full BGP table containing a default route (`0.0.0.0/0`) can match immediately when the structure records whole-space coverage. The no-default benchmarks below show the cost of lookups that cannot take that shortcut.

### Value Lookup (LPM)



| Implementation      | Small scale reads | Large scale reads | Internet routing | Read/Write   | Batch writes | Load writes  | Memory                  |
| ------------------- | ----------------- | ----------------- | ---------------- | ------------ | ------------ | ------------ | ----------------------- |
| `dirlpm`            | **11.63 ns**      | **194.2 M/s**     | **27.42 ns**     | **18.75 ns** | 27.32 μs     | 1.84 s       | 68.89 + 34.55 B/pfx     |
| `compiled-fib`      | 14.29 ns          | 148.5 M/s         | 40.21 ns         | 31.72 ns     | **15.38 μs** | 6.51 s       | 581.7 + 72.74 B/pfx     |
| `slotlpm`           | 18.01 ns          | 127.8 M/s         | 58.05 ns         | 24.84 ns     | 26.13 μs     | **134.6 ms** | 15.84 + 42.01 B/pfx     |
| `flatlpm`           | 25.44 ns          | 141.1 M/s         | 37.02 ns         | 29.35 ns     | 33.50 μs     | 1.89 s       | **11.39 + 9.683 B/pfx** |
| `steplpm`           | 18.20 ns          | 126.7 M/s         | 63.82 ns         | 25.20 ns     | 32.36 μs     | 801.1 ms     | 14.22 + 43.14 B/pfx     |
| `flatwalk` (tree)   | 25.98 ns          | 127.4 M/s         | 48.12 ns         | 37.23 ns     | 65.24 ms     | 2.88 s       | 19.32 + 25.76 B/pfx     |
| `bart-fast`         | 29.33 ns          | 107.7 M/s         | 76.67 ns         | 54.23 ns     | 9.35 ms      | 345.5 ms     | 32.35 + 38.87 B/pfx     |
| `bart-table-direct` | 32.12 ns          | 103.5 M/s         | 69.81 ns         | 45.13 ns     | 6.15 ms      | 226.5 ms     | 16.91 + 26.30 B/pfx     |
| `arenaartlpm`       | 39.78 ns          | 108.8 M/s         | 65.78 ns         | 71.31 ns     | 21.55 ms     | 1.28 s       | 72.17 + 11.78 B/pfx     |
| `artlpm`            | 39.97 ns          | 97.1 M/s          | 82.86 ns         | 66.33 ns     | 10.36 ms     | 472.5 ms     | 28.39 + 16.83 B/pfx     |
| `versioned-fib`     | 40.39 ns          | 93.5 M/s          | 84.99 ns         | 67.90 ns     | 21.63 ms     | 979.6 ms     | 28.39 + 16.83 B/pfx     |
| `versioned-hybrid`  | 40.30 ns          | 90.9 M/s          | 85.23 ns         | 75.88 ns     | 31.92 ms     | 1.51 s       | 128.0 + 33.65 B/pfx     |
| `versioned-rib`     | 51.79 ns          | 68.0 M/s          | 98.71 ns         | 94.99 ns     | 24.44 ms     | 1.14 s       | 99.66 + 16.82 B/pfx     |
| `tailscale-art`     | 55.68 ns          | 57.5 M/s          | 168.0 ns         | 145.3 ns     | 87.04 ms     | 3.85 s       | 995.3 + 367.4 B/pfx     |
| `kentik-patricia`   | 113.4 ns          | 39.7 M/s          | 847.5 ns         | 344.6 ns     | 20.69 ms     | 648.5 ms     | 56.72 + 111.6 B/pfx     |
| `go-iptrie`         | 131.5 ns          | 40.2 M/s          | 1.210 μs         | 327.6 ns     | 18.83 ms     | 671.9 ms     | 58.97 + 150.7 B/pfx     |

Again, `flatwalk` is included here just to show the cost diff of the tree traversal vs the LPM lookup.

### Hierarchy Traversal

| Implementation  | Traversal    | Small scale reads | Large scale reads | Internet routing | Read/Write   | Batch writes | Load writes  | Memory                  |
| --------------- | ------------ | ----------------- | ----------------- | ---------------- | ------------ | ------------ | ------------ | ----------------------- |
| `flatwalk`      | **41.87 ns** | 25.98 ns          | **127.4 M/s**     | **48.12 ns**     | **37.23 ns** | 65.24 ms     | 2.88 s       | 19.32 + 25.76 B/pfx     |
| `preorder2`     | 56.14 ns     | 19.88 ns          | 112.3 M/s         | 112.3 ns         | 54.60 ns     | **16.00 μs** | 8.54 s       | 795.8 + 488.3 B/pfx     |
| `aosart`        | 67.56 ns     | 46.35 ns          | 79.8 M/s          | 90.20 ns         | 64.73 ns     | 26.27 μs     | **150.4 ms** | 13.34 + 13.91 B/pfx     |
| `soaart`        | 82.85 ns     | 63.37 ns          | 60.8 M/s          | 118.0 ns         | 81.81 ns     | 39.16 μs     | 868.9 ms     | **12.03 + 12.81 B/pfx** |
| `split-rib-fib` | 111.5 ns     | **16.85 ns**      | 119.4 M/s         | 97.20 ns         | 43.26 ns     | 34.97 μs     | 8.04 s       | 772.4 + 392.6 B/pfx     |
| `orderwalk`     | 47.69 ns     | 44.90 ns          | 107.6 M/s         | 78.48 ns         | 60.56 ns     | 32.34 ms     | 1.40 s       | 13.19 + 15.65 B/pfx     |
| `fiborderwalk`  | 51.86 ns     | 20.84 ns          | 94.1 M/s          | 84.75 ns         | 66.46 ns     | 222.0 ms     | 8.78 s       | 699.3 + 340.4 B/pfx     |
| `bart-table`    | 73.47 ns     | 36.85 ns          | 88.4 M/s          | 79.27 ns         | 61.14 ns     | 6.77 ms      | 264.1 ms     | 16.91 + 26.30 B/pfx     |
| `artwalk`       | 181.3 ns     | 46.93 ns          | 69.9 M/s          | 98.15 ns         | 97.56 ns     | 14.28 ms     | 703.4 ms     | 99.66 + 16.82 B/pfx     |

*Traversal is the average of `BenchmarkTraversal/Supernets` and `BenchmarkTraversal/Subnets`.*

---

## Real Table vs. Generated Distributions

The workload generators (in `fibbench/workload_test.go`) try to model full BGP routing table shape. I remember when a full table was 300k - we started writing filtering functions when the full table was 700k.

`genPrefixes(1_401_481, 0.1865, …)` produces a synthetic dataset that matches the prefix length distribution, address family ratio, occupancy tail, and IPv6 `/16` allocations of a recent BGP dump:

| Property                         | `genPrefixes`   | Full Table Dump |
| -------------------------------- | --------------- | --------------- |
| Unique prefixes                  | 1,401,481       | **1,401,481**   |
| IPv6 share                       | 18.65%          | **18.65%**      |
| IPv4 prefixes per occupied `/16` | ~30.7           | **30.7**        |
| IPv4 occupancy p50 / singletons  | ~7 / ~28%       | **7 / 28.3%**   |
| IPv4 `/24` share                 | ~63.3%          | **63.3%**       |
| IPv4 prefixes longer than `/24`  | ~0.1%           | **0.1%**        |
| IPv4 prefixes `/16` or shorter   | ~1.6%           | **1.6%**        |
| IPv6 occupied `/16` blocks       | 65 RIR `/16`s   | **65 +** `::/0` |
| IPv6 `/32` / `/48` share         | ~10.4% / ~46.3% | **10.4% / 46.3%** |

Expanding a stride into a 256-entry array costs ~1 KB. In dense regions (~30.7 prefixes per `/16`) that works out to roughly 33 bytes per prefix. In sparse regions (~3.5 prefixes per `/16`) it climbs to around 290 bytes per prefix. BGP tables have a heavy tail here: half of the occupied `/16` blocks hold 7 or fewer prefixes, and 28% hold exactly one. `genPrefixes` keeps that asymmetry rather than smoothing it out.

To run against actual MRT dumps:
```sh
go run ./cmd/mrtconv -v4 v4-rib -v6 v6-rib -o table.bin
export PREFIXLOOKUP_TABLE=table.bin
```

### Real Table Performance (1,401,481 prefixes: 1.14M IPv4, 261k IPv6)

| Implementation | Zipf         | Uniform      | IPv4         | IPv6         | Retained B/prefix |
| -------------- | ------------ | ------------ | ------------ | ------------ | ----------------- |
| `dirlpm`       | **16.69 ns** | **38.16 ns** | **23.94 ns** | 65.46 ns     | 34.55             |
| `compiled-fib` | 25.65 ns     | 54.77 ns     | 40.85 ns     | **65.04 ns** | 72.74             |
| `flatlpm`      | 25.77 ns     | 48.26 ns     | 34.32 ns     | 66.53 ns     | **9.683**         |
| `flatwalk`     | 30.45 ns     | 65.80 ns     | 47.17 ns     | 78.45 ns     | 25.76             |
| `slotlpm`      | 30.57 ns     | 85.52 ns     | 53.78 ns     | 138.5 ns     | 42.01             |
| `steplpm`      | 32.84 ns     | 94.80 ns     | 55.21 ns     | 159.3 ns     | 43.14             |
| `arenaartlpm`  | 40.70 ns     | 90.86 ns     | 54.83 ns     | 180.8 ns     | 11.78             |
| `orderwalk`    | 56.76 ns     | 100.2 ns     | 82.42 ns     | 127.8 ns     | 15.65             |
| `aosart`       | 59.40 ns     | 121.0 ns     | 91.21 ns     | 152.6 ns     | 13.91             |
| `soaart`       | 81.70 ns     | 154.3 ns     | 128.5 ns     | 190.9 ns     | 12.81             |
| `artlpm`       | 50.52 ns     | 115.2 ns     | 77.75 ns     | 205.6 ns     | 16.83             |
| BART Table     | 51.54 ns     | 107.0 ns     | 84.33 ns     | 171.7 ns     | 26.30             |
| BART Fast      | 46.55 ns     | 106.8 ns     | 82.87 ns     | 123.7 ns     | 38.87             |
| Tailscale ART  | 96.49 ns     | 239.5 ns     | 208.8 ns     | 308.2 ns     | 367.4             |

#### A couple of things worth noting:
* **Density scaling:** `arenaartlpm` goes from 72.17 B/prefix on small fixtures down to 11.78 B/prefix on a full table. Node sharing in dense regions does most of that work.
* **IPv6 clustering:** `compiled-fib`, `dirlpm`, and `flatlpm` land within 2.3% of each other on IPv6 (65.04 to 66.53 ns) despite retained memory spanning 9.68 to 72.74 B/prefix. All three use compressed representations for the IPv6 `/48` allocations, which is where the time goes.

### Real Table Boolean Lookups (No Default Route)

With `0.0.0.0/0` and `::/0` removed, lookups can no longer short-circuit on full-space coverage:

| Implementation     | Uniform      | IPv4         | IPv6         |
| ------------------ | ------------ | ------------ | ------------ |
| `dirset`           | **17.86 ns** | **9.464 ns** | **37.61 ns** |
| `flatset`          | 23.42 ns     | 15.16 ns     | **37.40 ns** |
| `groupartset`      | 38.64 ns     | 26.49 ns     | 72.35 ns     |
| `parityset`        | 40.94 ns     | 30.84 ns     | 62.92 ns     |
| `artset`           | 48.66 ns     | 32.69 ns     | 101.3 ns     |
| BART Lite (direct) | 59.46 ns     | 45.83 ns     | 82.19 ns     |
| `thinrangeset`     | 79.51 ns     | 71.52 ns     | 82.03 ns     |
| `netipds`          | 346.4 ns     | 309.4 ns     | 199.7 ns     |
| `cidranger`        | 2.126 μs     | 2.004 μs     | 1.515 μs     |

* **`parityset`:** Checks boundary parity across disjoint address ranges. It does well on sparse sets that collapse into a handful of boundaries, and scales linearly with range fragmentation on dense IPv4 tables.
* **`dirset`:** Allocates a fixed 4 MiB bitmask for the whole IPv4 `/24` space. That's a good trade on a full table and a poor one on a small fixture.
* **Radix behaviour:** `netipds` is quick (7.1 ns) while the working set fits in cache, then stretches to 346.4 ns on cold full-table lookups. `cidranger` returns fast (38.25 ns) when a default route is present, but needs around 2.1 μs per lookup once a full tree traversal is required.

### 32 Concurrent Readers (Full Table)

From `BenchmarkRealTableParallel`, across a 65,536-address working set with no cache locality:

| Implementation | Mlookups/s | Implementation | Mlookups/s |
| -------------- | ---------- | -------------- | ---------- |
| `dirset`       | **330.8**  | `flatlpm`      | 96.2       |
| `flatset`      | 329.7      | `orderwalk`    | 80.1       |
| `parityset`    | 318.0      | `flatwalk`     | 78.2       |
| `groupartset`  | 172.4      | `slotlpm`      | 78.1       |
| `dirlpm`       | **113.8**  | `steplpm`      | 76.6       |
| `compiled-fib` | 82.2       | `soaart`       | 45.2       |

---

## Technical Details

### Harness Overhead Notes

Adapters wrapped in `newRebuilding` go through `atomic.Value`, interface assertions, and closures, which adds a few nanoseconds of harness overhead. The `bart-lite-direct` and `bart-table-direct` variants use direct atomic pointers matching the repository's native managed tables, so they're the fairer baseline.

### Shared Arena Core

`flatset`, `flatlpm`, and `flatwalk` share `internal/flatart`, a stride-8 ART stored in pointer-free arenas addressed by `uint32` slots:

1. **Inherited stride defaults:** Each stride records the shortest covering prefix at index 1. Deeper strides always represent longer prefixes, so the descent never backtracks and never needs a search stack.
2. **Compact childless strides:** Strides with no children skip the 64-byte child pointer block, so a single cache line is read before value resolution.
3. **Contiguous value indexing:** Value indices sit in contiguous slices resolved as `base + rank`, with no indirection lookups.
4. **Two-level `/16` root:** A flat 16-bit root needs 256 KB per family. Splitting it into a 1 KB `/8` index over shared 1 KB blocks lets memory scale with actual occupancy without changing stride depth (the real IPv6 root shrinks to 4 KB).

#### Tuning fun:
* **Branch penalties:** Adding a 4th stride shape needed an extra tag bit and a conditional jump. That added 5.7 ns to a 15 ns IPv4 lookup, which was more than the memory savings were worth.
* **Register pressure:** A branchless mask resolver came in at 24.6 ns against 14.7 ns for the branch-based version, because of register spilling. Precomputed cover masks ended up being the best compromise.

---

## Implementation Comparisons

Numbers below are from the Boolean Membership, Value Lookup, and Hierarchy Traversal tables.

### Boolean Sets: `dirset`, `flatset`, and `parityset`

* **`dirset`:** Two bits per IPv4 `/24` (covered, uncovered, or delegated to a longer-prefix range), plus the flatart arena for IPv6. A full table is ~63% `/24` and under 0.1% longer, so most IPv4 answers are one load, one shift, and one mask. The IPv4 front table is a fixed 4 MiB, which is why small-scale memory is 49.60 B/pfx and large-scale drops to 9.111 B/pfx. It leads the membership table on small reads (11.43 ns), large-scale throughput (254.4 M/s), and internet routing (5.398 ns). Rebuilds are the expensive part: 5.48 ms batch writes, 440.6 ms load.
* **`flatset`:** Same `internal/flatart` arena as `flatlpm` / `flatwalk`, but a lookup is a bitmask test per stride and never resolves a rank. Whole-space coverage - a default route, or any tiling of the family - collapses that family to one bit and drops the index. There is no 4 MiB floor (10.25 + 5.576 B/pfx). Reads sit between the other two (15.97 ns small, 5.756 ns internet, 198.3 M/s large). Batch writes 2.13 ms, load 143.3 ms.
* **`parityset`:** Membership depends only on the union, so prefixes collapse to maximal disjoint ranges stored as toggle boundaries. A `/16` slot table localises the search; empty slots answer from the parity of the slot index alone. On a table with a default route the whole family is one range. Writes are in a different class: 667.6 ns batch, 8.97 ms load. Internet routing is 5.574 ns - within 0.2 ns of `dirset` - while small-scale reads are 25.15 ns. Memory scales with range count (10.73 + 3.826 B/pfx).

`thinrangeset` (archived) is the smallest set in the table (1.968 + 2.949 B/pfx) at 14.51 ns internet routing. `groupartset` is the mutable alternative: in-place pointer updates, 23.21 ns small reads, 13.38 ns internet, 7.41 ms batch.

### Value Tables: `dirlpm`, `flatlpm`, and `slotlpm`

* **`dirlpm`:** IPv4 is expanded - a `/16` root over 256-entry blocks - so a typical `/24` lookup is two array indexes with no bitmask or popcount. IPv6 stays on the flatart arena. It wins every LPM read column: 11.63 ns small, 194.2 M/s large, 38.16 ns internet, 18.75 ns under write load. Memory is the trade (68.89 + 34.55 B/pfx). Batch writes (17.36 μs) match the step tables; a full load is 1.84 s.
* **`flatlpm`:** Compact arena trie, payload in a flat slice indexed by slot. No leaf-push and no 256-entry blocks. Smallest value table in the results (11.39 + 9.683 B/pfx). Internet routing is 48.26 ns - about 10 ns behind `dirlpm`, still ahead of the step tables (85–95 ns). Batch writes 24.50 μs, load 1.89 s.
* **`slotlpm` / `steplpm`:** Leaf-push the table into sorted `(boundary, route_id)` steps, then localise with a `/16` slot table. `slotlpm` carries the step range inline so a non-uniform `/16` does not pay an extra dense-record load. That is why it rebuilds so much faster (134.6 ms load vs 801.1 ms for `steplpm` and 1.84 s for `dirlpm`) while batch writes stay in the same band as `dirlpm` (17.93 μs / 18.44 μs). Lookups on a full table are slower: 85.52 ns and 94.80 ns internet routing.

`compiled-fib` wraps the archived block index with paged copy-on-write payloads. Payload batches are 5.599 μs, but retained size is 581.7 + 72.74 B/pfx and a load is 6.51 s. `artlpm` is the in-place pointer ART: 39.97 ns small, 115.2 ns internet, 10.43 ms batch - no generation rebuild, and writers are not wait-free.

### Hierarchy & Walks: `flatwalk`, `orderwalk`, and `soaart` / `aosart`

* **`flatwalk`:** Arena LPM plus a preorder catalogue. Descendants are the contiguous run after a route; ancestors are a 4-byte parent index per route. Fastest traversal in the table (41.87 ns) and the fastest LPM among walkable structures (25.98 ns small, 65.80 ns internet, 127.4 M/s). Rebuilds the whole generation: 65.90 ms batch, 2.88 s load. Memory 19.32 + 25.76 B/pfx.
* **`orderwalk`:** Drops the trie. A `/16` front index plus preorder arrays answer LPM, exact, parents, and descendants by bisection and a parent walk. Traversal is 47.69 ns - second to `flatwalk` - at 13.19 + 15.65 B/pfx. LPM is the cost (44.90 ns small, 100.2 ns internet). Batch writes 32.18 ms, load 1.40 s.
* **`soaart` / `aosart`:** Compiled stride-8 ARTs that keep every prefix at its own level, so one structure answers LPM and walks without a sidecar catalogue. `soaart` is struct-of-arrays (12.03 + 12.81 B/pfx, 82.85 ns traversal, 868.9 ms load). `aosart` packs a node into two cache lines with precomputed ranks: 67.56 ns traversal, 17.99 μs batch, 150.4 ms load - the fastest hierarchy rebuild.

`preorder2` is a managed wrapper around the archived preorder catalogue with paged payload updates: 5.219 μs batch writes and 19.88 ns small reads, at 795.8 + 488.3 B/pfx and an 8.54 s load. `artwalk` is the mutable pointer walk; traversal is 181.3 ns.

---

## Recommendations by Workload

| Use Case | Implementation | Why |
| :--- | :--- | :--- |
| **Lowest-latency LPM** | `dirlpm` | Wins every LPM read column: 11.63 ns small, 194.2 M/s large, 38.16 ns internet, 18.75 ns under write load. |
| **Lowest-latency membership** | `dirset` | 11.43 ns small, 254.4 M/s large, 5.398 ns internet. Pay a fixed 4 MiB IPv4 `/24` table. |
| **Sparse or fast-updating membership** | `parityset` | 667.6 ns batch writes, 8.97 ms load; 5.574 ns internet when the union collapses to a few ranges. |
| **Membership without the 4 MiB floor** | `flatset` | 15.97 ns small, 5.756 ns internet, 10.25 + 5.576 B/pfx. |
| **Minimum memory (values)** | `flatlpm` | 9.683 B/pfx on large tables, 48.26 ns internet routing. |
| **Frequent full rebuilds** | `slotlpm` | 134.6 ms load, 17.93 μs batch. Lookups are slower on a full table (85.52 ns internet). |
| **Payload updates with hierarchy** | `preorder2` | 5.219 μs batch via copy-on-write pages; 795.8 + 488.3 B/pfx and an 8.54 s load. |
| **Combined LPM and traversal** | `flatwalk` | Fastest traversal (41.87 ns) and the fastest LPM among walkable tables (65.80 ns internet). |
| **Compact hierarchy** | `soaart` | 12.81 B/pfx. Use `aosart` when rebuild latency matters (150.4 ms load, 17.99 μs batch). |
| **In-place single-threaded updates** | `artlpm` / `groupartset` | Incremental pointer mutation, no generation rebuild. |

---

## Structure Matrix

### Value / LPM Structures

| Package        | Primary Use                              | Read Complexity                                  | Memory Profile                                                 | Update Model                                                                                | Concurrency                         | IPv4/IPv6                             | Traversal Support             |
| -------------- | ---------------------------------------- | ------------------------------------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------- | ----------------------------- |
| `flatlpm`      | Low-memory managed FIB                   | 2–4 dependent loads                              | 11.4 B/pfx (gen), 9.7 B/pfx (real)                             | Value-slice CoW; index-enumerated rebuilds                                                  | Wait-free reads; single writer      | Shared arena, separate roots          | None                          |
| `steplpm`      | Churning/sparse FIB tables               | 1 `/16` load + interval bisection                | 14.2 B/pfx (gen), 43.1 B/pfx (real)                            | Vector CoW; structural index rebuilds                                                       | Wait-free reads; single writer      | Separate step tables                  | None                          |
| `slotlpm`      | Step FIB with inline slots               | 1 `/16` load; direct slot range check            | 15.8 B/pfx (gen), 42.0 B/pfx (real)                            | Vector CoW; sorted packed prefix slices                                                     | Wait-free reads; single writer      | Separate step tables                  | None                          |
| `dirlpm`       | Latency-optimised FIB                    | 3 array loads (no arithmetic on IPv4)            | 68.9 B/pfx (gen), 34.6 B/pfx (real)                            | Value-slice CoW; sorted prefix array rebuilds                                               | Wait-free reads; single writer      | Direct IPv4, compressed IPv6          | None                          |
| `flatwalk`     | LPM + tree hierarchy                     | Fast LPM, trie exact match                       | 19.3 B/pfx (gen), 25.8 B/pfx (real)                            | Generation rebuild                                                                          | Lock-free immutable reads           | Shared arena, separate catalogues     | Exact, Parents, Descendants   |
| `soaart`       | Compact hierarchy index                  | Trie descent                                     | 12.0 B/pfx (gen), 12.8 B/pfx (real)                            | Vector CoW; index rebuild on structure changes                                              | Wait-free reads; single writer      | Separate trees                        | Exact, Parents, Descendants   |
| `aosart`       | Cache-aligned hierarchy index            | Trie descent (supernets computed during descent) | 13.3 B/pfx (gen), 13.9 B/pfx (real)                            | Vector CoW; packed prefix slices                                                            | Wait-free reads; single writer      | Separate trees                        | Exact, Parents, Descendants   |
| `orderwalk`    | Subnet scans without trie                | Bisection + parent walk                          | 13.2 B/pfx (gen), 15.7 B/pfx (real)                            | Generation rebuild                                                                          | Lock-free immutable reads           | Separate catalogues and front indexes | Exact, Parents, Descendants   |
| `compiledfib`  | High-throughput FIB                      | Flat compiled LPM                                | 582 B/pfx (gen), 72.7 B/pfx (real)                             | Paged CoW payload updates; topology rebuilds                                                | Wait-free reads; single writer      | Separate layouts                      | None                          |
| `splitribfib`  | Managed split RIB/FIB                    | Fast forwarding path                             | 772 B/pfx (gen), 393 B/pfx (real)                              | Paged CoW updates; background structural rebuilds                                           | Wait-free reads; single writer      | Separate indexes                      | Parents, Descendants          |
| `preorder2`    | Managed hierarchy + FIB                  | Fast LPM with hierarchy                          | 796 B/pfx (gen), 488 B/pfx (real)                              | Paged CoW updates; topology rebuilds                                                        | Wait-free reads; single writer      | Separated within FIB                  | Exact, Parents, Descendants   |
| `fiborderwalk` | LPM with preorder scans                  | Fast LPM; sequential child scans                 | 699 B/pfx (gen), 340 B/pfx (real)                              | Generation rebuild                                                                          | Lock-free immutable reads           | Separated within FIB                  | Exact, Parents, Descendants   |
| `artlpm`       | Mutable in-place LPM                     | Fixed short stride depth                         | 28.4 B/pfx (gen), 16.8 B/pfx (real)                            | Incremental in-place updates                                                                | Single-threaded or external locking | Separate roots                        | Exact, Prefix, Full           |
| `artwalk`      | Mutable hierarchy                        | Trie descent with parent checks                  | 99.7 B/pfx (gen), 16.8 B/pfx (real)                            | Incremental in-place updates                                                                | Single-threaded or external locking | Separate roots                        | Parent, Supernet, Subnet, All |
| `arenaartlpm`  | Low-GC ART                               | Relocatable arena traversal                      | 72.2 B/pfx (gen), 11.8 B/pfx (real)                            | Incremental with generation rebuilds                                                        | Lock-free immutable generation      | Separate roots                        | Exact, Full                   |

### Boolean / Set Structures

| Package                       | Primary Use                       | Read Complexity                         | Memory Profile                                                   | Update Model                                        | Concurrency                     | IPv4/IPv6                    |
| ----------------------------- | --------------------------------- | --------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------- | ------------------------------- | ---------------------------- |
| `flatset`                     | General boolean membership        | 1 mask test per level                   | 10.3 B/pfx (100k), 5.6 B/pfx (1M)                                | Generation rebuild                                  | Lock-free immutable reads       | Shared arena, separate roots |
| `parityset`                   | Sparse membership sets            | 1 `/16` load + boundary bisection       | Scales with range count: 10.7 B/pfx (100k), 3.8 B/pfx (1M)       | Immutable publication (no-ops skip generation allocations) | Lock-free immutable reads | Separate boundary arrays     |
| `dirset`                      | High-performance IPv4 membership  | 1 memory load (IPv4)                    | Fixed 4 MiB IPv4 base: 49.6 B/pfx (100k), 9.1 B/pfx (1M)         | Generation rebuild                                  | Lock-free immutable reads       | Direct IPv4, compressed IPv6 |
| `bart-lite`                   | Adaptive radix filter             | ~10.7 ns standard, 5.9 ns direct        | 12.3 B/pfx (with defaults), 29.5 B/pfx (without)                  | Incremental / batch updates                         | Lock-free reads                 | Separate roots               |
| `artset`, `groupartset`       | Mutable boolean membership        | Single classifier access for hot IPv4   | 15.6–16.3 B/pfx (with defaults), 26.5–28.1 B/pfx (without)       | Incremental in-place updates                        | Single-threaded / external lock | Separate roots               |
| `rangematch`                  | Aggregated range filter           | Flat ~12 ns lookup                      | 12.0 B/pfx (gen), 13.6 B/pfx (real)                              | Range rebuild                                       | Lock-free immutable reads       | Separate ranges              |
| `soarangeset`, `thinrangeset` | Smallest coalesced range set      | Flat 12–13 ns lookup                    | 3.28 and 1.97 B/pfx (100k), 2.95 B/pfx (1M)                      | Range rebuild                                       | Lock-free immutable reads       | Separate ranges              |
| `netipds`                     | Small in-cache IP set             | 7.1 ns in-cache; misses scale to 346 ns | 25.6 B/pfx (gen), 64.3 B/pfx (real)                              | Incremental                                         | External locking required       | Combined/Family              |

---

## Running the Benchmarks

```sh
cd fibbench

# Standard 1s benchmark run
go test -run '^$' -bench . -benchmem -benchtime=1s

# Automated suite execution
./run-bench.sh

# Full suite run (5s per benchmark)
IMPLEMENTATIONS=full BENCHTIME=5s RESULTS_FILE=benchmark-results-5s.txt ./run-bench.sh
```

### Benchmark Descriptions

* **`BenchmarkFIB`:** Single-lookup latency across synthetic dual-stack tables loaded with default routes and generated prefixes (1,000 to 1,000,000 routes).
* **`BenchmarkQueryDistributions`:** Hits versus total misses (using the unallocated `240.0.0.0/4` space) to see how early each structure rejects.
* **`BenchmarkFamilyMixes`:** Single-stack (IPv4-only / IPv6-only) against dual-stack, to expose family decoding overhead.
* **`BenchmarkScaleSweep`:** Lookups against a non-contiguous address ring (coprime stride), so cold-cache behaviour shows up as table size grows.
* **`BenchmarkComparativeParallel`:** Aggregate throughput across 1 and 32 worker threads under Zipf distributions.
* **`BenchmarkMixedReadWrite`:** How far lookups degrade while background writers apply route changes, at read/write ratios from 100,000:1 to 10,000,000:1.
* **`BenchmarkBulkLoad`:** Full initialisation, memory allocation, and indexing time for 100,000 routes.
* **`BenchmarkUpdateBatches`:** Update latency at batch sizes of 1, 16, and 256.
* **`BenchmarkConvergenceStorm`:** 64-route withdraw-and-restore cycles, comparing atomic batch application against per-route updates.
* **`BenchmarkMemory` / `BenchmarkMembershipMemory`:** Retained Go heap and bytes-per-prefix after garbage collection.
* **`BenchmarkTraversal`:** The non-LPM operations: supernet lookups (all covering parents) and subnet scans (all child routes).
* **`BenchmarkRealTable` / `BenchmarkRealTableParallel` / `BenchmarkRealTableMemory`:** Latency, scaling, and memory retention against live full BGP dumps (~1.4M routes).
