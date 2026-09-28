# Bytecode versus SLOAD latency: 2026-09-27

## Conclusion

The unexplained tens of microseconds are predominantly storage-completion wait,
not in-memory B-tree traversal, decoding, or allocation. Two serial reads are
not two equal-latency reads: the 24 KiB second request takes about 92 us between
block issue and completion, versus about 64 us for 4 KiB. Direct reads bypassing
MDBX and the page cache reproduce this difference. This localizes the penalty
below the database; it does not distinguish NAND, controller, DMA, and completion
interrupt costs or establish a saturated-bandwidth bottleneck.

## Cold control

Nine trials per mode, 512 actual encoded contracts per trial. All values contain
24 KiB runtime plus the persisted jump table and metadata, spanning seven pages.
General read-ahead is disabled. Only the disposable copied database is evicted.

| Control | Follower NVMe wall/op | CPU/op | Builder NVMe wall/op | CPU/op |
| --- | ---: | ---: | ---: | ---: |
| Prefix-only MDBX read | 68.90 us | 2.64 us | 66.34 us | 2.59 us |
| Full value, current late prefetch | 166.05 us | 9.12 us | 163.34 us | 8.27 us |
| Full value, early-offset oracle | 105.89 us | 7.56 us | 110.23 us | 7.61 us |
| Direct 4 KiB | 66.51 us | 1.99 us | 64.85 us | 2.03 us |
| Direct sequential 4 + 24 KiB | 168.03 us | 5.19 us | 161.14 us | 5.07 us |
| Direct single 28 KiB | 105.44 us | 3.58 us | 105.69 us | 3.56 us |

For the current late-prefetch implementation on the follower NVMe:

- MDBX lookup including the first overflow page: 67.03 us wall, 2.53 us CPU.
- `MADV_WILLNEED`: 2.69 us wall, 2.70 us CPU (timer-boundary noise).
- Copying the remaining data: 95.38 us wall, 2.95 us CPU.
- Whole-pass CPU includes these stages, verification, loop/timer overhead, and
  user/kernel work; it must not be added again to phase CPU.

The extra over two prefix-only cold reads is 28.25 us on the follower device:
24.41 us off-CPU and 3.84 us CPU. On the builder device it is 30.66 us:
27.58 us off-CPU and 3.08 us CPU. This directly rejects an explanation based on
30-40 us of pure database/decoder CPU work.

The block trace's exact means and checks are in `summary.json` under `block`.
It independently measures roughly 64 us for 4 KiB, 92 us for the 24 KiB second
read, and 98 us for a single 28 KiB read. There are thousands of requests per
group. Buffered, direct, and MDBX access paths agree. Initial DB-open metadata
requests are separately identifiable by request size and are not used for these
means. Tracing is a separate run; the table above uses untraced controls.

## In-memory work

65,536 sampled keys per actual large source table, 2,621,440 measured random
lookups per table after conditioning, zero physical reads/major faults:

| Work | Wall/op |
| --- | ---: |
| Account B-tree lookup | 0.606 us |
| Bytecode B-tree lookup, including mapped overflow header | 0.822 us |

The exact Rust compact decoder was linked from the node's compiled dependency,
not reimplemented in C. It includes code allocation/copy and jump-table loading.
Measured means exclude one conditioning trial and include five trials of 72,000
decodes per configuration:

| Jemalloc configuration | Decode + release/op |
| --- | ---: |
| ~14 MiB input, immediate release | 0.415 us |
| ~216 MiB input, immediate release | 0.948 us |
| ~14 MiB input, retain 2,250 values then release | 2.275 us |
| ~216 MiB input, retain 2,250 values then release | 2.819 us |

The large-input retained case spends 2.598 us in decoding/allocation and
0.221 us in release. CPU and wall times match; allocation's anonymous minor
faults are included. System malloc is slower for retained batches (~5.35 us in
the large-input case), still not tens of microseconds. The node uses jemalloc.
These are component controls, not total EVM execution costs or additive
instruction-level accounting for the historical full-node run.

## Relating this to the original 2.7x ratio

The earlier builder figures were 59.08 us per SLOAD-loop iteration versus
160.02 us per bytecode iteration: an excess of 41.86 us over exactly twice the
SLOAD figure. That is not a comparison of two fully cold database reads.

The new fully cold controls independently reproduce 28-31 us excess over two
single-page reads, primarily off-CPU. The historical SLOAD run generated about
0.85 physical read requests per included iteration rather than one; bytecode
generated about 1.94. This is consistent with cache hits reducing the SLOAD
denominator, explaining why the observed ratio is greater than the ~2.4-2.5x
fully cold microbenchmark ratio. Whole-node counters are not opcode-attributed,
so this is not an exact cache-hit or remaining-microsecond decomposition.

In particular, this investigation has not profiled every opcode/provider/cache
operation in a newly repeated full-node run. The residual ~11-14 us when
bridging the component controls and old full-node averages is not assigned to
a specific function. It should not be mislabeled as proven CPU overhead.

The early-offset oracle reduces the current full-value path from 163-166 us
to 106-110 us by collapsing two requests to approximately one, without reducing
read bytes. This suggests moving prefetch inside MDBX before the first overflow
header touch. It is not an implemented node fix or measured end-to-end speedup.

## Validation and artifacts

- Idle machine; sequential controls under the benchmark lock.
- Both dedicated Micron NVMe devices tested, CPU 8 (follower) and CPU 0 (builder).
- No node started, no source database mutated/evicted, no global cache flush.
- 90 zero-residency cold checks per run; byte comparisons on every read.
- Warm buffered/mapped passes have zero read requests, read bytes, major faults.
- Trace checks reject partial completions, issue/completion mismatches,
  correlation collisions, outstanding requests, and device errors.
- C compiled with `-Wall -Wextra -Werror`; Rust formatted with nightly rustfmt.
- `latency-a.jsonl`, `latency-builder.jsonl`, `latency-traced.jsonl`,
  `block-latency.jsonl`, `latency-wide.jsonl`, and `codec-*.jsonl` are raw results.
- `summary.json` is generated by `contrib/bench/analyze-bytecode-latency.cjs`.
- `records*.bin` hold the exact encoded bytecode inputs for the codec control.
- Initial traces are retained as `*-v1.jsonl` and `*-v2-invalid.jsonl`. The second
  run detected two sector-key collisions and was rejected. The final trace uses
  kernel request identity, with collision and partial-completion checks.

Reproduction and limitations are documented in
`contrib/bench/bytecode-latency-diagnostic.md`.
