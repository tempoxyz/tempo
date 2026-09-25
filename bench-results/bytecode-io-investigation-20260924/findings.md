# Why the bytecode workload is worse

## Conclusion

The main demonstrated mechanism is whole-object loading combined with disabled
read-ahead: a 32-byte EXTCODECOPY charges 2,603 gas in the sampled transactions,
but a code-cache miss decodes approximately 27 KiB from a seven-page MDBX value.
The existing configuration normally demand-loads these adjacent pages as separate
4 KiB requests. SLOAD returns one small value, typically from one data leaf when
the B-tree's upper levels are cached.

This is not seven levels of Merkle traversal, nor expensive execution of the
target contract. The target starts with STOP and is not called: EXTCODECOPY reads
its bytes. The workload copies only 32 bytes at offset 1 and consumes them in an
accumulator. Source inspection plus isolated controls establish the mechanism;
the full-run counters show its practical scale, with the caveats below.

## Existing Full-Run Evidence

SLOAD is the successful rerun at `../20260924-123000-011`; bytecode is the earlier
validated run at `../20260924-073246-310`. Both used the same node SHA256,
1,000 offered TPS, 1,000 signers, 1,200 seconds of load, and a 600-second excluded
warmup. Both retained the 100,000 MiB storage and 100,000 MiB unique code corpora.
The shared router was updated between runs, so this is not an exact-fixture
three-way comparison. No new end-to-end node benchmark was run for this diagnosis.

| Metric | SLOAD | Bytecode | Bytecode / SLOAD |
| --- | ---: | ---: | ---: |
| Nominal state-access operations/Mgas | 459.37 | 324.71 | 0.707 |
| Follower whole-node read I/Os/executed Mgas | 333.83 | 2,074.06 | 6.213 |
| Follower whole-node read MB/executed Mgas | 1.367 | 8.497 | 6.214 |
| Builder whole-node read I/Os/executed Mgas | 7,874.04 | 35,413.44 | 4.497 |
| Follower execution Mgas/s | 42.479 | 7.743 | 0.182 |
| Builder execution Mgas/s | 19.524 | 6.110 | 0.313 |
| Canonical chain Mgas/s | 19.257 | 5.982 | 0.311 |

MB means decimal megabytes. Read I/Os average 4,096 bytes for SLOAD and about
4,097 bytes for bytecode on the follower. Neither database device recorded
merged read requests during either measured window. Nominal per-operation
normalization gives 0.727 whole-node reads/SLOAD versus 6.387 whole-node
reads/EXTCODECOPY. These include other node work; they are not direct opcode I/O
attribution or measured page-cache hit percentages.

The follower's average device read latency was essentially unchanged:
63.30 us for SLOAD versus 63.14 us for bytecode. It issued about 6,434 versus
11,692 reads/s, reading only 26.4 versus 47.9 MB/s. This is consistent with
many small latency-bearing reads rather than a large sequential transfer.
Device statistics include the whole device and are not execution-thread timings.

Bytecode builder execution-cache lookups missed 99.64% of the time. The recorded
code-cache capacity was 16,384 entries, versus 4,266,667 unique corpus contracts.
The follower's code-cache size approached this capacity. Cache generations and
prewarming also affect reuse; the capacity ratio alone is not a hit-rate model.

The builder's much larger I/O totals include speculative work for transactions
not included in blocks. Per-thread attribution was not collected, so it would
be incorrect to claim each included bytecode opcode itself caused 109 reads.
The seven-page object cost applies to speculative cold loads too, but the exact
share of builder I/O due to prewarming versus other work remains unmeasured.

## The Lookup Path

1. The router hashes salt and the shared cursor to choose 128 addresses across
   the 4.27-million-contract corpus.
2. REVM loads the account with code before copying the requested byte range.
3. On a cache miss, the latest-state provider obtains the account from
   HashedAccounts and the full bytecode value from Bytecodes by code hash.
4. The bytecode codec copies the complete padded bytecode and reconstructs the
   persisted jump table. There is no lazy 32-byte database slice on this path.
5. Reth sets `no_rdahead: true`; MDBX applies `MADV_RANDOM` to its mapping.
   Touching the next nonresident page can therefore cause another synchronous
   demand read even though it is adjacent in the same overflow extent.

References in the measured dependency checkout:

- [EXTCODECOPY load before slice](/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/revm-interpreter-43.0.1/src/instructions/host.rs:90).
- [Latest account lookup](/home/ubuntu/repos/reth-payload-cancel-fix/crates/storage/provider/src/providers/state/latest.rs:73).
- [Latest bytecode lookup](/home/ubuntu/repos/reth-payload-cancel-fix/crates/storage/provider/src/providers/state/latest.rs:311).
- [Whole bytecode copy](/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/reth-primitives-traits-0.7.1/src/account.rs:210).
- [Jump-table reconstruction](/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/reth-primitives-traits-0.7.1/src/account.rs:235).
- [Reth read-ahead configuration](/home/ubuntu/repos/reth-payload-cancel-fix/crates/storage/db/src/implementation/mdbx/mod.rs:471).
- [MDBX MADV_RANDOM](/home/ubuntu/repos/reth-payload-cancel-fix/crates/storage/libmdbx-rs/mdbx-sys/libmdbx/mdbx.c:20184).

## Actual Record Layout

Read-only inspection of the stopped follower scratch database found:

| Table | Branch footprint | Leaf footprint | Overflow footprint |
| --- | ---: | ---: | ---: |
| Bytecodes | 4.25 MiB | 275.86 MiB | 113.93 GiB |
| HashedAccounts | 8.16 MiB | 467.36 MiB | none |
| HashedStorages | 836.02 MiB | 71.02 GiB | none |

Each of 512 sampled corpus records had 24,576 runtime bytes, a 3,072-byte jump
table, and padding/codec metadata, totaling 27,662-27,693 encoded bytes. The value
began 20 bytes into its first overflow page and spanned exactly seven pages.
Bytecodes has 29,866,686 overflow pages in total. This large data footprint,
not its roughly 4 MiB branch index, is the main candidate for sustained cold
loads on a host with 62.4 GiB shared RAM.

Bytecode also needs account lookup, unlike repeated SLOADs within one owner.
However, its account and code-index footprints fit comfortably in RAM and are
much smaller than the overflow corpus. Their actual residency was not traced,
so they are not claimed to cause zero I/O. Seven overflow pages alone are enough
to explain the order of magnitude of the observed per-access cost.

## New Controlled Experiments

The diagnostic copied the exact 512 encoded values and their code-hash keys into
a private MDBX table on the follower NVMe. Three trials per mode used verified
zero-residency cold starts and same-environment warm controls. Only the private
file was evicted; the large source was read-only, with no host-wide cache flush.
Read requests came from a dedicated cgroup's database-device `io.stat`.

Means per record, with normal read-ahead disabled:

| Access mode | Read requests | Major faults | Read bytes | Time |
| --- | ---: | ---: | ---: | ---: |
| Read only requested 32 bytes | 1.020 | 1.016 | 4,256 | 67.5 us |
| Read full encoded value | 7.008 | 7.004 | 28,784 | 465.4 us |
| Full value, targeted extent prefetch | 2.018 | 1.016 | 28,784 | 165.7 us |

Targeted `MADV_WILLNEED` was applied only to this value's seven-page extent after
MDBX returned it, keeping general read-ahead disabled. The first overflow page
was already touched by lookup. Request count fell about 3.47x and lookup time
about 2.81x, without reducing read bytes. Fewer major faults did not mean fewer
bytes fetched: pages can arrive through explicit prefetch rather than faults.

With general read-ahead enabled, the full-value control averaged 0.254 requests
and 22.1 us per record. That mode benefits from fetching neighboring records in
the small copy and must not be projected onto the 114 GiB random-access corpus.
For the prefix-only control, enabling read-ahead increased bytes from 4,256 to
28,656 per record, illustrating the cost of indiscriminate read-ahead.

All 18 cold-residency checks passed. All 18 warm passes recorded zero major
faults, zero storage read bytes, and zero read requests. Every returned byte range
was checked against the source records. The diagnostic compiled with warnings
treated as errors and both experiment invocations exited successfully.

This measures the decoder's page footprint, not its exact Rust CPU cost. Timings
include database opening, lookup and byte verification. No gas is charged in this
storage-engine control, and no end-to-end speedup is claimed.

## Prewarming and Comparison Limits

In the measured windows, 6,971/9,117 bytecode transactions (76.46%) had a preceding
transaction in their block, versus 5/1,297 SLOAD transactions (0.386%). Every
sampled non-first bytecode transaction had zero target overlap with parent-state
replay; all 128 accesses cost 2,603 gas. Thus bytecode exercised the intended
within-block history mechanism much more often. This is not a direct trace of
the actual speculative workers, and first transactions or other speculative
transactions can still warm matching targets.

The older bytecode follower also entered pipeline catch-up eight times during
measurement. Whole-node I/O covers that work, but execution-cache and payload-
thread counters do not cover every path. Only complete whole-node ratios are
used above. Neither the 6.21x I/O/gas difference nor 5.49x follower execution
slowdown is claimed to be explained exactly by the seven-page factor alone.

The most focused follow-up optimization is to test value-sized prefetch for
Bytecodes overflow extents in the real node, leaving random small-value reads
unchanged. The control establishes a mechanism worth testing, not a production
recommendation to enable MDBX-wide read-ahead. Range-aware bytecode loading is
another possibility but would require changes to the provider/codec/EVM path.

## Reproduction and Artifacts

See [diagnostic instructions](../../contrib/bench/bytecode-page-diagnostic.md)
and [source](../../contrib/bench/bytecode-page-diagnostic.c).
The isolated controls used MDBX 0.13.12, 4 KiB pages, and the same bundled static
library as the earlier storage controls. No production node or fixture changes
were made. A separate successful pilot omitted the targeted-prefetch mode.

- `page-controls-targeted.jsonl`: final record layouts and all controlled measurements.
- `page-controls-targeted-summary.json`: asserted trial counts, cold/warm checks, and means.
- `comparison.json`: normalized full-run comparison and caveats.
- `disk-counters.json`: archived device counter deltas, including request latency and merges.
- `cache-capacity-history.json`: cache capacities and measured-window history coverage.
- `binaries-and-source.sha256`: diagnostic source, executable, MDBX library and node hashes.
- `page-controls.jsonl`: initial no-targeted-prefetch pilot, retained separately.

Linux read-byte accounting is storage-layer accounting, not SSD-internal NAND
traffic: [kernel I/O counter documentation](https://docs.kernel.org/filesystems/proc.html#proc-pid-io-display-the-io-accounting-fields).
