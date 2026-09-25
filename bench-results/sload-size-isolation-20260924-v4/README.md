# SLOAD size isolation: measured conclusion

Completed 2026-09-24. All four load phases and their audits passed. Nodes were
stopped after durable catch-up. This is one controlled sequential pass, not a
confidence interval or proof of the worst possible workload.

## Result

The smaller transaction's useful-read advantage disappears when prewarming is
disabled. The surprising speedup is a transaction-size/prewarming interaction,
not evidence that an individual SLOAD becomes intrinsically faster in a smaller
transaction. Higher gas per useful read also inflates the smaller case's gas/s.

Primary measurement window: load seconds 600-1200, after 600 seconds of warmup.

| SLOADs/tx | Prewarming | Builder execution Mgas/s | Canonical SLOAD/s | Chain production Mgas/s | Follower durable Mgas/s | Builder read requests/Mgas |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 4096 | on | 18.241 | 8274.594 | 18.013 | 18.072 | 8635.622 |
| 128 | on | 38.516 | 15151.328 | 37.689 | 37.700 | 5582.820 |
| 4096 | off | 39.183 | 17822.763 | 38.798 | 38.285 | 365.149 |
| 128 | off | 44.100 | 17478.992 | 43.479 | 42.908 | 323.377 |

With prewarming on, 128-read transactions deliver 83.1% more canonical workload
SLOADs/s than 4096-read transactions. With prewarming off, they deliver 1.9%
fewer. Their gas per useful SLOAD is 14.3% higher, about 2488 versus 2177, because
fixed transaction/router costs are amortized across fewer reads. Consequently,
the remaining gas/s advantage with prewarming off is not a useful-read advantage.

The separately selected last-five-minute window agrees. Whole-builder read
requests per canonical SLOAD are 18.788 (4096/on), 13.893 (128/on), 0.795
(4096/off), and 0.806 (128/off). These are physical I/O requests for the whole
node, including speculative work, trie and persistence, not unique page misses
or reads attributed to individual opcodes.

## Mechanism and limits

The measured binary's builder prewarming implementation seeds twice the worker
count in transactions, then replenishes on completion. Its wrapper checks the
stop flag before `evm.transact_raw`, not between SLOADs within that transaction.
Thus a transaction-count lookahead can represent much more speculative state
work for a 4096-read transaction than a 128-read transaction, and already-running
transactions can continue after cancellation is requested. The matching source
is archived under the binary's build-source directory; the implementation is
`crates/payload/builder/src/prewarming.rs` (initial batch at line 163, whole-tx
execution at line 255).

The much higher I/O and larger throughput penalty with prewarming enabled are
consistent with speculative read amplification and contention. This experiment
isolates the prewarming subsystem interaction, but does not separately quantify
lookahead, cancellation tails, CPU competition, or cache pollution. Both builder
and engine prewarming are disabled in the off control; execution caches and the
bytecode page-prefetch setting remain enabled.

History-bypass coverage is also explicitly audited: 0.08% for 4096/on versus
96.72% for 128/on. The large/on case is a diagnostic control with almost entirely
single-transaction blocks, not a successful history-bypass workload. Its three
first-transaction traces prove cold EVM reads, not prewarming divergence. Small
cases retain the normal non-first-transaction sampling and 90% eligibility gate;
their sampled parent-state replays have zero overlap with actual read targets.

Do not read follower execution Mgas/s as sustainable throughput. The 128/off case
has 47 pipeline runs, including cached replay; its execution-only 54.906 Mgas/s
is not useful end-to-end capacity. Its follower durable rate is 42.908 Mgas/s and
backlog grows from 0.413 to 0.703 Ggas. Large/off backlog grows from 0.785 to
0.981 Ggas. Both on cases maintain their backlog during the measured window;
all four eventually durably catch up after the timed load.

## Controls and reproduction

All cells use the same binary, unchanged populated fixture and complete storage
domain, 1000 offered TPS, 1000 signers, CPU allocation and separate NVMe devices.
Each node has a verified 20 GiB total-memory cap, no swap and no OOM events.
Every cell starts from a fresh restore with each scratch MDBX file individually
evicted and verified by `mincore` to have zero resident pages before startup.
No global cache flush or source-snapshot mutation is used. Actual file cache is
reported: equal total-memory limits do not reserve equal page-cache capacity.

The fixture retains 100000 MiB of populated storage and 100000 MiB of unique
bytecode. Binary SHA256:
`5e4752f9d04cf152486487c6d4a33c91fa31011e6df9e7fa3760d0acd39b9f2d`.
Fixture root:
`0x35b455ab5ebd982f1516eb9cd5660e4a652e1bbbe78de642b1f0f59eb5cc9784`.

See `contrib/bench/sload-size-isolation.md` for the reusable runner and tool
requirements. Run order was 4096/on, 128/on, 128/off, 4096/off. The suite took
about 117 minutes including setup, observation and post-load audits. Exact
configuration, command lines, hashes and timing are in `experiment.json`; input
sources are archived in `source/` and pre-run changes in `worktree.patch`.

`throughput.md` and `throughput.json` contain primary measurements, time slices,
cache residency and audit details. `late-window.md` and `late-window.json`
contain the 900-1200 second sensitivity check. Its analysis script was selected
before the four-case comparison completed and does not replace the primary window.

Earlier attempts are excluded, not pooled into these results:

- `sload-size-isolation-20260924-200336`: stopped during restore to correct copied-file cache ownership; no load ran.
- `sload-size-isolation-20260924-v2`: large/on load finished but lacked required non-first trace samples; audit failed and the result is excluded.
- `sload-size-isolation-20260924-v3`: stopped during restore to complete the explicit large-control audit policy; no load ran.

The normal history-bypass benchmark audit is not relaxed. Only the explicit
4096-read diagnostic control permits first-transaction trace samples and records
that limitation. All four final cases ran from fresh restores with fixed inputs.
