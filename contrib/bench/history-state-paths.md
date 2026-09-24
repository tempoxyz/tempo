# History-dependent bloated state paths

For the directly comparable three-case suite, use the
[saved benchmark configurations](configs/README.md). The default runner now
includes the original SLOAD workload on the same fixture and binary; the
two-case results below remain a historical record. The public entry point is
`nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD`.

Local-chain performance experiment, with prewarming left enabled. This extends
the original history-dependent SLOAD design, not the cache-resident vault controls.
It tests two hypotheses; it does not establish a universal worst case.

- `history_code`: 128 EXTCODECOPY operations per transaction. Target addresses
  are selected using `keccak(salt, cursor)` and per-access hashes across 4,266,667
  distinct 24,576-byte code bodies (100,000 MiB). A leading STOP makes the rest
  unreachable data; deterministic BLAKE3 output prevents trivial compression and
  code-hash deduplication. Copying 32 bytes still requires the provider to obtain
  the bytecode object. Contiguous overflow pages may coalesce into fewer reads;
  actual disk requests and bytes, rather than code size alone, measure that.
  A 1,024-access smoke test produced one transaction per block, defeating the
  intended within-block history change; that attempt was rejected, not reported
  as a valid history-dependent result. Batch size must allow multiple transactions
  per block, and the report must quantify the share with preceding transactions.
- `history_write`: 1,024 nonzero-to-nonzero writes to populated slots in the
  original 100,000 MiB SLOAD import. History selects a 4,096-slot logical page;
  the first 1,024 slots are read and updated by toggling the top value bit.
  This retains the original single-account storage tree. It varies slots, not
  storage-owner addresses, avoiding an extra call/account-load confound. It is
  **not** a multi-account storage-write benchmark.

Each successful transaction advances a shared cursor. Current builder prewarming
uses parent state, so preceding transactions change the selection in real
execution. The first transaction can match, and collisions/other transactions'
prefetches can warm some targets. Do not claim a guaranteed 100% mismatch.

## Recorded Results: 2026-09-24

Both 1,200-second runs completed with the first 600 seconds excluded. Both
correctness/persistence audits passed. The fixture occupies about 331 GB per
node, with 62.4 GiB of host RAM shared between the two nodes.

| Workload | Canonical Mgas/s | Follower durable Mgas/s | Follower execution Mgas/s | Follower whole-node major faults/executed Mgas |
| --- | ---: | ---: | ---: | ---: |
| Bytecode | 5.982 | 5.356 | 7.743 | 2090.343 |
| Populated-slot writes | 22.240 | 8.404 | 68.444 | 927.177 |

These are observed window rates, not proven steady-state ceilings. The write
follower's backlog grew from 9.716 to 17.511 Ggas during measurement, and its
post-load audit completed 1,005 seconds after load ended. Execution-only rates
hide the incremental Merkle cost. Bytecode also had some catch-up; its backlog
grew from 0.064 to 0.404 Ggas and its audit completed 79 seconds after load.

The bytecode follower recorded 2,074 read I/Os per executed Mgas, averaging
4,097 bytes per read; the device-wide counters also average about 4 KiB. That
is about 6.39 whole-node read I/Os per nominal EXTCODECOPY at the observed gas
per transaction, not one large 24 KiB read. This ratio includes other node
work and is not direct per-opcode I/O attribution.

All six sampled non-first transactions had zero target overlap with parent-state
replay. Across the entire runs, 77.64% of code transactions and 70.54% of write
transactions had earlier workload transactions in the same block. First
transactions are not claimed to defeat parent-state prewarming.

The original evidence is in the local archive
`bench-results/history-state-paths-sustained-20260924-v2/{throughput.md,throughput.json}`;
raw benchmark archives and the experimental node/dependency patches are not
included in this benchmark PR.
The historical SLOAD result used another binary; these runs do not establish a
same-binary ranking against it or a universal worst case.

The subsequent matched run on 2026-09-24 stopped after the SLOAD load phase:
only one measured block contained multiple transactions, below the audit's
three-block requirement. That attempt is rejected, not a validated three-way
comparison. The native command preserves the original 4,096-read workload and
this fail-closed audit; changing its batching requires a separate experiment.

## Reproduction

Requires the two preserved original block-zero state-access snapshots, the same
host-specific e2e harness (separate NVMe mounts, CPU sets, systemd and sudo), and
compatible node and fixture-helper binaries. The native command builds the
requested git refs; historical measurements used an explicitly patched local
binary and are not automatically reproduced by unpatched refs. The two nodes
share host RAM. Initialization
only modifies a new `history_paths` copy; original `.virgin` snapshots are read
only. The helper refuses live/nonlocal/already-prepared databases. A failed
import is marked incomplete and must not be used as a valid fixture.

```sh
bash contrib/bench/txgen/compile-history-state-paths.sh
bash contrib/bench/txgen/compile-history-state-paths.sh --test
RUSTFLAGS='-C target-cpu=native' cargo build -p tempo \
  --example prepare_history_state_paths --example read_finish_checkpoint --profile profiling \
  --features jemalloc,asm-keccak -j8
bash contrib/bench/prepare-history-state-paths.sh
nu bench-e2e.nu state-access-bloat-worst-case --dry-run
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD
```

Run all three cases sequentially, restoring the same fixture for each. Defaults are
1,200 seconds, 600 seconds warmup, 1,000 offered TPS, no artificial transaction
cap. Native flags `--duration`, `--summary-warmup-seconds`, `--tps`, and
`--feature-binary` select overrides; sender/checkpoint binary overrides remain
available through the harness. At least 270
measured seconds are required by the observer coverage checks. Suite exit zero
requires all selected load phases, correctness audits, and analysis to succeed.
The opt-in `--single-restore` mode is restricted to one observed feature phase
with an explicit binary and dedicated snapshot suffix. It skips redundant
pre-phase/final copies, verifies block-zero checkpoints before starting nodes,
and retains the stopped final scratch database for inspection. The next run
always restores from the unchanged virgin fixture.

Before sending load, both nodes must durably persist ordinary blocks past genesis.
This is outside the measured window and does not modify prewarming or workload
selection. Otherwise an early follower catch-up starts MerkleExecute at block 1,
which deliberately rebuilds the entire imported trie regardless of its existing
contents. That initialization artifact was observed in the first sustained write
attempt; the run was stopped and rejected. Priming evidence is archived per case.

## Evidence and Limitations

At least eight distributed blocks' receipts reconcile canonical gas and success. Three
non-first transactions (when available) have actual prestate/call/diff traces
compared with parent-state replay and cursor-overridden opcode replay. The audit
checks populated code/values, 128 code accesses or 1,024 writes, cold gas charges, changed nonzero
storage, and access-set agreement. The replay models prewarming's state; it is
not direct instrumentation of speculative worker accesses.

Reports separate canonical wall gas/s, execution-only gas/s, application-cache
misses, follower payload-thread major faults, whole-node cgroup major faults/file
refaults, and database-device I/O per gas. Whole-node counters cover catch-up,
prewarming and persistence too, including speculative work for transactions never
included. They share aligned observer gas endpoints. Missing/partial coverage and
counter resets fail analysis; older uninstrumented runs report null, not zero.
Executed-gas counters can include replayed execution; they are not strictly a
count of finally charged canonical gas. A nonstationary write backlog also means
window I/O/gas ratios do not capture all eventual persistence cost of that window.
A read request is not a cache miss or necessarily one physical page.
Reports also sum canonical gas crossed by each durable frontier and quantify
backlog against the producer's head. Comparing only the follower's own head
with its persisted state can hide pipeline catch-up lag. Commit progress is
stepwise, so the observed durable rate is not by itself an asymptotic capacity
estimate. Zero-execution intervals retain raw I/O/faults and report null per-gas
ratios rather than failing or dividing by zero.
Observer frontiers must advance during the measured window, and both nodes must
durably persist through the drained workload. Traces run after the measurement
window. They are excluded from timed I/O, not described as persistence-only I/O.
Post-load catch-up is bounded at 30 minutes for writes and 10 minutes for code;
neither allowance is part of measured throughput. A growing follower backlog is
reported, not treated as a sustainable canonical producer rate.

The 100,000 MiB label describes the original dump, not physical total DB bytes.
Both cases additionally contain the code corpus. Preserve manifests, binary
hashes, source archives and allocated/apparent sizes. Archived SLOAD results used
an earlier unpatched binary; do not present them as a same-binary comparison.
