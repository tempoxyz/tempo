# Speculative execution benchmarks

Experimental and disabled by default. GitHub saturation benchmarks have not shown
a consistent net improvement over sequential execution; this work has not demonstrated
that execution is no longer the node's bottleneck. The implementation targets current
main (Tempo 1.14, Reth 2.7, revm 43), with ordered read validation and replay.

Engine payload validation now consumes strict results from its existing
prewarming workers when available, and executes ordered misses directly.
Workers receive advisory state hints only from accepted block commits; discarded
execution results never advance those hints. The handoff defaults to at most 128
completed results; `--execution.capture-window` also permits 256 or 512 for
controlled comparisons. It changes Engine admission, retention and the in-flight
cap, with the same 32 MiB limit on estimated result payload and the block's
accepted-state hints retained separately. The estimate is not an allocator/RSS
bound. The Engine's external prewarming coordinator uses the selected capture
window for both its lead over the committed cursor and its queued/running job
cap. The coordinator polls progress and cancellation every 100 microseconds;
workers do not wait for admission. The bounds exclude converted inputs, provider
caches and the initial worker setup job.
The first 128-window comparison
regresses official latency metrics despite improving Engine reuse and execution time.
The optional dispatcher is pinned to
[Reth 382b9390f](https://github.com/paradigmxyz/reth/commit/382b9390f9901c51f1d0cb94836f80c175be9615).
Small blocks, disabled prewarming and
BAL payloads retain the regular scheduler. Engine prewarming concurrency follows
`--engine.prewarming-threads`; the regular pool follows `--execution.threads`.
Typed block executors use authoritative State-cache validation, with received
BALs retaining ordinary database validation.
Engine expiring-AA commits omit nonce-precompile storage hints to reduce prefix
publication work. Their ring-pointer predictions remain relative to the parent
and source offset; missing or older hints still undergo full ordered validation
and conflicting candidates execute ordinarily. Keyed nonce and builder hints
retain their existing publication paths.
Automatic generic scheduling starts at five transactions in the remaining
candidate slice; shorter blocks, tails and system-delimited slices execute
directly. Already prepared and prewarmed candidates remain eligible for reuse.
`--execution.capture-diagnostics` optionally records Engine admission, strict
execution, publication and consumption outcomes without changing scheduling.
It defaults off. Counters belong to a unique session and payload hash;
`loop_finish` is concurrent and precedes block acceptance, while `session_drop`
has final counts but may be delayed or absent at process exit. Reconcile only
final snapshots for accepted blocks. Worker completion counts cover the capture
hook, not the full prewarming job. Confirm performance without these counters.
`--execution.stage-diagnostics` independently enables ordered validation,
ordinary execution and commit wall times when speculation is enabled. It defaults
off and performs no clock reads when disabled. Counts include returned errors;
ordinary execution also includes body replay after a conflict. Snapshots precede
block finalization and must be reconciled with accepted blocks. These timers
exclude dispatch, prefix publication, receipt construction, system and inspected
execution, finalization, and commits bypassing the EVM wrapper. They do not measure
CPU time or the full block cost; confirm performance with diagnostics disabled.
Builder workers also follow `--engine.prewarming-threads`. Speculative admission
uses `--execution.batch-size`, capped at 128 outstanding candidates, with a separate
32 MiB estimate limit on completed results retained by each build. Running workers,
the single extracted candidate and accepted-prefix hints are outside that estimate.
Pending, contended or over-budget results fall back to ordinary ordered execution.
Ordinary prewarming retains its two-candidates-per-worker window.
Mutable context access and inspector use also require checking journal warming
before reuse; custom warm sets retain ordinary execution and its gas charges.

T14 workers can also rebase one certified nonzero custody increment from a
successful single-call AA channel open. A whole-transaction journal observer
excludes other accesses to that slot; arithmetic, every SSTORE gas class and
all other reads must still match. Zero crossings, overflow, warm target access
lists, authorization lists and multi-call transactions retain ordinary replay.
The `native_rebased` counter is separate from fee rebasing.

Only reusable benchmark scripts and this summary belong in this directory.
Store reports, JSON, TSV, logs, profiles, rejected patches and research notes in
`benchmark-artifacts/parallel-execution/` at the repository root. That directory
is ignored by Git. The local archive contains the previous detailed notes as
`research-notes.md`; GitHub workflow runs retain their own downloadable artifacts.
Do not add generated evidence to commits. Keep material results in this summary
and link the corresponding workflow run.

## Correctness and in-memory execution

The scheduled E2E workflow also provides a separate manual generated-correctness
mode. It runs the public mix with speculative peer A and sequential peer B,
compares their finalized canonical blocks and complete receipts, and requires
fresh opposite-peer Engine execution plus positive canonical reuse in both
parallel roles. It fails if the generated cohort or required log evidence is
missing. Both peers use the selected candidate binary; shared changes such as
State commit optimization still require their separate ordinary-State oracle
tests. These runs do not publish performance results or Slack notifications.
The manual `capture-window` choice selects 128, 256 or 512. An explicitly
configured window requires generated blocks larger than that window from both
producers, as well as positive included reuse in each parallel role.

[Generated validation 37103153124](https://github.com/tempoxyz/tempo/actions/runs/37103153124)
passes on `0936aef39` (the same Rust implementation as `13e97e5be`). Both peers
match selected finalized header fields, ordered transaction hashes and full receipts for blocks 8–170:
163 dense blocks containing 1,573,044 transactions. Each block has a producer
execution and fresh opposite-peer Engine execution followed by `VALID`.
The parallel peer builds 89 blocks and validates 74; its included builder reuse
is at least 806,336 transactions, and Engine reuse is exactly 258,154.
Both peers use sixteen prewarming workers, with execution threads eight versus
zero. This is a correctness result for the paid expiring-AA public mix, not a
comparison against unmodified main or a sustained 50,000 TPS result.

[Generated validation 37108470757](https://github.com/tempoxyz/tempo/actions/runs/37108470757)
passes on `06f046cda` with capture window 512. Live checks match finalized roots,
selected header fields, ordered transaction hashes and full receipts for 171 blocks containing
1,710,254 transactions. Every block exceeds the window; both peers produce
blocks, and every block has fresh opposite-peer Engine execution followed by
`VALID`. The parallel peer includes at least 911,939 builder reuses and exactly
435,180 Engine reuses. Both peers launch the same verified binary, with eight
versus zero execution threads and sixteen prewarming workers. Archived receipt
digests and 855 independently checked log records support the live verification;
the archive does not contain the complete receipt bodies. This correctness run
does not establish a performance improvement.

[Generated validation 37128602979](https://github.com/tempoxyz/tempo/actions/runs/37128602979)
passes on `b4719cec6`, including the Engine nonce-hint omission, with capture
window 512. Live checks match state/receipt roots, selected header fields, ordered
transaction hashes and full receipts across 181 finalized blocks and 1,587,855
transactions. Both peers produce dense blocks; the parallel peer includes at
least 822,717 builder reuses and exactly 405,488 Engine reuses. Independent audit
checks 904 source records and both finalized chains, with zero node errors.
Receipts remain a live-oracle result: the archive retains their digests only.
This is correctness evidence, not a throughput comparison against main.

[Bounded-dispatch validation 37135338419](https://github.com/tempoxyz/tempo/actions/runs/37135338419)
passes on `274320653` with capture window 512. Live checks match state/receipt
roots, selected header fields, ordered transaction hashes and full receipt JSON
across 166 finalized blocks and 1,530,645 transactions. Both peers produce blocks
larger than the window. Included builder reuse is at least 753,216; accepted
Engine logs show 476,364 reuses across 651,249 received transactions (73.15%). They bind
every block to producer and fresh opposite-peer execution, with 1,637 `VALID`
statuses and no node errors. The archive retains receipt digests rather than
receipt bodies. Reuse on this generated workload does not establish a speedup.

[Generated validation 37164999238](https://github.com/tempoxyz/tempo/actions/runs/37164999238)
passes on boxed-result candidate `7cedad7a4`: the same executable with eight versus
zero execution workers matches finalized roots, ordered transactions and full
receipts for 187 blocks containing 1,579,481 transactions. Engine reuse is 534,584
and included builder reuse is at least 789,795; both peers produce dense blocks.
The archive retains receipt digests; full receipt comparison ran live.

```sh
gh workflow run bench-e2e-scheduled.yml --ref onbjerg/parallel-execution \
  -F sequential-peer=true -f ref='<candidate-sha>'
```

```sh
cargo +1.98.1 test --release --locked -p tempo-evm --lib
cargo +1.98.1 test --release --locked -p tempo-payload-builder --lib
cargo +1.98.1 test --release --locked -p tempo-node --test it \
  'tip20::test_tip20_transfer::parallel'
mkdir -p benchmark-artifacts/parallel-execution
TEMPO_BENCH_HARDFORK=T14 TEMPO_BENCH_COUNTS=10000,25000,50000,100000 \
  TEMPO_BENCH_WORKERS=0,4,8,16,32 \
  TEMPO_BENCH_WORKLOADS=tip20_paid_aa_expiring_multitoken \
  cargo +1.98.1 test --release --locked -p tempo-evm execution_throughput \
  -- --ignored --nocapture \
  > benchmark-artifacts/parallel-execution/execution-throughput.log 2>&1
```

`workers=0` selects sequential execution. Counts are transactions per run,
not offered TPS. The harness compares complete receipts and final trie roots
against sequential execution and uses `revm::State` for the node's account
deletion rules. The funded multi-token fixture uses 1,000 senders,
four TIP-20 transfer tokens, explicit pathUSD fees and expiring AA nonces (T12+).
The T14 `tip20_paid_aa_expiring_public_mix` fixture models the GitHub preset's
80% transfers, 5% issuer mints and 15% native MPP opens, with existing recipients
and a shared channel-reserve balance. It also checks minted supply and deposits.
Set `TEMPO_BENCH_CONFLICTS=1` to count conflicting read keys; this diagnostic
suppresses throughput and phase timings because tracing changes execution cost.
`TEMPO_BENCH_BATCH_SIZE` sets the speculative window, and
`TEMPO_BENCH_PHASES=1` adds preparation, ordered-execution and commit timings.
Compare equally instrumented runs. Signing, initial state setup, disk I/O,
networking, consensus and trie hashing are excluded from execution throughput.

`TEMPO_BENCH_PREWARMING=1` instead exercises the builder's recorded-execution
path with persistent workers and twice as many pending candidates as workers.
`TEMPO_BENCH_PREWARMING_PREFIX=0` disables accepted-prefix hints for comparison.
`TEMPO_BENCH_STATE_VALIDATION=1` selects the builder's authoritative State-cache
validator; unset or `0` uses generic database reads. Compare both settings using
the same compiled binary.
`TEMPO_BENCH_STATE_HOOK=1` includes block transitions and a no-op state hook,
matching the node's borrowed commit path. With that enabled,
`TEMPO_BENCH_STATE_COMMIT=1` selects the optimized repeated-storage commit;
unset or `0` uses the ordinary State commit. Compare both settings in one binary.
The sequential reference always uses ordinary commits.
This mode always includes a sequential receipt/root comparison. It models the
ordered reuse path with an in-memory provider and a standard thread queue;
it waits for selected results and does not model the node's ready-only probes,
configurable builder admission window or completed-result quota. In addition,
it excludes the node's provider I/O, shared Rayon pool, pool coordinator, bundle
merging and real hook work. Without `TEMPO_BENCH_STATE_HOOK`, it also excludes
transition accumulation and hook delivery. Regular scheduler tuning switches are unsupported
in this mode. Results before the switch from `CacheDB` commits to `State` also
used different account-deletion rules and are not comparable throughput figures.

A final paired 1,000,000-transaction T14 diagnostic with eight workers measures
155,245 TPS with generic validation versus 168,645 with State-cache validation
(+8.63%), with matching sequential receipts and roots. This is an in-memory
result; the node benchmark remains the performance gate.

With transition accumulation and hook delivery enabled, three paired
1,000,000-transaction T14 public-mix runs measure 155,729 versus 172,733 TPS
at eight workers (+10.92%) for ordinary versus optimized State commits. At
sixteen workers the medians are 135,592 versus 138,566 (+2.19%), with mixed
individual pairs. Ordinary sequential controls vary -0.34%. Every run matches
ordinary sequential receipts and roots; these in-memory figures exclude bundle
merging and actual hook work and do not establish a node-level win.

Scanning consecutive warm reads under one account lookup further raises median
throughput from 167,594 to 188,014 TPS (+12.18%) in three paired million-transaction
T14 runs with eight workers. All receipts and roots match; sequential controls
remain approximately 129k TPS. These local results exclude node I/O and do not
establish a GitHub throughput improvement.

The native-increment candidate `a5e6c3231` improves the million-transaction
public mix from 148,076 to 167,539 TPS with eight workers (+13.14%) and 126,466
to 146,659 with sixteen (+15.97%), comparing medians of three interleaved pairs
against `abb11d902`. Its sequential control falls 6.51% (121,668 to 113,743 TPS).
All threaded runs match their binary's sequential receipts and roots; the
sequential overhead remains under investigation. These are in-memory figures.

Publishing only changed ordinary storage slots to advisory state hints measures
179,175 to 180,273 TPS at eight workers (+0.61%, mixed paired results) and 141,105
to 170,637 at sixteen (+20.93%, all three pairs improve), against `2109a4149`.
All threaded runs match sequential receipts and roots, with similar reuse;
creation still publishes all observed slots. Omitted hints may increase reads or replay
after Engine pre-execution changes, so the GitHub comparison remains necessary.

A single builder result slot replaces the per-candidate result channel and
separate completion allocation. Three interleaved million-handoff pairs using
actual captured results reduce median handoff time 36.75% for ready results and
21.72% with one worker and a sixteen-result window. This diagnostic includes
common job and permit channels, excludes execution and validation, and does not
establish a node throughput improvement.

Boxing infrequent coordinator invalidations shrinks each command from 128 to
16 bytes. With the single result slot, a separate interleaved comparison reduces
handoff-only median time another 7.21% for ready results and 17.37% across threads.
All three executable pairs improve; node-level impact remains unmeasured.

For historical data, use the read-only differential replay command:

```sh
mkdir -p benchmark-artifacts/parallel-execution
tempo parallel-replay --chain /path/to/genesis.json --datadir /path/to/node-data \
  --from 1000 --to 1100 --threads 8 --batch-size 128 \
  --output benchmark-artifacts/parallel-execution/replay.tsv
```

Bounds are inclusive; the database must retain parent state and canonical
receipts. Replay compares execution outputs and state deltas, stored receipts,
gas and receipt roots, and canonical state roots. Its execution timers exclude
trie hashing and run sequential first, so cache warmth can differ.

## Local node diagnostics

```sh
cargo +1.98.1 build --release --locked -p tempo -p tempo-bench
python3 benchmarks/parallel-execution/run_node.py \
  --output benchmark-artifacts/parallel-execution/node-trial \
  --targets 10000,25000,50000,75000 --workers 0,8 --duration 10
python3 benchmarks/parallel-execution/summarize_cpu.py \
  benchmark-artifacts/parallel-execution/node-trial \
  > benchmark-artifacts/parallel-execution/node-trial-summary.json
```

Omit `--output` to use a fresh ignored `node-*` directory. Each trial creates
fresh genesis state and uses loopback RPC, no peers, 100 funded accounts,
100 ms dev blocks, and disabled prewarming. Node and generator share the host;
this diagnostic differs from the GitHub benchmark's normal prewarming and large
state database. Use `--profile-cpu` with `pidstat` for per-thread CPU samples.
`profile_node.py --node-binary /path/to/tempo` captures Pyroscope profiles into
a fresh ignored `profile-*` directory by default; the binary needs the
`pyroscope` feature. `summarize_profile.py DIRECTORY` prints the profile summary.
Redirect summaries into the ignored artifact directory. Profiling affects timing.

## GitHub measurement gate

Use `.github/workflows/bench-e2e.yml` for paired node measurements and
`.github/workflows/bench-replay.yml` for historical replay. Pin baseline, feature
and txgen revisions. Recent e2e comparisons use T14, three interleaved 90-second
pairs, 1,000 senders, four tokens, 100 concurrent requests, a 100 GiB bloat input,
and the public-mix preset (80% transfers, 15% MPP opens, 5% mints). The feature
uses `--execution.threads 8 --execution.batch-size 128`. Retain normal roots and
prewarming. Use the workflow's `no-slack=false` option for future manual runs;
the on-win policy posts only with a significant improvement and no significant
regression. It suppresses neutral, losing and mixed results.

The existing `bench-e2e-multi-region.yml` workflow also supports a single-region
GCP run with two validators on `c4d-standard-48-lssd` VMs and a separate load
generator. Pin both revisions and record the actual CPU topology, binary builds
and measurement intervals; its workload controls and reporting differ from the
bare-metal comparison. Cloud runs currently have no win classifier or Slack post.
GCP teardown now snapshots resource identities, recovers verified leftovers and
requires two empty inventories. After a lost runner, dispatch that same workflow
with `cloud=gcp-cleanup` and `baseline=bench-e2e-multi-region-<run-id>-<attempt>`.
Recovery requires a completed target run and checks exact ownership labels and
resource IDs; it does not delete shared networking or cache buckets.
[Cloud setup run 37131504100](https://github.com/tempoxyz/tempo/actions/runs/37131504100)
verifies all six VM/boot-disk identities absent after Terraform teardown and
three empty inventories. Recovery deletion was unnecessary and remains untested
against live resources. The run produced no performance result: its harness
enabled T14 but disabled earlier forks by using lexical JSON field order,
stalling baseline consensus before load. The workflow now pins
[the numeric hardfork-order fix](https://github.com/tempoxyz/tempo-multi-region-benchmark/commit/49546631d5322ec32bdd9b986919bc25a05853ad);
its local regression tests and the following cloud run pass.

[Cloud comparison 37135616796](https://github.com/tempoxyz/tempo/actions/runs/37135616796)
compares main `61c979a524` with `274320653` on two 48-vCPU validators and a separate
generator. In one 90-second pair at 50k requested TPS, chain TPS rises from 18,981
to 21,025 (+10.77%), builder gas throughput rises 21.33% and validator gas throughput
rises 5.61%; validator p90 also rises 16.74%. This is a descriptive, mixed result.
Actual attempt rates are 19,726 and 21,920/s; pool-full errors dominate failures.
All 322 measured blocks (3,535,780 transactions) match producer execution, fresh
peer execution and later `VALID`. Both arms activate every fork through T14,
and teardown evidence confirms all three VMs and boot disks absent. Cloud builds
use Rust 1.99.0/default features, unlike the bare-metal comparison; profiling was
off. The run establishes neither sustained 50k TPS nor CPU saturation, and sends
no Slack notification.

[Cloud diagnostic 37139307488](https://github.com/tempoxyz/tempo/actions/runs/37139307488)
repeats that comparison with profiling and Engine scheduler tracing. All 328
measured blocks (3,678,010 transactions) bind to producer execution, fresh peer
execution and later `VALID`; all three VMs and boot disks are absent after cleanup.
TPS rises from 19,069 to 22,064, but validator p90 rises 22.33%. This is one
instrumented pair, not a performance win. Kernel captures report no loss;
Samply reports substantial loss and cannot establish absolute CPU attribution.
In accepted Engine log-event envelopes, scheduled time falls from 20.93 to
17.12 microseconds per transaction; feature runnable and nonrunnable time are
1.00 and 1.16 microseconds, respectively. Scheduled time remains 88.79% of these
feature intervals. These symbolic scheduler partitions use estimated clock
alignment and include instrumentation and kernel interruptions. Independent
matched `schedstat` counter intervals agree with scheduled time within 0.181%;
runqueue totals differ by up to 4.744%. During sending, Tempo uses about 19–20
CPU equivalents per validator while the hosts report 24–26 idle CPU equivalents.
The machines expose 48 logical CPUs, but missing cgroup limit files prevent a
claim about CPU entitlement. Execution still contains substantial serial work.

These earlier cloud results have unverified source-to-running-binary binding.
[CPU diagnostic 37148468451](https://github.com/tempoxyz/tempo/actions/runs/37148468451)
found that regional caches could retain an older ELF and checksum after a forced
source rebuild, while receiving new provenance. Its live baseline ELF hash differs
from the build provenance. The run also rejected unsupported perf metadata during
preflight, before running the feature arm; it supplies no CPU attribution or A/B
result. All three VMs and their boot disks were removed.

[CPU retry 37152374490](https://github.com/tempoxyz/tempo/actions/runs/37152374490)
verifies matching build, ready-marker and live baseline ELF hashes after the
cache repair. Both preflights still fail: one has missing or broken DWARF callers,
and the other starts during cooldown. The feature arm never runs. All three VMs
and boot disks are removed; this supplies no CPU attribution or paired result.
The next harness uses source-bound frame-pointer builds and waits for a fresh
post-reset preparation marker before starting its activity window.

[CPU diagnostic 37157291850](https://github.com/tempoxyz/tempo/actions/runs/37157291850)
qualifies all four recordings against source-bound frame-pointer builds and
accepted Engine intervals. The audit covers 1,046 measured blocks and 10,413,660
transactions; all three VMs and boot disks are removed. At 50k offered TPS, this
single instrumented pair delivers 16,791 versus 18,038 TPS, while validator p90
rises from 258.11 to 293.45 ms. It is a mixed diagnostic, not a performance win.
Feature caller-presence counts are 230/186 for ordered validation, 161/152 for
prefix publication, 132/108 for commit and 371/314 for ordinary execution or replay,
over 1,464/1,223 in-interval samples on the two validators. These groups are
nonadditive; kernel and unresolved samples remain in the denominators. Storage
provider leaves account for 76/52 validation samples, motivating work on repeated
cold reads. Host counters still lack ancestor CPU limits and worker affinity;
the next harness captures those separately at a bounded ten-second cadence.

The workflow's builder gas throughput averages `gas_used / elapsed` over full
payload builds. It includes setup, transaction selection, waits and finalization;
it is not execution-only throughput. CPU profile shares describe sampled work
and must be combined with elapsed-time measurements before identifying a bottleneck.

[Bounded-dispatch comparison 37135326741](https://github.com/tempoxyz/tempo/actions/runs/37135326741)
compares `274320653` with speculative predecessor `b4719cec6`, using window 128.
The official result is **Regression**: TPS 15,723 to 15,884 is neutral, while
validator p90 rises 5.60% and block-interval p90 rises 4.36%. Across the accepted
chains, Engine reuse rises from 30.59% to 77.15% and execution falls from 25.29 to
24.19 microseconds per transaction; foreground state-root finishing time rises
in every pair. These log cohorts include warmup and differ from the official
measurement cohorts. All 7,146 observed payload statuses are `VALID`; the workflow
correctly skips its win-only Slack post. This is not a comparison against main.

[Session-borrow comparison 37140139020](https://github.com/tempoxyz/tempo/actions/runs/37140139020)
compares `1c86a7ab5` with `274320653`, removing an ordered-path session Arc clone.
The official result is **No Difference**: TPS is 14,080 to 13,727 and every
classified metric is neutral. All 6,437 observed payload statuses are `VALID`,
and all six terminal peer heads match. Accepted Engine execution is 21.81 versus
22.04 microseconds per transaction, with mixed changes across pairs. This change
has not demonstrated a throughput improvement; win-only Slack correctly skips it.

[Window comparison 37137516063](https://github.com/tempoxyz/tempo/actions/runs/37137516063)
uses one verified `274320653` binary with capture windows 128 and 512. The official
result is **Mixed Results**: TPS 15,682 to 16,205 is neutral, mean block interval
improves 6.01%, and builder p99 worsens 21.94%. Accepted Engine execution worsens
from 22.36 to 23.41 microseconds per transaction in aggregate and in every pair;
reuse falls from 75.72% to 70.67% as conflicts increase. The default remains 128.
Each pair runs 512 first, so ordering may affect these descriptive comparisons.
All 6,667 observed payload statuses are `VALID`; audited shutdown tails are
excluded from the common-chain cohort. Win-only Slack correctly skips the result.

[Historical comparison 37136697134](https://github.com/tempoxyz/tempo/actions/runs/37136697134)
replays mainnet blocks 42,370,356–42,420,355 twice per arm against main `61c979a524`.
All 250,000 submissions, including warmup, are `VALID`. Mean latency regresses
0.24% and arithmetic mean gas throughput regresses 0.71%; Slack is skipped.
Each measured pass contains 10,160 transactions, with only four blocks reaching
five transactions. Retained logs provide no positive worker-reuse evidence;
the generated differential run supplies that coverage separately.

For a bounded scheduling diagnostic, the manual E2E workflow accepts
`profiling=samply-scheduling`. It forwards both `--per-cpu-threads` and
`--cswitch-markers` with 100 Hz stack sampling, records the runner profiler's version,
help and binary hash,
and disables Slack. These profiles may distinguish gaps following preempted
versus blocked switch-outs; they do not provide wakeup latency or blocking stacks.
Audit the actual marker schema and event loss before drawing conclusions. The
artifact includes a Bash/Nu command because the Derek bot does not expose these
options. Confirm performance separately with ordinary profiling settings.

Both the [1,000 Hz](https://github.com/tempoxyz/tempo/actions/runs/37113738991)
and [100 Hz](https://github.com/tempoxyz/tempo/actions/runs/37114793096) scheduling
captures lost events in every recorder. They cannot partition off-CPU time
reliably. The manual `profiling=kernel-scheduling` diagnostic instead adds one
15-second kernel trace per phase after a 20-second delay, filtering scheduler
switch and successful wakeup events for the two nodes' named Engine and builder
threads across all CPUs. It requires `run-pairs=1` and `duration>=60`, keeps
Samply at 100 Hz for scope identification, and forces Slack off. The preflight
checks the actual runner's perf executable and tracepoint formats before builds.
Raw traces, process identities, clock samples and recorder diagnostics are saved
with the workflow artifacts. Exact accounting requires a separate zero-loss,
thread-lifetime and accepted-block audit; the delay alone does not prove that
capture occurred during measured load. Builder work on fallback Tokio threads
is outside this named-thread trace's coverage.

[Kernel capture 37116887722](https://github.com/tempoxyz/tempo/actions/runs/37116887722)
records 138,465 scheduler events across both phases without recorded loss or
internal target-thread transition anomalies. Accepted, fully contained scopes
on baseline node A cover 12 Engine blocks (88,281 transactions) and 17 builder
blocks (145,703 transactions). Engine execution spends 71.63% scheduled,
10.78% runnable and 17.59% nonrunnable; builder transaction filling spends
55.20%, 33.23% and 11.57%, respectively. These are one-window diagnostics on a
32-logical-CPU runner, not an A/B performance result. Nonrunnable time does not
identify the wait primitive, and scheduled time includes interrupts or steal.
Raw records, recorder completion, process lifetimes, independent clock samples,
profile markers and accepted block hashes were reconciled. Perf can silently
skip a failed final loss-counter read, so this is evidence of no observed loss,
not an unconditional completeness guarantee.
The separate Samply recorder lost 41,136 events on baseline node A. Its surviving
scope markers match every retained accepted-block log inside the kernel capture;
its sampled CPU shares are not qualified by the kernel recorder's loss audit.

The offline decoder preserves numeric states from the saved tracepoint schema;
the runner's textual output renders some preemptions as ordinary runnable state.
It rejects unsupported binary layouts, truncation, loss and throttle records,
and positive recorded lost counters. Successful decoding alone does not qualify
scheduler accounting or accepted-block coverage. Keep its output ignored:

```sh
python3 benchmarks/parallel-execution/decode_scheduler_trace.py \
  --input /path/to/scheduler-baseline-1/perf.data \
  --preflight /path/to/scheduler-baseline-1/preflight.json \
  --output benchmark-artifacts/parallel-execution/scheduler-events.jsonl \
  --summary benchmark-artifacts/parallel-execution/scheduler-decode.json
```

Completed sender-reuse comparisons against main `61c979a524f9`:

| Target TPS | Sequential TPS | Feature TPS | Change | Workflow |
| --- | ---: | ---: | ---: | --- |
| 10,000 | 9,915 | 9,924 | +0.09%, neutral | [37029957596](https://github.com/tempoxyz/tempo/actions/runs/37029957596) |
| 25,000 | 17,502 | 14,634 | -16.39% | [37033132058](https://github.com/tempoxyz/tempo/actions/runs/37033132058) |
| 50,000 | 16,745 | 13,330 | -20.39% | [37027627722](https://github.com/tempoxyz/tempo/actions/runs/37027627722) |
| 75,000 | 16,869 | 12,202 | -27.67% | [37033133677](https://github.com/tempoxyz/tempo/actions/runs/37033133677) |

These are confirmed block-throughput figures. Target rate, actual submissions
and confirmed TPS differ; none establishes sustained 50k input. The 10k run is
input-limited and still regresses validator gas throughput by 27.74%. Raw sender
failures occur at 50k and 75k, and are distinct from included-transaction errors.
Compare paired results within a run; runners and profiling differ across runs.

[Historical replay 37025825306](https://github.com/tempoxyz/tempo/actions/runs/37025825306)
passes 5,000 mainnet blocks per pair (42,230,064–42,235,063; 1,232 transactions)
with workers confirmed active: 1,207 results reused and 25 conflicts per pass.
Canonical checks pass, but newPayload gas throughput regresses 14.93%. This is
sparse correctness coverage, not a capacity measurement.

[Expanded replay 37041568715](https://github.com/tempoxyz/tempo/actions/runs/37041568715)
completed 24,458 measured blocks (8,107 transactions) before the source RPC ran
out of blocks. All submitted payloads were valid; no paired comparison completed.
Replay now selects an older snapshot when needed to fit the source's available range.

[Prewarming reuse comparison 37035535006](https://github.com/tempoxyz/tempo/actions/runs/37035535006)
measures 15,334 baseline versus 14,298 feature TPS (-6.76%); builder gas
throughput falls 20.58% and validation throughput falls 34.20%. Only 12.42% of
builder candidates reuse prewarming; the rest conflict and execute again.
The recorded fatal engine-stop follows graceful shutdown. Workflow Slack
notifications were suppressed. This change has not demonstrated a net gain.

[Prefix-state comparison 37038805662](https://github.com/tempoxyz/tempo/actions/runs/37038805662)
measures 16,325 baseline versus 14,402 feature TPS (-11.78%); builder gas
throughput falls 27.46% and validation throughput falls 32.71%. Builder reuse
remains low at 13.63%; recording accepted-prefix hints takes 7.30% of sampled
builder CPU. Validator reuse is 76.88%. Slack notifications were suppressed.
Builder concurrency followed `--engine.prewarming-threads`, with twice that many
admitted candidates. These earlier runs used a separate Engine speculative pool.
Generated differential and real-node AA/Engine observer tests pass. Further
optimization remains in progress.

[Recovery/channel comparison 37041564867](https://github.com/tempoxyz/tempo/actions/runs/37041564867)
measures 15,984 baseline versus 13,747 feature TPS (-14.00%). Builder gas
throughput falls 26.09% and validator gas throughput falls 29.19%. Engine signature
crypto falls below 0.1% of sampled CPU, but 90.84% of builder conflicts concern
account/code/block metadata. A State-backed reproduction identified incorrect
empty-account hints for repeated AA senders.

[Account-lifecycle comparison 37046803134](https://github.com/tempoxyz/tempo/actions/runs/37046803134)
confirms zero metadata conflicts, with 81.76% builder reuse and 85.79% validator
reuse. It still loses: 14,297 baseline versus 13,237 feature TPS (-7.41%, below
the workflow's significance threshold), builder gas throughput -17.02%, and
validator gas throughput -33.83%. Both gas-throughput regressions are significant.
Remaining conflicts concern storage and 64 builder nonce-pointer predictions.
This is a correctness and reuse improvement, not an end-to-end performance win.

[Expanded replay 37046812230](https://github.com/tempoxyz/tempo/actions/runs/37046812230)
passes both 50,000-block pairs over 42,241,314–42,291,313 after selecting an older
snapshot within the source's available range. Historical validation throughput
falls 17.20%; p90 and p99 newPayload latency rise 14.78% and 20.00%. Both this
replay and the account-lifecycle e2e workflow suppress win-only Slack messages.

[Worker-isolation comparison 37052539277](https://github.com/tempoxyz/tempo/actions/runs/37052539277)
uses eight feature prewarming workers and measures 17,198 baseline versus 14,303
feature TPS (-16.83%); builder and validator gas throughput fall 26.12% and 34.38%.
Builder reuse is 85.95% and validator reuse is 85.78%, with storage conflicts only.
The workflow suppresses Slack. Cross-run differences do not isolate the effect
of changing the worker count.

[State-cache comparison 37055427310](https://github.com/tempoxyz/tempo/actions/runs/37055427310)
measures 12,032 baseline versus 11,011 feature TPS (-8.49%, neutral with wide
variance); builder and validator gas throughput fall 31.38% and 36.51%.
Both configurations have long block gaps. Builder validation still accounts
for 17.23% of sampled CPU despite fewer generic database reads. Local cache-read
improvements have not translated into a node win; Slack was suppressed.

[State-cache replay 37055435207](https://github.com/tempoxyz/tempo/actions/runs/37055435207)
validates all 250,000 submitted blocks, including warmup, with throughput down
16.84%. Of 12,476 nonempty measured blocks, 10,752 contain only one transaction.

[Singleton replay 37057293797](https://github.com/tempoxyz/tempo/actions/runs/37057293797)
skips worker dispatch for singleton lookahead. Against its own paired main
baseline, validation throughput falls 2.74%, p90 latency rises 1.25%, and p99
rises 8.01%. It still does not satisfy the on-win Slack gate. Different runners
and paired baselines prevent attributing the entire cross-run change to this edit.

[Engine-prewarming comparison 37065073109](https://github.com/tempoxyz/tempo/actions/runs/37065073109)
measures 13,755 baseline versus 13,929 feature TPS (+1.27%, neutral); builder and
validator gas throughput still fall 27.37% and 18.40%. Engine candidates are
available for 78.69% of canonical transactions, but only 9.37% of all transactions
are reused: stale storage reads dominate conflicts. Full execution after misses
or conflicts takes 41.74% of sampled Engine CPU. Builder reuse remains 85.88%.
This is not a win, and the workflow suppresses Slack.

[Engine-prewarming replay 37065079966](https://github.com/tempoxyz/tempo/actions/runs/37065079966)
validates all 250,000 submitted blocks, including warmup. Execution throughput
falls 2.26% and p99 latency rises 8.42%. Only 47 measured blocks per pass contain
at least five transactions, so historical coverage of the handoff is limited.

[Accepted-prefix comparison 37070029365](https://github.com/tempoxyz/tempo/actions/runs/37070029365)
raises Engine reuse to 60.00% of canonical transactions, but throughput falls
16,583 to 14,467 TPS (-12.76%); builder and validator gas throughput fall 25.46%
and 14.73%. Prefix updates and read validation consume visible ordered CPU.
The workflow suppresses Slack. Actual sender rates remain below 17k/s, but the
sender is closed-loop: its 50,000-pending cap repeatedly fills, throttling input
until transactions are included. The configured 50k/s is a ceiling, and lower
observed sender rates alone do not imply that this test is unsaturated.

[Accepted-prefix replay 37070034657](https://github.com/tempoxyz/tempo/actions/runs/37070034657)
validates all 250,000 submissions, with throughput down 2.73% and p99 up 7.76%.
Its measured range is 42,267,216–42,317,215, different from the preceding replay;
all four passes match 14,327 transactions. Only 25 blocks per pass meet the
five-transaction capture threshold. Slack is suppressed.

[Native-increment comparison 37077569936](https://github.com/tempoxyz/tempo/actions/runs/37077569936)
measures 15,374 baseline versus 14,737 feature TPS (-4.14%). Builder reuse reaches
96.76% and Engine reuse 68.24% of canonical transactions; native rebasing applies
to 10.92% and 9.84%, respectively. Builder and validator gas throughput still fall
24.63% and 15.46%, so Slack is suppressed. All 4,328 recorded feature payload
statuses are valid. High reuse has not yet produced an end-to-end win.

[Native-increment replay 37077572124](https://github.com/tempoxyz/tempo/actions/runs/37077572124)
validates all 250,000 submissions over the same measured range as the preceding
replay. All four passes match 14,327 transactions and 1,540,650,231 gas. Validation
throughput falls 2.53% and p99 latency rises 8.67%, suppressing Slack. Retained
logs cover 22 of 25 capture-eligible blocks per feature pass, with only 13
available candidates among 130 transactions; ordinary two-to-four-transaction
lookahead reuses 88.72%. This sparse sample provides limited Engine-capture
coverage and no observed native rebases.

[Changed-slot prefix comparison 37082990580](https://github.com/tempoxyz/tempo/actions/runs/37082990580)
measures 16,481 baseline versus 14,664 feature TPS (-11.02%); builder and validator
gas throughput fall 25.07% and 14.72%. All 4,354 recorded payload statuses are valid.
[Its replay 37082994464](https://github.com/tempoxyz/tempo/actions/runs/37082994464)
validates all 250,000 submissions, with matching measured heights, transactions
and gas; throughput falls 1.96% and p99 rises 8.87%. Win-only Slack is suppressed.

[Single-result-slot comparison 37083942894](https://github.com/tempoxyz/tempo/actions/runs/37083942894)
measures a statistically neutral TPS change of -5.69% with wide uncertainty;
builder and validator gas throughput fall 29.29% and 27.44%. Long sender and block
stalls affect both sides, limiting attribution to the handoff change. All 2,087
recorded payload statuses are valid, and Slack is suppressed. Commit, validation,
prefix updates and candidate handoff remain the largest ordered builder stages.

[State-commit comparison 37087370471](https://github.com/tempoxyz/tempo/actions/runs/37087370471)
measures 11,386 baseline versus 11,977 feature TPS (+5.19%, statistically neutral);
builder and validator gas throughput fall 25.39% and 18.89%. All 3,548 feature
payload statuses are valid. Builder reuse is 96.44% of attempted candidates and
Engine reuse is 68.10% of canonical transactions. Both sides have long block
gaps, and the workflow suppresses Slack. The optimized commit runs on both node
paths; commit, validation, prefix updates and handoff account for 16.33%, 16.67%,
10.79% and 9.27% of sampled builder CPU. Cross-run profile shares do not isolate
the optimization's effect, and this comparison still establishes no overall win.
Within aligned nonempty fills, baseline builder CPU is 16.92–17.24 microseconds
per transaction versus 10.14–10.58 for the feature, while fill elapsed time rises
from 22.62 to 35.84 microseconds after subtracting explicit empty-pool sleep.
This points to substantial off-CPU time in the feature. The cause is unresolved:
baseline uses sixteen prewarming workers, feature eight, and their transactions
and profile coverage differ.

The blocking builder diagnostics in `0ca637201` report readiness and cumulative pending
Condvar time, plus coordinator receive count and elapsed time. Result timing
includes mutex reacquisition after waking, but excludes initial mutex acquisition.
Source summaries also cover cancelled builds; result summaries require the normal
fill exit. A same-binary handoff diagnostic measures approximately 10 ns extra
per already-ready result; cross-thread pairs vary widely and do not establish
node overhead. That instrumentation left scheduling and admission unchanged.

[Builder-wait comparison 37091828345](https://github.com/tempoxyz/tempo/actions/runs/37091828345)
measures 15,890 baseline versus 15,053 feature TPS (-5.27%); builder and validator
gas throughput fall 25.08% and 21.31%. All 4,256 reported payload statuses are
valid, and the workflow suppresses Slack. Across the retained chains' 669 builds
containing pool transactions, pending-result waits consume 85.69 of 150.92 seconds
of fill time (56.78%); source receives consume another 4.46 seconds. About 14.95%
of selected handles were pending. These elapsed timers include scheduling and
call overhead; they are not pure off-CPU measurements. Seven transient locally
canonical blocks are excluded, including two containing 8,483 transactions.

The builder now probes only the already-selected result once. A pending or
contended slot falls back to ordinary execution in source order. Dropping the
consumer does not return capacity until its worker also finishes; abandoned
queued jobs skip per-job execution. Ready/pending/contended counters remain, with
zero result-wait time. Thirty-nine builder tests and fourteen node checks pass,
including fixed blocks produced by both builder modes and compared against
sequential roots, receipts and full execution output. The performance effect
is measured in [comparison 37094114130](https://github.com/tempoxyz/tempo/actions/runs/37094114130):
15,908 baseline versus 14,919 feature TPS (-6.2%), with builder and validator gas
throughput down 18.4% and 16.9%. The workflow suppresses Slack; removing the
result wait has not established an overall win. The retained chains contain
657 nonempty fills: result waits are zero, source receives consume 9.08 of
140.24 seconds. Builder reuse attempts amount to 75.59% of the 4,083,219 included
transactions; that counter can include attempts later rejected before inclusion.
All 4,237 reported payload statuses are valid.

The preceding comparison's first-pair Engine metrics report 15.92 seconds inside
transaction execution versus 0.29 seconds receiving transactions. Profile CPU
bounds leave at least 7.01 seconds of execution wall time unexplained by recorded
Engine CPU; they cannot identify the blocking call. Diagnostics now split
result-map and prefix-writer lock acquisition from hold time, with per-block
totals and unchanged validation, commit and lock behavior. The diagnostic passes
254 EVM/builder unit tests and fourteen node checks,
including sequential state-root, receipt and full-output comparisons for both
builder modes, TIP-20 transfers and expiring AA transactions.

[Lock-diagnostic comparison 37096389581](https://github.com/tempoxyz/tempo/actions/runs/37096389581)
measures 15,634 baseline versus 15,355 feature TPS (-1.78%, statistically neutral);
builder and validator gas throughput fall 18.47% and 18.52%. All 4,224 reported
payload statuses are valid, and win-only Slack is suppressed. Across 648 nonempty
blocks on the highest common retained chains, Engine lock acquisition consumes
1.69% of internal execution wall time; acquisition plus hold time consumes 8.80%.
Builder prefix acquisition and hold consume 0.82% and 5.92% of fill time; result
waits remain zero. These timers include scheduling and on-CPU work, and the Engine
denominator excludes parts of the official newPayload metric. Lock acquisition
does not explain most of the regression. The third pair has an additional empty
tail block without both nodes' retained canonical announcements; it is excluded.

[Worker-configuration comparison 37098730158](https://github.com/tempoxyz/tempo/actions/runs/37098730158)
compares `042ec0dc0` against itself with eight versus sixteen prewarming workers.
TPS rises from 15,121 to 16,313 (+7.88%), builder gas throughput rises 7.28%, and
validator throughput rises 14.00%. Builder p90 latency rises 3.52%, so win-only
Slack is suppressed. This configuration also doubles the then-current builder
window from sixteen to thirty-two candidates; it does not isolate worker count.
Builder pending results fall from 21.63% to 9.56%, while Engine reuse falls from
66.84% to 31.87%. Better throughput does not imply more whole-candidate reuse,
and this comparison does not establish a win against main.

[Provider-diagnostic comparison 37100288877](https://github.com/tempoxyz/tempo/actions/runs/37100288877)
compares `042ec0dc0` against main with sixteen prewarming workers and provider
timers on both sides. TPS falls from 17,104 to 16,035 (-6.25%); builder and validator
gas throughput fall 9.19% and 7.32%. Win-only Slack is suppressed. Matched first-pair
log and metric cohorts show provider elapsed time rising from 1.52 to 3.23
microseconds per transaction, chiefly storage reads, despite similar call counts.
Provider time accounts for 12.37% of feature Engine execution elapsed time. These
timers include cache work, I/O and scheduling; they do not identify the cause of
the increase or account for most total execution time. This instrumented run is
separate from the subsequent bounded-builder experiment.

[Bounded-builder comparison 37100753798](https://github.com/tempoxyz/tempo/actions/runs/37100753798)
compares `13e97e5be` against main with sixteen prewarming workers on both sides.
Builder gas throughput improves 3.07%, while validator throughput regresses 6.16%.
TPS changes from 15,510 to 15,290 (-1.42%, statistically neutral); win-only Slack
is suppressed for the mixed result. This supports retaining the builder candidate
provisionally, but does not isolate its change from the earlier implementation
or establish an overall node improvement.

[Isolated builder comparison 37103181238](https://github.com/tempoxyz/tempo/actions/runs/37103181238)
compares `042ec0dc0` against `13e97e5be`, fixing both sides at sixteen prewarming
workers, eight execution threads and batch size 128. The bounded builder window
and result quota improve builder gas throughput 11.79% and TPS from 15,843 to
16,533 (+4.36%). Validator gas throughput changes -1.40%, statistically neutral.
Block-time p90 rises 8.23% and validation p99 rises 13.55%, so the result remains
mixed and win-only Slack is suppressed. This isolates the builder improvement;
it does not establish a win against main.

[Capture diagnostic 37104562656](https://github.com/tempoxyz/tempo/actions/runs/37104562656)
compares eight versus sixteen prewarming workers at revision `46cb6f4f6`,
with builder and Engine windows both fixed at 128. Final capture counters cover
every eligible accepted block: admission beyond the Engine window rises from
1.32% to 58.85% of hook entries, while count and byte quotas reject zero results.
Validator gas throughput improves 17.36%, but block-time p99 rises 131.24%; the
instrumented result is mixed and Slack is suppressed. A wider window would
perform additional strict execution, so these counts do not predict a speedup.

[Capture-window comparison 37108485802](https://github.com/tempoxyz/tempo/actions/runs/37108485802)
compares windows 128 and 256 using the same verified `06f046cda` executable,
with sixteen prewarming workers and capture diagnostics disabled. The workflow
classifies block-time p90's 3.34% decrease as an improvement; TPS changes from
15,900 to 15,706 (-1.22%), statistically neutral, as are builder and validator
gas throughput. Its win-only Slack step succeeds. Exact Engine reuse rises
from 30.68% to 46.95% across the matched canonical cohorts, while execution
elapsed time per transaction falls only 1.91%. The default remains 128; this
configuration comparison establishes neither a throughput gain nor a win
against main.

[Capture-window comparison 37110497271](https://github.com/tempoxyz/tempo/actions/runs/37110497271)
compares windows 128 and 512 with that same executable and worker configuration.
TPS changes from 17,575 to 17,477 (-0.56%); every official performance axis is
statistically neutral, so win-only Slack is suppressed. Across 1,562 verified
canonical blocks and 9.72 million transactions, exact Engine reuse rises from
31.54% to 50.48%, while internal execution time per transaction falls only 2.03%.
The default remains 128 because increased reuse has not improved node throughput.

[Worker comparison 37118414748](https://github.com/tempoxyz/tempo/actions/runs/37118414748)
compares sixteen versus eight prewarming workers in the same `06f046cda`
executable, with execution threads eight and both windows 128. TPS changes from
16,901 to 16,797 (-0.62%, neutral), while builder and validator gas throughput
fall 5.72% and 12.51%. Some latency measures improve, but the official result is
mixed and win-only Slack is suppressed. Across 1,603 verified canonical blocks
and 9.32 million transactions, Engine reuse rises from 29.77% to 65.71%; internal
execution time per transaction nevertheless rises 18.48%. These descriptive
cohorts differ across phases, and every pair runs feature first. Retain sixteen
workers; increased reuse has not established faster execution.

[Proof-worker comparison 37120629626](https://github.com/tempoxyz/tempo/actions/runs/37120629626)
reduces both storage and account proof pools from 32 to 16 in the same executable,
with sixteen prewarming workers and otherwise unchanged settings. TPS rises from
16,699 to 17,450 (+4.50%, statistically neutral), while validator gas throughput
falls 5.42%. Builder p50, validator p99 and mean block time improve, but the
official result is mixed and win-only Slack is suppressed. All twelve processes'
actual pool counts are verified; 1,603 common canonical blocks contain 9.50 million
transactions, with all 7,354 observed payload statuses `VALID`. Every pair runs
feature first. Retain the existing proof-worker defaults; this comparison does
not establish a throughput gain or a win against main.

[Main comparison 37122789429](https://github.com/tempoxyz/tempo/actions/runs/37122789429)
compares latest main `61c979a52` with retained parallel executor `06f046cda`, using
sixteen prewarming workers in both and eight execution workers in the feature.
Three 90-second pairs at 50,000 offered TPS measure 17,253 versus 16,469 achieved
TPS (-4.54%, statistically neutral). Validator gas throughput falls 10.37% and
validator p50 rises 8.08%; builder p50 and p90 improve. The official result is mixed
and win-only Slack is suppressed. All 1,576 common canonical blocks contain
9.61 million transactions, all 7,239 observed payload statuses are `VALID`, and
all six terminal peer heads agree. These are peer acceptance checks within each
arm, not independent sequential receipt/root replay. Every pair runs feature
first. The validator regression remains unresolved; this is not a win against main.

[Current main comparison 37144723072](https://github.com/tempoxyz/tempo/actions/runs/37144723072)
compares `61c979a52` with `1c86a7ab5`, including bounded Engine dispatch and the
session borrow. Three 90-second pairs at 50,000 offered TPS achieve 14,433 versus
13,834 TPS (-4.15%, statistically neutral). Validator gas throughput falls 7.56%
and validator p90 rises 5.50%; builder p50 improves 2.61%. The official result is
mixed and win-only Slack is skipped. All six terminal peer heads agree, with
6,127 observed `VALID` statuses and no unexplained in-load errors. Accepted Engine
reuse is 76.40%, but this has not established a net improvement over main. Every
pair runs feature first; peer acceptance does not replace the separate sequential
receipt/root oracles.

[10k comparison 37147944604](https://github.com/tempoxyz/tempo/actions/runs/37147944604)
uses the same main and candidate at 10,000 offered TPS. Three 90-second pairs
deliver 9,909 versus 9,910 TPS, statistically neutral. The official result is
mixed: validator gas throughput falls 2.73% and validator p50 rises 5.29%, while
validator p99 improves 8.13%. All six terminal peer heads agree and all 7,646
observed payload statuses are `VALID`; seven errors follow explicit shutdown.
Win-only Slack correctly skips this result. This input-limited point does not
establish a throughput improvement or an independent sequential receipt/root check.

[25k comparison 37153166293](https://github.com/tempoxyz/tempo/actions/runs/37153166293)
uses the same commits and three 90-second pairs at 25,000 offered TPS. Achieved
TPS is 14,440 versus 14,103 (-2.33%, statistically neutral). Validator gas
throughput falls 7.89% and validator p50 rises 5.12%; builder p90 improves 6.01%.
The result is mixed and win-only Slack skips it. All six sender reports have
zero failures and match the common canonical transaction counts; all 6,340
observed payload statuses are `VALID`. Five terminal peer heads agree; the sixth
has one linked empty shutdown block. Losing siblings are excluded from accepted
costs. Offered rate exceeds achieved rate despite zero sender errors.

[75k comparison 37155408370](https://github.com/tempoxyz/tempo/actions/runs/37155408370)
uses the same commits and three 90-second pairs at 75,000 offered TPS. Achieved
TPS is 13,329 versus 13,666 (+2.53%, statistically neutral). Validator gas
throughput falls 10.05% and validator p50/p90/p99 rise 12.25%/10.93%/28.40%;
block-time p99 improves 28.38%. The result is mixed and win-only Slack skips it.
All six terminal peer heads agree and all 5,941 observed payload statuses are
`VALID`; eighteen errors follow explicit shutdown. Heavy sender failures occur
in every phase. One baseline has 3,751 more RPC acceptances than canonical
transactions, reconciled with additional failure events; individual outcomes
are unproven. This offered-load point does not demonstrate 75,000 delivered TPS.
All 952 accepted nonempty builds stop at the proposal time budget. No empty-pool
sleep is recorded for 456/464 baseline builds and 481/488 feature builds; other
waits remain included in wall time. Both arms use identical budgeting logic.

[Dispatch-lead comparison 37150430298](https://github.com/tempoxyz/tempo/actions/runs/37150430298)
compares `1c86a7ab5` with `ec0f4a6ea`, widening dispatch from 128 to 512 while
keeping capture and in-flight limits at 128. The official result is improvement:
builder p50 falls 2.03%; TPS rises from 13,144 to 13,891, statistically neutral.
On the official block cohort, after removing the first five blocks per run,
Engine reuse falls from 76.31% to 41.76%. Engine time rises 6.04% and foreground
root finishing falls 24.11%; their sum rises 1.04% per transaction, worsening
in every pair. These descriptive ratios differ from official metric means and
percentiles, which filter their own samples separately. The wider
lead is reverted because its root benefit is offset by lost reuse. All 6,157
observed payload statuses are `VALID`; this does not replace sequential oracles.
The workflow's on-win Slack step succeeds; it does not retain a message ID.

[Boxed-result comparison 37165703119](https://github.com/tempoxyz/tempo/actions/runs/37165703119)
compares `1c86a7ab5` with `7cedad7a4` in three 90-second pairs at 50,000 offered
TPS. The official result is improvement: block-interval p99 falls 34.06%, with no
significant regressions. Achieved TPS rises from 13,506 to 14,330, statistically
neutral. All 8,267,605 accepted transactions reconcile exactly with sender reports;
all six terminal peer heads agree and all 6,092 payload statuses are `VALID`.
Retained-result lock wait/hold fall from 0.715/0.461 to 0.143/0.109 microseconds
per accepted transaction, and Engine reuse rises from 76.44% to 80.51%. Total
Engine wall time on the official block cohort improves only 0.85% descriptively;
moving unboxing outside the lock explains part of the shorter hold interval.
Retain boxed results. This comparison is against the previous parallel executor,
not main, and does not establish 50,000 achieved TPS. The win-only Slack notifier
succeeds without retaining a delivery receipt.

[Main comparison 37168821638](https://github.com/tempoxyz/tempo/actions/runs/37168821638)
compares main `61c979a52` with `7cedad7a4` in three 90-second pairs at 50,000
offered TPS. The result is mixed: achieved TPS is 15,999 versus 16,285,
statistically neutral. Builder gas throughput improves 3.57%, but validator gas
throughput falls 6.51%, validation p50 rises 7.17%, and block-interval p90 rises
5.33%. Win-only Slack explicitly skips all notifications. The common chains
contain 9,071,192 transactions matching sender acceptances; all 6,775 recorded
payload statuses are `VALID`. Three one-peer empty tail blocks and one losing
nonempty sibling are excluded. On the official block cohort, Engine wall time
falls from 21.501 to 21.138 microseconds per transaction while root finishing
rises from 4.000 to 4.469; their sum rises 0.41%. These descriptive timings do
not replace the official metric statistics or establish an overall main win.

A local experiment made contended prefix reads fall back to the parent provider.
It preserved differential correctness but reduced eight-worker reuse from about
97% to 62–65%, lowering median throughput 31.74% across three paired million-
transaction runs. Sixteen-worker throughput also fell 15.99%. The experiment was
reverted; its patch and evidence remain in the ignored artifact directory.

An experiment using Alloy's fixed-key aliases for the private accepted-prefix
maps improved local million-transaction public-mix geometric-mean throughput
3.21% across three eight-worker pairs and 8.75% across two sixteen-worker pairs.
Individual gains vary substantially; all ten runs match sequential receipts
and state roots. The harness waits for worker results and uses in-memory state,
so these measurements do not establish a node throughput improvement.
The [isolated node comparison 37111463672](https://github.com/tempoxyz/tempo/actions/runs/37111463672)
regresses TPS from 16,550 to 15,449 (-6.65%) and block-time p99 by 248.48%; builder
and validator gas throughput remain statistically neutral. Win-only Slack is
suppressed. The map change was reverted; local gains did not survive the node
benchmark.

Skipping identical prefix metadata and bytecode clones also failed local timing:
geometric-mean throughput fell 1.59% across three eight-worker pairs and 0.93%
across two sixteen-worker pairs. All ten million-transaction differential runs
passed. The experiment was reverted before a node benchmark or source commit.

Batching four Engine prefix publications in ordered, bounded buffers also failed
its local gate: median publication cost rose 8.24% across five pairs with sixteen
EVM workers. Nine boundary tests and every final-prefix comparison passed. These
short trials replay accepted T14 TIP-20/AA outputs, with only the final test crate
optimized; they do not measure node TPS. The prototype remains an ignored artifact
and is not integrated.

A compact read-record prototype reduced each inline record from 152 to 120 bytes.
Eight-worker geometric-mean throughput rose 3.53%, with mixed individual pairs,
but both sixteen-worker pairs regressed (6.68% overall). All ten million-transaction
receipt/root oracles, 279 unit tests and fourteen node integration tests passed.
The prototype was reverted before committing or dispatching a node comparison.

A prototype retained the authoritative account borrow across cold storage reads.
Across three local 100k-transaction TIP-20/AA pairs, throughput changed +0.81% at
eight workers and -0.92% at sixteen, with mixed pairs. All six receipt/root oracles
and 235 EVM tests passed. Only the final test crate was optimized; these are not
node throughput measurements. The production change was reverted, retaining two
provider-order and cache-equivalence tests, which also pass on the restored code.

A diagnostic over 10k–100k public-mix transactions finds that 6.08–7.95% of
recorded reads match previously written storage after excluding predicted nonce
pointers. Read-time provenance and intervening generations remain unchecked.
This does not bound the share
of validation time. Separate instrumented local runs measure 0.93–1.36 microseconds
per ordered validation, including fee/native rebasing; all receipt/root oracles
pass. These are in-memory diagnostics, not node performance results. The temporary
probes were removed; a broader versioning design still needs node cost evidence.

[Stage diagnostic 37125841828](https://github.com/tempoxyz/tempo/actions/runs/37125841828)
uses identical `29ae49200` binaries and settings in both arms, with timers enabled.
The audit covers 570 common canonical blocks and 2.98 million transactions;
all 2,606 observed payload statuses are `VALID`. On accepted nonempty Engine
blocks, ordered validation consumes 4.36% of internal execution elapsed time,
ordinary execution 54.32%, commits 8.58%, and prefix publication 9.02%.
These wall times include descheduling and exclude other execution stages.
Engine reuse is 33.14–33.53%; builder validation costs about 3.17 microseconds per
included transaction versus 1.01 in Engine validation. Nine completed builds
outside the common chains are excluded; all eight `ERROR` log records follow
explicit shutdown. This diagnostic does not establish a performance improvement;
Slack is disabled. The low Engine validation share favors testing worker and
prefix-publication costs before adding validation shortcuts.

[Nonce-hint comparison 37128598935](https://github.com/tempoxyz/tempo/actions/runs/37128598935)
isolates Engine expiring-nonce storage-hint omission (`29ae49200` versus
`b4719cec6`). Three pairs at 50k offered TPS classify as **No Difference**:
TPS is 15,387 versus 15,230 (-1.02%) and validator gas throughput changes +1.43%;
all official axes are neutral and win-only Slack is skipped. Across 1,454 accepted
common-chain blocks and 8.76 million transactions, aggregate Engine prefix hold
falls from 1.887 to 1.400 microseconds per transaction, consistently lower in all
three pairs. These different accepted workloads measure wall time, including
descheduling, and do not isolate nonce-only CPU cost or establish a throughput
gain. All 6,685 payload statuses are `VALID`; seven errors follow explicit shutdown,
and three unfinished next-child builds at shutdown are excluded from accepted work.

[Lock-diagnostic replay 37096394462](https://github.com/tempoxyz/tempo/actions/runs/37096394462)
measures 29.483 versus 28.421 Mgas/s (-3.60%), with p99 newPayload latency rising
from 1.444 to 1.571 ms (+8.80%). All 250,000 submissions are valid; all four
passes match measured heights 42,292,723–42,342,722, 12,508 transactions and
1,567,389,432 gas. Only twelve measured blocks per pass qualify for Engine capture;
both feature passes retain this complete cohort but reuse just two of its seventy
transactions. Rotated logs omit some earlier measured blocks, limiting aggregate
reuse analysis. This is the same sparse range as
[state-commit replay 37087375235](https://github.com/tempoxyz/tempo/actions/runs/37087375235),
which also regressed. Win-only Slack is suppressed; historical replay has not
established a performance improvement against main.

[Small-batch replay 37110030307](https://github.com/tempoxyz/tempo/actions/runs/37110030307)
isolates the five-transaction scheduling threshold (`46cb6f4f6` versus `f1b7b081f`).
All 250,000 submissions are valid; four measured passes match 50,000 blocks,
12,269 transactions and 1,525,956,457 gas. Official mean newPayload latency falls
1.27%, p99 falls 12.12%, and mean Mgas/s rises 4.31%, with no classified regression;
the win-only Slack posting step succeeds. The affected two-to-four-transaction
cohort has 19.66% lower mean latency. This supports retaining the threshold,
but does not establish a dense-workload gain or a win against main.
