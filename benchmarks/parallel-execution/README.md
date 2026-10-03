# Speculative execution benchmarks

Experimental and disabled by default. Completed GitHub saturation benchmarks
still regress against sequential execution; this work has not demonstrated that
execution is no longer the node's bottleneck. The implementation targets current
main (Tempo 1.14, Reth 2.7, revm 43), with ordered read validation and replay.

Engine payload validation now consumes strict results from its existing
prewarming workers when available, and executes ordered misses directly.
Workers receive advisory state hints only from accepted block commits; discarded
execution results never advance those hints. The handoff defaults to at most 128
completed results; `--execution.capture-window` also permits 256 or 512 for
controlled comparisons. It changes only Engine admission and retention, with
the same 32 MiB limit on estimated result payload and the block's
accepted-state hints retained separately. The estimate is not an allocator/RSS
bound. Small blocks, disabled prewarming and
BAL payloads retain the regular scheduler. Engine prewarming concurrency follows
`--engine.prewarming-threads`; the regular pool follows `--execution.threads`.
Typed block executors use authoritative State-cache validation, with received
BALs retaining ordinary database validation.
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
match finalized headers, transaction bodies and full receipts for blocks 8–170:
163 dense blocks containing 1,573,044 transactions. Each block has a producer
execution and fresh opposite-peer Engine execution followed by `VALID`.
The parallel peer builds 89 blocks and validates 74; its included builder reuse
is at least 806,336 transactions, and Engine reuse is exactly 258,154.
Both peers use sixteen prewarming workers, with execution threads eight versus
zero. This is a correctness result for the paid expiring-AA public mix, not a
comparison against unmodified main or a sustained 50,000 TPS result.

[Generated validation 37108470757](https://github.com/tempoxyz/tempo/actions/runs/37108470757)
passes on `06f046cda` with capture window 512. Live checks match finalized roots,
headers, transaction bodies and full receipts for 171 blocks containing
1,710,254 transactions. Every block exceeds the window; both peers produce
blocks, and every block has fresh opposite-peer Engine execution followed by
`VALID`. The parallel peer includes at least 911,939 builder reuses and exactly
435,180 Engine reuses. Both peers launch the same verified binary, with eight
versus zero execution threads and sixteen prewarming workers. Archived receipt
digests and 855 independently checked log records support the live verification;
the archive does not contain the complete receipt bodies. This correctness run
does not establish a performance improvement.

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

The workflow's builder gas throughput averages `gas_used / elapsed` over full
payload builds. It includes setup, transaction selection, waits and finalization;
it is not execution-only throughput. CPU profile shares describe sampled work
and must be combined with elapsed-time measurements before identifying a bottleneck.

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
