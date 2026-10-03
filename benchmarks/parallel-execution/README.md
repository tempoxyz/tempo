# Speculative execution benchmarks

Experimental and disabled by default. Completed GitHub saturation benchmarks
still regress against sequential execution; this work has not demonstrated that
execution is no longer the node's bottleneck. The implementation targets current
main (Tempo 1.14, Reth 2.7, revm 43), with ordered read validation and replay.

Engine payload validation now consumes strict results from its existing
prewarming workers when available, and executes ordered misses directly.
Workers receive advisory state hints only from accepted block commits; discarded
execution results never advance those hints. The handoff retains at most 128
completed results and 32 MiB of estimated result payload, with the block's
accepted-state hints retained separately. The estimate is not an allocator/RSS
bound. Small blocks, disabled prewarming and
BAL payloads retain the regular scheduler. Engine prewarming concurrency follows
`--engine.prewarming-threads`; the regular pool follows `--execution.threads`.
Typed block executors use authoritative State-cache validation, with received
BALs retaining ordinary database validation.
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
This mode always includes a sequential receipt/root comparison. It models the
ordered reuse path with an in-memory provider and a standard thread queue;
it excludes the node's provider I/O, shared Rayon pool, pool coordinator, bundle
transitions and state hooks. Regular scheduler tuning switches are unsupported
in this mode. Results before the switch from `CacheDB` commits to `State` also
used different account-deletion rules and are not comparable throughput figures.

A final paired 1,000,000-transaction T14 diagnostic with eight workers measures
155,245 TPS with generic validation versus 168,645 with State-cache validation
(+8.63%), with matching sequential receipts and roots. This is an in-memory
result; the node benchmark remains the performance gate.

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
Builder concurrency follows `--engine.prewarming-threads`, with twice that many
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
