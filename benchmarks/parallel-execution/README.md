# Speculative execution benchmarks

Experimental and disabled by default. Completed GitHub saturation benchmarks
still regress against sequential execution; this work has not demonstrated that
execution is no longer the node's bottleneck. The implementation targets current
main (Tempo 1.14, Reth 2.7, revm 43), with ordered read validation and replay.

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
against sequential execution. The funded multi-token fixture uses 1,000 senders,
four TIP-20 transfer tokens, explicit pathUSD fees and expiring AA nonces (T12+).
`TEMPO_BENCH_BATCH_SIZE` sets the speculative window, and
`TEMPO_BENCH_PHASES=1` adds preparation, ordered-execution and commit timings.
Compare equally instrumented runs. Signing, initial state setup, disk I/O,
networking, consensus and trie hashing are excluded from execution throughput.

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

[Prewarming reuse comparison 37035535006](https://github.com/tempoxyz/tempo/actions/runs/37035535006)
measures 15,334 baseline versus 14,298 feature TPS (-6.76%); builder gas
throughput falls 20.58% and validation throughput falls 34.20%. Only 12.42% of
builder candidates reuse prewarming; the rest conflict and execute again.
The recorded fatal engine-stop follows graceful shutdown. Workflow Slack
notifications were suppressed. This change has not demonstrated a net gain.

[Prefix-state comparison 37038805662](https://github.com/tempoxyz/tempo/actions/runs/37038805662)
measures `43dd0364e236` against the same main at a 50k target; results are pending.
Workers consult advisory values from the accepted prefix, and exact read
validation still gates reuse. Generated differential tests compare outcomes,
receipts, roots and nonce-order changes; real-node AA and Engine observer tests
pass. Builder concurrency follows `--engine.prewarming-threads`, with twice that
many admitted candidates; `--execution.threads` controls the separate Engine
execution pool. Further optimization remains in progress.
