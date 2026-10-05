# Speculative execution benchmarks

Experimental and disabled by default. Official node benchmarks have not shown a
consistent net gain over sequential execution or sustained 50,000 TPS. High reuse
and faster local execution do not establish that execution is no longer the
node's bottleneck. Compare pinned revisions under the same workload and controls.

## Artifact policy

Keep reusable scripts and this operational reference tracked. Put generated JSON,
TSV/CSV, logs, profiles, receipts, rejected patches, plans and research notes in
ignored `benchmark-artifacts/parallel-execution/` or `bench-results/`. These local
directories may be symlinks to external storage; preserve their relative paths.
Never force-add evidence. Workflow artifacts are the remote source of raw results.
The previous detailed diary is archived locally as
`benchmark-artifacts/parallel-execution/research-notes-readme-a8b560e0a.md`.

## Execution controls and limits

| Node option | Meaning |
| --- | --- |
| `--execution.threads 0` | Disable speculation; positive values set the regular speculative pool size. |
| `--execution.batch-size 128` | Generic batch size and speculative builder admission window; builder admission is capped at 128. |
| `--engine.prewarming-threads 16` | Existing Engine and builder prewarming worker count. |
| `--execution.capture-window 128` | Engine lead, in-flight and retained-result count bounds; choices are 128, 256 and 512. Independent of builder batch size. |
| `--execution.capture-diagnostics` | Optional Engine admission/publication/consumption counters; defaults off. |
| `--execution.stage-diagnostics` | Optional ordered validation, ordinary execution and commit wall timers; defaults off. |

Engine consumes strict prewarming results when ready and executes ordered misses
or conflicts directly. Canonical transaction commits publish advisory prefix
hints; discarded candidates do not. Every reused result still passes ordered
read validation. Typed executors can validate through authoritative State caches;
received BALs retain ordinary database validation. Inspector use, custom fee
managers, changed execution environments and nonstandard journal warming retain
ordinary execution. Small blocks and BALs retain standard prewarming scheduling;
automatic generic slices shorter than five transactions execute directly.

Engine captures reuse complete results after validation. A conflicting T14
capture executes the whole transaction again. The generic scheduler's call-body
cache is limited to pre-T7 execution and is not carried by Engine captures;
modern storage-credit accounting needs additional recording before that cache
can safely skip a body after fresh validation and fee processing.

Engine and builder each limit retained result payload estimates to 32 MiB.
These are not allocator/RSS limits: accepted-prefix hints, provider caches,
converted inputs, running workers and extracted results are outside the estimate.
Builder probes are ready-only and fall back on pending, contended or over-budget
results. Engine nonce hints remain predictions and never bypass validation.

T14 may rebase one certified custody increment from a successful single-call AA
channel open. Its whole-transaction observer excludes other target accesses;
checked arithmetic, the complete SSTORE gas class and all other dependencies must
match. Unsupported gas classes, authorization/multicall shapes or target warming
retain ordinary replay. `native_rebased` is separate from fee rebasing.

Diagnostic snapshots precede block acceptance. Match them to accepted payload
hashes and sessions; `session_drop` has final counters but can be absent at exit.
Stage timers include descheduling/errors, exclude several block stages, and are
neither CPU time nor total validation/build time. Confirm performance with
diagnostics disabled.

## Correctness

Run unit and real-node oracles with the repository's pinned toolchain:

```sh
cargo +1.98.1 test --release --locked -p tempo-evm --lib
cargo +1.98.1 test --release --locked -p tempo-payload-builder --lib
cargo +1.98.1 test --release --locked -p tempo-node --test it \
  'tip20::test_tip20_transfer::parallel'
```

The scheduled workflow has a separate manual generated-correctness mode:

```sh
gh workflow run bench-e2e-scheduled.yml --ref onbjerg/parallel-execution \
  -F sequential-peer=true -f ref='<candidate-sha>' -f capture-window=128
```

It uses the same candidate binary for speculative peer A and sequential peer B,
checks selected finalized header fields, roots, ordered transaction hashes and
full live receipt JSON, and requires producer/fresh opposite-peer Engine evidence
followed by `VALID`. Both producer roles must contain blocks larger than the
selected window, with positive included builder reuse and exact Engine reuse.
`verify_generated.py` validates the config and live cohort; missing evidence fails.
Shared changes such as State commit optimization need separate ordinary-State
oracles. This mode has no performance classification or Slack notification.
Archived receipt digests support the live check; they are not full receipt bodies.

For example, [boxed-result validation](https://github.com/tempoxyz/tempo/actions/runs/37164999238)
checks 187 blocks and 1,579,481 transactions using eight versus zero workers.
This establishes workload-specific correctness, not a comparison against main.

Historical database replay is read-only and requires retained parent state and
canonical receipts. Bounds are inclusive:

```sh
tempo parallel-replay --chain /path/to/genesis.json --datadir /path/to/node-data \
  --from 1000 --to 1100 --threads 8 --batch-size 128 \
  --output benchmark-artifacts/parallel-execution/replay.tsv
```

It compares execution/state deltas, stored receipts, gas, receipt roots and
canonical state roots. Execution timers exclude trie hashing and run sequential
first, so cache warmth can differ. Sparse history may provide little reuse coverage.

## In-memory performance screening

```sh
mkdir -p benchmark-artifacts/parallel-execution
TEMPO_BENCH_HARDFORK=T14 TEMPO_BENCH_COUNTS=10000,25000,50000,100000 \
  TEMPO_BENCH_WORKERS=0,8,16 \
  TEMPO_BENCH_WORKLOADS=tip20_paid_aa_expiring_public_mix \
  TEMPO_BENCH_PREWARMING=1 TEMPO_BENCH_STATE_VALIDATION=1 \
  TEMPO_BENCH_STATE_HOOK=1 TEMPO_BENCH_STATE_COMMIT=1 \
  cargo +1.98.1 test --release --locked -p tempo-evm execution_throughput \
  -- --ignored --nocapture \
  > benchmark-artifacts/parallel-execution/execution-throughput.log 2>&1
```

Counts are transactions per run, not offered TPS; zero workers selects sequential
execution. Every threaded run checks complete receipts and final trie roots
against ordinary sequential State commits. The T14 public mix models 80%
transfers, 5% mints and 15% MPP opens **by transaction count**, with existing
recipients, explicit pathUSD fees and expiring AA nonces. This differs from the
official gas-weighted preset. `tip20_paid_aa_expiring_multitoken` isolates transfers.

| Environment variable | Diagnostic control |
| --- | --- |
| `TEMPO_BENCH_BATCH_SIZE` | Regular speculative window. |
| `TEMPO_BENCH_PHASES=1` | Preparation, ordered execution and commit timings. |
| `TEMPO_BENCH_CONFLICTS=1` | Conflict-key counts; suppresses throughput/phase timing. |
| `TEMPO_BENCH_PREWARMING=1` | Persistent prewarming workers with a two-per-worker pending window. |
| `TEMPO_BENCH_PREWARMING_PREFIX=0` | Disable advisory prefix hints. |
| `TEMPO_BENCH_STATE_VALIDATION=1` | Authoritative State-cache validator instead of generic DB reads. |
| `TEMPO_BENCH_STATE_HOOK=1` | Include transitions and a no-op state hook. |
| `TEMPO_BENCH_STATE_COMMIT=1` | Optimized State commit; requires the state-hook mode. |

Use alternating pairs, report sequential-control drift and keep instrumentation
identical. Prewarming mode waits for selected results; it does not model ready-only
node probes, builder admission/quota, shared Rayon scheduling or provider I/O.
Signing, initial state setup, networking, consensus, trie hashing, bundle merging
and actual hook work are excluded. These are screening results, not node TPS.

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

Omitting `--output` creates a fresh ignored directory. Trials use fresh genesis,
loopback RPC, no peers, 100 funded accounts, 100 ms dev blocks and disabled
prewarming. Node and generator share the host. This differs from official large-state
measurements. `--profile-cpu` uses `pidstat` for per-thread samples.
`profile_node.py --node-binary /path/to/tempo` captures profiles with a
`pyroscope`-enabled binary; `summarize_profile.py DIRECTORY` summarizes them.
Redirect summaries to ignored storage. Profiling affects timing.

## Official measurements and interpretation

Use `.github/workflows/bench-e2e.yml` for paired nodes and `bench-replay.yml` for
history. Pin baseline, candidate, workflow and txgen revisions. The standard dense
comparison uses T14, three interleaved 90-second pairs, `preset=default` (public
mix), 1,000 senders, four tokens, 100 concurrent requests and a 100 GiB bloat input.
Keep roots enabled, normal prewarming and matched profiling/build settings. Typical
experimental args are `--execution.threads 8 --execution.batch-size 128
--engine.prewarming-threads 16 --execution.capture-window 128`; confirm CLI support
on each revision before comparing with main. `no-cache=true` forces fresh locked
binary builds, not fresh state bloat. Retain snapshot and actual binary provenance.

The current official harness interprets preset weights as target gas shares:
public mix targets 80% transfers, 5% mints and 15% MPP. Pin a txgen revision with
`--gas-weighted-mix` support (for example, `8ca73369c4b42ffffaf40066bbde8673141049c1`).
Setup is confirmed separately, then sampling calibrates item selection before
generation and every ten seconds. Check achieved `block_composition`, generation
failures and delivered load; calibration can pause generation. Count-weighted
historical runs and local screens are different workloads. This txgen revision
freezes sender elapsed time before collecting receipt metrics; setup and receipt
collection are separate from the measured workload clock.

Manual E2E `no-slack=false` means on-win: at least one significant improvement
and no significant regression. Neutral, losing and mixed results are suppressed.
A successful notification step does not prove delivery; inspect its explicit send
or skip result. A builder-only win is not a TPS win. No overall gain was established
by the retained candidate's [main comparison](https://github.com/tempoxyz/tempo/actions/runs/37168821638).

Separate offered TPS, actual submissions, RPC outcomes and accepted-chain TPS.
Audit six phase launches, source/build hashes, paired metrics, sender accounting,
canonical hash cohorts, peer heads, fresh `VALID` evidence and all node errors.
Use the renderer's exact measured/warmup cut; all-accepted log cohorts are different.
Builder gas throughput averages `gas_used / elapsed` over complete builds, including
selection, waits and finalization. Internal Engine/root wall times and sampled CPU
shares are different quantities. More reuse alone does not establish less total work.

Historical `verify-receipts=true` compares full RPC receipt arrays across live
passes and binds source hashes/header roots. It retains compressed digest ledgers,
with a 20-minute deadline per pass and a 50,000-block limit. These are correctness
runs, not performance measurements. Mainnet sparsity must be reported separately
from dense generated coverage.

## Profiling and cloud diagnostics

`profiling=samply-buffered` builds a pinned job-local Samply with larger perf
buffers, records build provenance and reports allocations and observed lost
events. It uses 100 Hz sampling and disables Slack. A zero lost-event count alone
does not prove complete CPU coverage, valid unwinding or lossless accounting.

`profiling=samply-scheduling` adds switch markers at 100 Hz and disables Slack.
Audit actual schema/loss before interpreting gaps; it supplies neither wakeup
latency nor blocking stacks. `profiling=kernel-scheduling` requires one pair and
at least 60 seconds: it adds a 15-second all-CPU trace after a 20-second delay,
with 100 Hz Samply for scope identity and Slack off. `scheduler_trace.py` provides
`preflight --output PATH` and bounded `capture` for two explicit node datadirs.

```sh
python3 benchmarks/parallel-execution/decode_scheduler_trace.py \
  --input /path/to/phase/perf.data --preflight /path/to/phase/preflight.json \
  --output benchmark-artifacts/parallel-execution/scheduler-events.jsonl \
  --summary benchmark-artifacts/parallel-execution/scheduler-decode.json
```

Successful decoding alone does not establish lossless accounting or load overlap.
Bind thread lifetimes, clocks and accepted scopes; named builder captures omit
fallback Tokio threads. Keep sampled CPU and scheduler states separate from
elapsed-time attribution; they do not identify the wait primitive or prove a cause.

`bench-e2e-multi-region.yml` supports two GCP `c4d-standard-48-lssd` validators and
a separate generator. Verify actual topology, resource limits and live ELF/build
identity; its controls/reporting differ from bare metal and cloud Slack stays off.
Teardown checks exact resource identities and fresh empty inventories. Lost-runner
recovery uses the same workflow with `cloud=gcp-cleanup` and
`baseline=bench-e2e-multi-region-<run-id>-<attempt>`; the target run must be completed.
Recovery validates ownership labels/IDs and leaves shared infrastructure untouched.
