# Block lifecycle capture

Select **profiling: lifecycle** in the `bench-e2e` workflow. This runs the feature
revision on both local validators and uploads the `block-lifecycle` artifact.
Extract the artifact and open a phase's `index.html`. The viewer works offline.
Open `perfetto-p50.json`, `perfetto-p90.json` or `perfetto-p99.json` in
[Perfetto](https://ui.perfetto.dev) for a small trace of an actual representative
block. The compact index links every individual block/attempt page and focused
Perfetto file. Standalone context pages/traces contain every span, frame transfer
and milestone, including unassociated work, in chunks of at most 10,000 records.
Chunks preserve original intervals without clipping; their time ranges can overlap.
The viewer paginates operations in groups of 500. Complete raw captures and
`lifecycle.json` remain available; a monolithic Perfetto export is optional.

The feature revision must include the pinned Reth capture layer and Commonware
instrumentation. To run directly, use `--lifecycle --run-side feature`. Other
profilers and ValScope publication are disabled. The workflow uploads only the
lifecycle directory, not ordinary benchmark logs/reports.

For an optimization comparison, set both `baseline` and `feature` to explicit
instrumented revisions and use `run-pairs: 1` (feature, then baseline).
This runs both revisions sequentially on the same physical runner, restoring
the snapshot before each phase. Each phase has its own first-backpressure cutoff
and pruned artifact directory. Without an explicit baseline, lifecycle mode
continues to run only the feature revision. Both revisions must contain the
capture instrumentation; an ordinary uninstrumented baseline is unsuitable.
The harness checkout is pinned to the workflow dispatch revision.
`run-pairs: 2` counterbalances order as feature/baseline/baseline/feature;
snapshot restoration alone does not equalize OS or device caches.

Lifecycle mode requires 64 GiB of available workspace/root space before builds
and 48 GiB before each capture. It builds sequentially and removes only disposable
build intermediates after verifying each executable. These checks fail early on
undersized runners; published capture directories and shared caches are retained.

Separate workflow jobs can land on different machines even with identical
runner labels. Their operation counts can help identify work changes, but do
not treat cross-runner timing differences as controlled optimization speedups.

## Reduced instrumentation for optimization comparisons

Select **profiling: lifecycle-milestones**, or pass
`--lifecycle --lifecycle-detail milestones` directly, to retain coarse block and
attempt milestones plus account/storage proof-worker identities and CPU totals,
and cold execution-overlay resolution scopes,
while disabling detailed proof, storage, transport and poll
recording at the subscriber. The node reads `TEMPO_LIFECYCLE_DETAIL=milestones`;
the default is `full`. Both revisions must support the requested detail mode.
The harness checks recorder headers and rejects a silent fallback to full detail,
unknown detail values or mixed modes across validators.

This mode keeps the same source-timestamped first-backpressure stop, raw artifact
pruning, pseudonyms, loss counters, telemetry suppression and private-only upload
path. Reports explicitly identify the reduced coverage. Active wall time is
unmeasured, not zero. Retained identity scopes describe tracing reference
lifetimes; coarse phase durations come from milestones. Operation-completion
events are disabled here because wrappers around excluded spans may otherwise
refer to a retained ancestor. Full captures retain their existing completion
semantics.

Use **profiling: lifecycle-compare-detail** (or
`--lifecycle --lifecycle-detail compare`) with `run-pairs: 2` to run all eight
phases in one job: full feature/baseline, milestones feature/baseline, milestones
baseline/feature, full baseline/feature. Each phase restores snapshots and has an
independent cutoff. Both variant order and detail order are counterbalanced;
explicit side metadata selects baseline/feature args even with mode-prefixed
phase names. Use the same milestone-capable binary for both settings of a proof
parameter to isolate its effect at each detail level. Reduced recording still has overhead, and
changing capture mode can change scheduling: it is not a zero-observer baseline.
Use full detail again when diagnosing a particular stall.

## Stop at first backpressure

Lifecycle runs stop the load process group when either validator first enters
engine **persistence backpressure**. The marker is emitted in Reth immediately
before waiting on persistence, timestamped on the shared monotonic clock and
flushed to the capture file. A watcher checks both streams every 50 ms; the
cutoff uses the source timestamp, not the later detection or shutdown time.
An intentional stop still runs validator shutdown and artifact generation.

The upload directory receives only pruned copies of the captures. Raw records
at or after the earliest marker on either validator are removed before report
construction, including late span fields and finalization markers. Aggregate
envelopes crossing the cutoff are omitted because their call totals cannot be
split accurately. Their omission count appears in capture coverage. Span
portions before the cutoff remain visible with a `cutoff` label; these do not
claim a completed operation. Only blocks finalized strictly before the cutoff
can enter p50/p90/p99. If none qualify, the artifacts remain available but no
percentiles are claimed.

The cutoff and capture-integrity metadata are retained in `window.json` and
footers. No post-backpressure performance data is uploaded, including in the
JSONL files. Temporary full captures live outside the artifact directory and
are deleted after packaging. If there is no backpressure, the configured
duration remains the normal limit. Startup backpressure detected before load
launch skips the load and yields no load-window percentile samples.

## Repair or regenerate an existing Perfetto export

The old exporter created one thread track per span, which could overwhelm the
Perfetto UI. With the latest PR checkout, regenerate from the `lifecycle.json`
you already downloaded; there is no need to rebuild the node or rerun the bench:

```sh
python3 contrib/bench/lifecycle/report_package.py report/lifecycle.json --out report
```

To also generate the potentially very large full Perfetto file:

```sh
python3 contrib/bench/lifecycle/perfetto.py report/lifecycle.json --out report --full
```

For any individual report-local block number:

```sh
python3 contrib/bench/lifecycle/perfetto.py report/lifecycle.json --out report --block 200
```

Choose **Open trace file** in Perfetto and select the newly generated JSON file.
Start with a percentile file for a focused view. Full and focused exports use the
same capture clock. Packaged focused files contain operations attributed to that
block, causal ancestors labeled separately, its milestones, and explicitly labeled frame transfers overlapping its
proposal-to-finalization window; context frames do not acquire a block identity.

Visual lanes are reused by validator, subsystem and interval kind. Their count
is bounded by simultaneous intervals, not the total number of operations. Each
lane has non-overlapping intervals, so crossing async operations remain intact
without being misrepresented as a synchronous call stack. Lane names explicitly
say `virtual`: they represent elapsed wall time, not real threads or CPU usage.
Original span/parent IDs and the creation-thread ordinal remain inspectable as
arguments. Aggregate envelopes have separate tracks and retain their call counts
and summed call time; their envelopes are not continuous execution.

## Population and endpoints

A complete block runs from proposal handling start to the first accepted
finalization certificate on either captured validator. This endpoint is consensus
finalization, not later execution-layer persistence/FCU completion. Subsequent
operations remain visible. The p50/p90/p99 buttons select actual blocks by
nearest rank in this duration distribution, never a combination of unrelated
stage percentiles. The first five complete blocks are warmup; both endpoints
must also lie inside the recorded load window.

Incomplete blocks and attempts remain visible but do not enter the population.
Unassociated attempts have selectable run-local IDs and explicit outcomes:
cancelled, failed, incomplete at cutoff/shutdown, or unexplained. A proposal can
be cancelled before a block exists; that is not itself event loss. Payload IDs
link detached work to an attempt only when the mapping is unambiguous.
Event loss, malformed input, I/O errors, or a missing footer disable percentile
selection. Sample count is shown; a small-sample p99 is descriptive.

## Coverage and interpretation

Captured work includes proposal/payload handoff, builder phases, roots, encoding,
construction, persistence, pacing, Marshal/cache/archive/broadcast, encrypted
framing and codec work, sequential/BAL replay, receipts/merging, prewarm, overlays,
cache updates, root waits, persistence, voting and certificate handling.

Marshal message spans carry enqueue/dequeue markers: `marshal.queue_wait`
measures time before the actor accepts the message. Storage scopes distinguish
archive/journal sync initiation, waiting for prior syncs, buffered writes, blocking
pool queue delay and filesystem sync. Engine persistence exposes batch heights
and counts, provider acquisition, per-block state writes, hashed state/trie/history
updates, static-file/RocksDB work, MDBX commit and BAL flush. Cache scopes separate
update-lock acquisition, insertion, validation waiting and state-root completion.
These are nested intervals; their durations must not be summed indiscriminately.

Matching encrypted authentication-tag digests join individual send/receive frames,
including batched writes. No message bytes are retained. Transfer spans cover
pre-socket encryption completion to ciphertext receipt, not pure wire latency.

Existing spans are retained alongside added scopes. Five high-frequency scopes
(`execution_overlay`, `state_trie_overlay`, `database_provider_ro`, account and
storage proof calculations) retain every call count and elapsed time as an
aggregate under their enclosing operation. Dashed bars show the first/last-call
range; that range is not continuous work. Nested or concurrent call totals must
not be added to block wall time. No calls are sampled out. The report lists observed
operations and missing milestones. Async durations include waits; enter/exit
intervals are active wall time, not CPU time. Overlapping background work is
labeled temporal context, not causality. Kernel scheduling, NIC timestamps and
per-opcode EVM tracing are outside this capture. Both validators share the host's
monotonic clock; multi-host clock synchronization is not implemented here.

## Privacy

The subscriber exports static operation names and allowlisted numeric fields.
Arbitrary messages, debug arguments, errors, transaction contents, account
addresses, peer keys, IPs, hostnames, URLs, paths and credentials are discarded.
Block/payload/frame references are pseudonymized before writing with a fresh
32-byte per-phase key. That shared key lives outside the artifacts, has mode
0600, and is removed after node shutdown. The report replaces tokens with local
block ordinals.

The layer has an independent filter. Lifecycle events are disabled in ordinary
Reth log filters. Raw node stdout/file logs are disabled for these phases; OTLP,
ClickHouse, VictoriaMetrics and other profiler exports are suppressed. The queue
is bounded and nonblocking; loss invalidates completeness. Artifacts retain
benchmark timing, sizes/counts and block heights, not production identities.

## Validation

Run `python3 -m unittest discover -s contrib/bench/lifecycle -p 'test_*.py'` for
late block association, percentile selection, warmup, incomplete attempts, loss
handling and portable exports. The Reth capture tests check field rejection and
source-side pseudonymization. Consensus, durability and wire behavior are unchanged.

## Branch structure and remaining precision

Tempo owns the markers, harness and viewer. The pinned [Reth fork](https://github.com/joshieDo/reth/tree/joshie/bench-e2e-lifecycle) owns the source filter and execution/storage probes; the pinned [Commonware fork](https://github.com/joshieDo/monorepo/tree/joshie/bench-e2e-lifecycle) owns consensus and transport probes. Both forks start from the exact dependency revision used by Tempo.

The acceptance pass is a capture-quality check: two clean footers, no event loss,
a nonempty load-window population, consistent cross-validator milestones, and
visible build, replay, transport and persistence operations. It does not diagnose
performance. Per-block operations use explicit digest/payload association and
parentage. A frame pair proves a transport transfer but is not yet joined to an
application block across all queue boundaries; those transfers remain explicitly
labeled context. Broad parent spans also include uninstrumented work. Neither
blank time nor a broad span is claimed to be a fully explained CPU interval.

Closing those remaining gaps requires propagating a local message envelope ID
through network fanout and batching, transport queue enqueue/dequeue markers, and scheduler/off-CPU
profiling if kernel attribution is needed. Such IDs must remain source-filtered
and must not alter network messages. Use this draft's coverage inventory to
verify those additions before beginning the separate investigation phase.

### Operation completion and reference lifetimes

`operation_completed` and `operation_abandoned` markers delimit instrumented
operations independently of tracing references retained by detached children.
The report preserves causal parent IDs even when children outlive the operation.
An unmarked scope is labeled `span_lifetime`; its close timestamp is not proof
that the function ran or waited until that time. A last poll exit is never used
as completion. Active wall time is not CPU time. Completion/cancellation markers
at or after first backpressure are pruned with every other timed record.


Execution totals also report the synchronous transaction loop's elapsed wall time
(`execution_loop_ns`) and, on Linux when both resource samples succeed, its
execution-thread user+system CPU time (`execution_thread_cpu_ns`). The numeric
`execution_cpu_measured` flag is 1 for a measured value (including zero), or 0
with the CPU field absent when unavailable. Older captures show **unmeasured**.
At most two thread-bound `getrusage(RUSAGE_THREAD)` samples bracket each completed
loop when the existing `lifecycle` INFO tracing gate is enabled; other subscribers
can also enable that gate. There is no per-transaction CPU syscall. An early error
keeps the existing behavior of emitting no totals and takes only the start sample.
CPU nanoseconds are derived from microsecond-resolution counters. Sampling
endpoints differ slightly, so the viewer preserves wall and CPU separately and
does not compute or clamp an apparent off-CPU residual.

The loop includes transaction-iterator waits, EVM execution, receipt cloning and
sending, and same-thread bookkeeping/observer overhead. It excludes block
initialization, pre-execution changes, finalization and other threads (including
recovery, prewarming, proof and receipt-root workers). Existing `execution_ns`
is just the summed EVM transaction calls and is **not** the matching wall scope
for this CPU measurement. Local proposal builds and the parallel BAL replay path
do not emit these loop totals. A wall/CPU gap can indicate time this thread was
not executing, but does not identify scheduler, kernel or I/O causes.

Supplemental execution-loop resources reuse those same two thread snapshots,
without extra or per-transaction syscalls. `execution_resources_measured` is 1
when all six optional deltas are available, or 0 with their fields omitted when
unsupported or sampling fails. Older CPU-only captures show resource counters
as **unmeasured**. Measured zero is preserved. Fields are:

- `execution_voluntary_context_switches` and `execution_involuntary_context_switches`.
- `execution_minor_page_faults` and `execution_major_page_faults`.
- `execution_block_input_operations` and `execution_block_output_operations`:
  OS-reported filesystem input/output operation counts, not blockchain block
  counts, bytes, or counts of every read/write syscall.

These are deltas on the same execution thread and loop interval as the CPU
measurement; they exclude other workers and block initialization/finalization.
They count occurrences, not elapsed wait time or exact switch/fault timestamps.
A voluntary switch does not identify a specific blocking reason, and the counters
alone do not prove what caused an elapsed stall or how long I/O took. Several
causes can coexist. CPU values and wall-clock boundaries are unchanged.

## Proof-worker CPU accounting

Full and milestone captures can report current-thread user+system CPU and elapsed wall time
for each completed account/storage proof-worker invocation. The recorder takes
two resource samples around `worker.run()`, never per proof job. Receive waits
and teardown are within that interval; worker construction and error forwarding
are outside it. Sampling requires a lifecycle capture file, supported full or
milestone detail, and a build with metrics enabled. Milestone mode retains only
the exact `storage_worker` and `account_worker` identity scopes and their totals;
it still omits worker polls, jobs and detailed proof operations. Retained worker
spans anchor explicit event parents even when another subscriber enables excluded
intermediate spans. Their span lifetimes are context, not measured active work.

Older milestone captures have no worker totals. Missing completions remain
unmeasured; unsupported platforms or failed resource samples emit unavailable
CPU rather than zero. These two samples per worker have overhead and are held
identical on both sides of an optimization comparison. Comparing the same binary
in full and milestone modes can estimate the effect of detailed instrumentation
on worker CPU, but reduced mode still has observer cost and may change scheduling.

The block viewer groups recorded completions by validator and proof type,
retaining each completion in `proof_worker_totals` with its anonymous span ID.
It shows measured/unavailable/failed counts and sums measured worker CPU. This
is partial accounting when any worker lacks a completion before the cutoff;
missing workers are not zero. CPU and wall values are preserved even when a
small interval's microsecond-resolution CPU delta exceeds elapsed wall time.
Worker wall intervals overlap one another and execution, so neither their wall
sum nor CPU plus execution wall is a block latency decomposition.

### Root-work opportunity counters

When worker capture is enabled, each completed worker-total event also carries
`root_probes_measured` and six numeric counts: `storage_partial_roots` /
`storage_partial_cached`, `account_sync_roots` / `account_sync_cached`, and
`account_missing_roots` / `account_missing_cached`. They count root-only
computation attempts and cache-presence snapshots immediately before those
attempts. They cover separate roots for partial storage proofs, delayed account
Sync encoders, and dispatched account results missing a root, respectively.

This diagnostic still performs the original calculations. Cache presence is a
racy observation, not saved work, time, CPU, or a causal I/O diagnosis. Counts
accumulate per worker, include attempts that subsequently error, and emit only
with its existing completion event. No addresses, slots, per-job events or new
syscalls are recorded. Disabled worker capture allocates no observer and performs
no extra cache lookup. Enabled capture uses one local observer per worker and one
cache lookup at each observed fallback; that measurement overhead is part of the
captured worker CPU. Counters are optional: absent/disabled data is unmeasured,
not zero. The viewer summarizes complete counts from successful recorded workers;
failed or cutoff-crossing work must not be interpreted as complete block totals.

## Cold execution-overlay attribution

This diagnostic revision retains field-free `state.overlay.resolve`, `frontiers`,
`execution_anchor`, `execution_cache`, `cache_ready`, `cache_pending_skip`,
`cache_wait`, `cache_miss`, `compute_envelope`, `compute_worker`, and `compute_inline`
scopes (all share the `state.overlay.` prefix) in full and milestone modes.
Milestones also retains `read_validator_config_at_block_hash` with its existing
pseudonymized block hash, so peer-refresh reads remain distinct from transaction
execution. No new identity or numeric fields are exported.

Provider-local OnceCell hits return before the new resolution scopes. The existing
high-frequency `state.overlay.execution_overlay` aggregate remains full-only.
`frontiers` and `execution_anchor` cover first-resolution setup. `execution_cache`
covers a shared-cache lookup/resolution; `cache_ready` marks a ready result,
`cache_pending_skip` marks a best-effort precompute skipping in-progress work, and
`cache_wait` encloses the actual wait call. A `cache_miss` envelope starts after an
initial miss and includes path selection plus any subsequent race, wait or compute;
it is not a count of unique calculations. State-trie cache work emits none of these
execution-cache scopes. A parent equal to its anchor can return an empty execution
overlay without touching the shared cache.

`compute_envelope` includes dispatch and waiting. Its explicit child
`compute_worker` covers the merge/extend call executed through the worker pool;
`compute_inline` covers that call when no pool is configured. The pool may execute
inline when already on its own worker. These are wall intervals, not CPU samples,
and their difference is not an exact scheduler-queue measurement. The worker keeps
its captured parent and subscriber across dispatch. New scopes use synchronous
lifetimes; a read can include synchronous waiting even when full capture reports
similar active-wall and wall durations. Cutoff pruning and incomplete-scope marking
are unchanged. Older captures need not contain these optional scopes.
