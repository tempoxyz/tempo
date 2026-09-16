# Block lifecycle capture

Select **profiling: lifecycle** in the `bench-e2e` workflow. This runs the feature
revision on both local validators and uploads the `block-lifecycle` artifact.
Extract the artifact and open a phase's `index.html`. The viewer works offline.
Open `perfetto-p50.json`, `perfetto-p90.json` or `perfetto-p99.json` in
[Perfetto](https://ui.perfetto.dev) for a small trace of an actual representative
block. `perfetto.json` contains the full capture.

The feature revision must include the pinned Reth capture layer and Commonware
instrumentation. To run directly, use `--lifecycle --run-side feature`. Other
profilers and ValScope publication are disabled. The workflow uploads only the
lifecycle directory, not ordinary benchmark logs/reports.

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
python3 contrib/bench/lifecycle/perfetto.py report/lifecycle.json --out report
```

For any individual report-local block number:

```sh
python3 contrib/bench/lifecycle/perfetto.py report/lifecycle.json --out report --block 200
```

Choose **Open trace file** in Perfetto and select the newly generated JSON file.
Start with a percentile file for a focused view. Full and focused exports use the
same capture clock. Focused files contain only operations attributed to that
block, its milestones, and explicitly labeled frame transfers overlapping its
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
Event loss, malformed input, I/O errors, or a missing footer disable percentile
selection. Sample count is shown; a small-sample p99 is descriptive.

## Coverage and interpretation

Captured work includes proposal/payload handoff, builder phases, roots, encoding,
construction, persistence, pacing, Marshal/cache/archive/broadcast, encrypted
framing and codec work, sequential/BAL replay, receipts/merging, prewarm, overlays,
cache updates, root waits, persistence, voting and certificate handling.

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
through fanout and batching, queue enqueue/dequeue markers, and scheduler/off-CPU
profiling if kernel attribution is needed. Such IDs must remain source-filtered
and must not alter network messages. Use this draft's coverage inventory to
verify those additions before beginning the separate investigation phase.
