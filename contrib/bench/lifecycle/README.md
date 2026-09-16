# Block lifecycle capture

Select **profiling: lifecycle** in the `bench-e2e` workflow. This runs the feature
revision on both local validators and uploads the `block-lifecycle` artifact.
Extract the artifact and open a phase's `index.html`. The viewer works offline.
`perfetto.json` can also be opened in Perfetto.

The feature revision must include the pinned Reth capture layer and Commonware
instrumentation. To run directly, use `--lifecycle --run-side feature`. Other
profilers and ValScope publication are disabled. The workflow uploads only the
lifecycle directory, not ordinary benchmark logs/reports.

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

Existing spans are retained alongside added scopes. The report lists observed
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
