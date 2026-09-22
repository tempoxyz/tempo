# Read-readiness diagnostics

Lifecycle reports preserve the optional Reth read-readiness events under one
top-level `read_readiness` object. Events retain the block identity assigned by
the existing parent/span mapping; events without an exact mapping stay in
`unattributed`. The parser never assigns a block by timestamp or proximity.

All diagnostic values are fixed, nonnegative `u64` fields. Read totals use
`read_role` values 1–5 and `read_class` values 0–9. `read_coverage` reports
`read_execution_mode=1` for the serial instrumented path and `2` for the BAL
path, which is currently unsupported. Cache checkout reasons are numeric enum
values; cache miss states distinguish inflight, completed, failed,
never-observed, unknown-due-to-cap, and unknown-contention. Unknown states are
preserved as counters and are never converted to zero or inferred from a
missing field.

Logical read totals and database read totals are inclusive diagnostic views.
They may overlap, so consumers must not add them as exclusive populations.
All short reads are counted in the totals. Individual samples are completion
selected and retained at most eight per `(node, parent-event, read_role)` scope;
the same cap applies to unattributed samples. `read_samples_omitted` is the
producer's omission count, while `report_dropped_samples` covers malformed,
cutoff-crossing, or locally capped records.

The report applies the strict outer event cutoff to every diagnostic stage.
Samples additionally require `read_end_ns >= read_begin_ns`,
`read_end_ns <= event.ts`, and completion before the cutoff. Invalid or mixed
readiness headers make the report invalid; an absent legacy header is treated
as disabled for compatibility.

## Numeric vocabulary

Roles: 1 execution, 2 prewarm, 3 account proof, 4 storage proof,
5 serial payload-builder reads (including state setup and finalization).
Classes: 0 logical account, 1 logical storage, 2 logical code, 3 database account,
4 database storage, 5 database code, 6 account trie, 7 storage trie, 8 history or
changeset, 9 other database access.
Checkout reasons: 1 absent cache, 2 matching cache still in use, 3 other cache
still in use, 4 reuse matching parent, 5 reset for another parent, 6 cache disabled.

Correlation retains at most 65,536 exact keys across 64 shards of 1,024 entries privately per cache checkout. Keys
and addresses are never exported. Successful prewarm completion means its
backing read returned successfully; it does not prove publication into the cache
has completed. Known positive observations survive unrelated tracking contention.
Absent or failed observations become unknown only in shards where coverage is lost.
A shard can reach its capacity before the whole tracker is full; this is reported
as unknown due to capacity rather than as an unobserved prewarm.

This probe measures read duration, including CPU work and waiting. It does not
itself distinguish kernel I/O sleep from scheduling delay. The existing kernel
capture is needed for that distinction. The current capture adds no per-read
trace events: counters accumulate locally and emit after a scope finishes.

## Short validation capture

Use one 30-second feature-only milestone capture against the unchanged runtime
behavior, with read-readiness enabled. The first persistence-backpressure event
ends the eligible interval; raw captures and derived artifacts are pruned too.
Treat this as instrumentation validation, not evidence of a performance gain.
Retain compact reports and provenance; delete remote bulk artifacts after verified
download, then remove local bulk copies after analysis. Runner cleanup must
preserve the seeded snapshots and remove only job-owned output.

The historical `split_when_queue_nonempty` field refers to the account proof
queue. `split_when_storage_queue_nonempty` covers storage backlog separately.
Each queue has joint force/account-idle/storage-idle reason counters, so aggregate
reason counts do not need to be guessed to explain a split under backlog.

Builder cache/prewarm summaries emit after both building and its prewarm workers
finish. The diagnostic reporter retains counters and a span, not the execution
cache, so it cannot delay cache handoff. Summary stage ordering is not a completion
marker. Failed or canceled attempts without a produced block remain unattributed;
worker summaries crossing the capture boundary remain censored.

A valid load-finished capture may contain one unfinished terminal proposal. The
report exposes `shutdown_tail_open_spans` only when exact payload/parent identity
links prove the known resource forest descends from the latest finalized block,
all open work is unbound, and recorder integrity is intact. It preserves open
counts and the incomplete attempt, without inventing completion times or block
ownership. Other unexplained open spans still invalidate the capture.
