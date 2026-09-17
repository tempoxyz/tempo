# Execution fault diagnostic

This isolated harness adds one full-capture `feature-1` phase to the reviewed
five-slot `setup_failure_v2` reservation policy. It uses runtime
`0bd62dd2f0e509016439b2189cd0f4998d007a26`, a pin-only descendant of accepted
`41f606ef415effc66c429192220c4a36faea98a9`. Its Reth descendant adds the missing
optional native thread-registration hook to that collector; engine and storage
algorithms remain identical. Runtime sources and Cargo pins are not changed by
this harness. It is a cause diagnostic, not an optimization comparison.

The scheduler producer, classifier, strict cutoff handling and bounded SQLite
report index are copied from reviewed `132006dbfc32d5e2e31eff30544af8f790bbbda0`.
The dedicated workflow runs an owned-file fault capability test before starting
the validators. Unsupported probes, capture loss, missing registration evidence,
and invalid cutoff evidence remain fatal. The five-slot reservation policy and
64 GiB guard are unchanged. No worker or host identities are published.

`kernel_stacks_v2` distinguishes a complete private stack containing an exact
`filemap_fault` caller above `io_schedule` from generic I/O scheduling, futex,
and unknown paths. It does not identify the file, storage device, provider,
transaction, or persistence subsystem. Registered executor thread aliases join
actual lifecycle entered intervals to scheduler intervals. Scheduled residence
is not thread CPU; blocked-before-wake and runnable-after-wake are separate.
Only strict pre-cutoff intervals contribute. New measurements must not be pooled
causally with old captures, and the diagnostic observer itself has a cost.

The reporter preserves the base harness's worker counters, full-capture loader,
prewarm-disabled validation, source pruning, package export, and serialization
memory release. It adds the reviewed scheduler sidecars and closed progress
reporting. It intentionally does not export frame-lineage derived reports, but
retains the accepted source fields in the pruned raw capture. The leaf and
whole-process CPU observers are explicitly disabled.

Validation includes lifecycle and scheduler unit suites, actual workflow Bash
routing and Nu snippets, reservation transport tests, a live owned-file fault
probe, and a bounded original-runtime capture-prefix loader/privacy check.
The prefix is intentionally incomplete and provides compatibility evidence only;
it is not a valid standalone benchmark or scheduler capture.

The first harness `54b74202cfa9e5c39b66fb382861743dd900079d` was rejected
before workload because the accepted runtime lacked this native hook; anonymous
raw thread ordinals alone do not support a kernel join. A separate latent export
bug omitted `time_origin_ns`. This follow-up exports the existing integer origin
and exercises actual pruning, scheduler indexing/publication, and fault Perfetto
output together. The prior failed spec and artifacts remain unchanged.
