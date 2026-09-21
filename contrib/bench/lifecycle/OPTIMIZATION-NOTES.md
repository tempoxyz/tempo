# Optimization decisions and experiment history

Updated 2026-09-21. Keep benchmark, instrumentation, privacy, cutoff, and
correctness fixes in their PRs even when an optimization is not adopted.
An unsuccessful optimization does not invalidate a useful measurement fix.

## Validated capture and election failure, 2026-09-21

[Detailed findings](EXECUTION-FINDINGS-2026-09-21.md): run35578876523 passed all
capture audits (77 eligible blocks). Exact receiver execution joins identify
file-backed fault I/O-path blocking (p50 16.772 ms, p90 61.451 ms) and runnable
delay (p50 12.160 ms). Block11 has a 170.459 ms final state-root wait. These are
diagnostic observations, not benchmark-proven optimizations.

The follow-up root run35592243235 failed before workload execution because the
five-slot reservation barrier timed out while jobs queued on three distinct
runners. Replaying all five capacity receipts succeeds; this is not a missing
snapshot or disk-space shortage. Keep further runs paused until orchestration
is corrected. Background state-persistence backpressure remains out of scope.

## Snapshot inventory correction, 2026-09-21

The earlier all-runner missing-dataset conclusion was unsupported: the inventory
checked `tempo_e2e_102400mb`, but the actual harness converts bloat=100 to
`tempo_e2e_100000mb`. This applies to both our pinned harness and the successful
current-main harness. Historical failed benchmark admissions remain real; the
wrong-path inventory cannot establish their cause or justify rebuilding data.

The corrected [read-only inventory35576312288](https://github.com/tempoxyz/tempo/actions/runs/35576312288)
covered five distinct runners. Four have all nine required files readable to
both runner and root on both mounted sides; the fifth has one mounted ready
side and one unmounted, unverified side. All five jobs removed their two owned
inventory files and temporary directory. No snapshot was mounted or modified.
The diagnostic fix adds a regression that executes the harness's actual Nu
conversion instead of repeating the probe's assumed size.

The blanket snapshot blocker below is historical and superseded. Use a ready
runner, refresh the frozen kernel/root analysis bindings for the current gate,
and perform a fresh diagnostic capture before paired archive/journal trials.
Actual run admission, strict pre-backpressure pruning, and cleanup still apply.
The five prebuilt bundles were checked today and remain available until
2026-09-24; no rebuild is presently needed for artifact availability.

## Snapshot preservation audit, 2026-09-21

[Read-only baseline inventory35577695848](https://github.com/tempoxyz/tempo/actions/runs/35577695848)
verified all nine required dataset paths in all ten saved virgin baselines
across five distinct runners, including the baseline for the unmounted working
side. This checks filesystem metadata, not full database integrity. No dataset
contents were exported; no volume was mounted, recovered, promoted, or written.
All five jobs confirmed deletion of their two temporary files and directory.

The prebuilt benchmark path restores working volumes from the saved baselines;
its recovery and full-recovery operations copy virgin to scratch. It cannot
enter the native dataset rebuild/promotion path. Resetting a working volume
removes run mutations and any data never saved into its baseline; it does not
clear the saved baseline. The producer cleanup deletes only owned build roots.

[PR #7713](https://github.com/tempoxyz/tempo/pull/7713) now rejects workspace
cleanup paths overlapping snapshot/state roots, symlinked ancestors, and mounted
or nested-mounted directories before deletion, with `--one-file-system` on the
startup reset. The same follow-up is on the root and archive consumer branches.
Validation: 182 lifecycle tests passed with one skipped; 17 cleanup tests passed
on each consumer variant; 14 read-only inventory tests passed. Disposable ext4
fixture bytes were unchanged by probing. These safeguards assume no unrelated
privileged process changes paths between validation and deletion.

## Deferred to other work

**Proposer decoded-block reuse before first forwarding is out of scope for
this investigation. The user explicitly deferred it to other work on
2026-09-17. Do not implement, port, or benchmark it again here unless the user
reopens it.** No owner, delivery date, or external implementation is assumed.

This is the seeded/read-cache path that avoids reconstructing an already-built
block from the archive before forwarding. It differs from the finalized-height
cache, which removes later post-finalization decoding, and from locally built
proposal rehash removal. The latest diagnostic capture lacks the seeded path.
[The earlier single-pair trial](https://github.com/tempoxyz/tempo/actions/runs/35149821744)
tested read caching plus seeding together: forwarding median 11.119 to 0.094 ms,
release-to-body median 25.165 to 14.147 ms. It was feature-first only, with no
whole-node CPU/RSS result; do not present it as a counterbalanced node win.

The user clarified on 2026-09-17 that only **backpressure from background state
persistence** is excluded. Consensus/archive durability waits are explicitly in
scope for investigation and safe optimization. Earlier notes interpreted the
exclusion too broadly; that interpretation is superseded. Preserve required
crash durability and ordering. Execution-thread stalls must be attributed from
evidence, not classified as persistence by assumption.

Concrete durability outliers in run35212362924, verified against complete context
and exact parent chains (the trace label `fsync` wraps `File::sync_data()`):

| Phase / block | Observed interval | Recorded durability operations |
|---|---:|---|
| Baseline 1 / 27 | Verification done to notarize vote: 494.438 ms | Verified-archive blob `fsync` 492.266 ms; voter journal sync 0.229 ms. |
| Baseline 2 / 28 | Verification done to notarize vote: 421.242 ms | Verified-archive `fsync` 220.106 ms; voter append metadata work 199.063 ms (including partition-directory sync 198.634 ms); journal sync 0.246 ms. |
| Feature 2 / 27 | Verification done to notarize vote: 243.758 ms | Verified-archive `fsync` 52.250 ms; voter append metadata work 162.050 ms; journal sync 27.334 ms. |
| Feature 1 / 23 | Receiver notarize vote to first finalization: 96.816 ms | Proposer journal syncs 73.941 ms and 17.736 ms before finalize vote. |
| Baseline 1 / 45 | Receiver notarize vote to first finalization: 67.465 ms | Proposer journal syncs 36.329 ms and 25.934 ms. |

These are observed operation wall durations, not device-level root causes. The
first three marshal actor operations themselves finish in about 1–2 ms; retained
async persistence children and the durable acknowledgment extend the enclosing
scope. Do not describe that as an actor occupied for 494 ms. All examples precede
the backpressure cutoff and remain in the measured block distributions.

## Retirement requested on 2026-09-17

The user requested closing unsuccessful optimization experiments. PRs
#7681 (inline proofs), #7688 (builder context), #7690 (engine parent), #7693
(command sender), and #7696 (overlay cursor) were closed because node
benefit was not established. Preserve immutable revisions and benchmark results
below; closure is not deletion of the experimental evidence or instrumentation.
PR #7679 is a correctness fix now maintained by another person and must remain
untouched. Keep #7661, #7680 and #7694 for useful instrumentation. Keep #7682's
measured signature-allocation reduction separate from claims of node speedup.
The finalized decode cache, combined broadcast/decode trial, and direct hints
retain demonstrated narrower effects; they are not general node-speed winners.

Five PRs were closed and 22 remote branch heads were removed (13 Tempo, 9 Reth).
Retired branch heads and closure receipts are recorded in
`RETIREMENT-2026-09-17.json`. Retained local Git refs prevent experimental commits
from becoming unreachable. Existing benchmark and capture source refs remain
reproducible; no artifacts are rewritten.

## Paths tried without an established overall improvement

The table preserves useful local effects as well as unfavorable results.
Paired percentages are the two experiment orders, not confidence intervals.
Negative latency/CPU percentages mean less time/work. A branch remaining
separate is not an endorsement or a request to retry it unchanged.

| Path | Evidence and result | Decision |
|---|---|---|
| Finalized-block decode cache | [35153081402](https://github.com/tempoxyz/tempo/actions/runs/35153081402): three decodes become one in sufficiently observed blocks. Block p90 -2.4%/-0.6%; validation-tail effect is cohort-sensitive; feature cutoffs earlier. | Proven redundant-work removal, no established broad latency/throughput gain. |
| Scatter/gather body encoding | [35155660716](https://github.com/tempoxyz/tempo/actions/runs/35155660716): body-send stage saves about 0.27/0.32 ms per block; block p90 +4.5%/+5.6%. Encryption still copies. | Below the current >=5 ms target; no whole-block win. |
| Deferred overlay-node cloning | [35217859925](https://github.com/tempoxyz/tempo/actions/runs/35217859925), [PR7696](https://github.com/tempoxyz/tempo/pull/7696): storage-worker CPU/tx -4.15%/-4.61%, block p90 +3.32%/+4.14%, replay-through-verification p90 +4.90%/+32.87%. | PR closed and branch retired; no demonstrated latency win. The unpublished direct-return variant introduced an equal-key fixture regression. |
| Smaller proof-result channels | [35156951687](https://github.com/tempoxyz/tempo/actions/runs/35156951687): local requested bytes 3744 to 744 per successful cycle, same two allocations. Node validation-tail p90 +4.6%/+26.0%. | Allocation-footprint saving only; no latency win. |
| Combined decode cache, dedicated broadcast, signature borrowing | [35158162202](https://github.com/tempoxyz/tempo/actions/runs/35158162202): repeated decode removal and vote-to-verify responsiveness; block p90 -10.9%/+5.4%/-3.7%/+3.4% over four pairs, aligned with phase order. | Do not pool opposing pairs into a speedup. Dedicated broadcast adds a thread. |
| Body-subscription fallback | [35168887587](https://github.com/tempoxyz/tempo/actions/runs/35168887587): motivating large mailbox stall did not recur; body and block-tail effects mixed. | Do not re-propose it as a demonstrated fix for current delays. |
| Eight prewarming threads | [35167388039](https://github.com/tempoxyz/tempo/actions/runs/35167388039): block p90 -7.9%/-18.8%, but execution-loop wall/tx +47.2%/+52.1% and more proof jobs. | A tradeoff, not a general improvement; retain the favorable block result alongside regressions. |
| 24/32 prewarming threads | [24 threads](https://github.com/tempoxyz/tempo/actions/runs/35188620001), [32 threads](https://github.com/tempoxyz/tempo/actions/runs/35186731416): faster replay in some cohorts, larger proof-completion tails and mixed block results. Initial lookahead also changed; runtime predates ownership correction. | No new default established. |
| Corrected fixed-lookahead 16/32 comparison | [35219652510](https://github.com/tempoxyz/tempo/actions/runs/35219652510): reviewed exact-source legacy compatibility fix followed by all audits and 12 Perfetto imports accepts 267 blocks. With initial seed 32 fixed, 32 vs 16 threads reduces loop wall/tx 14.25%/12.00%, but CPU/tx +0.72%/+1.09%, block p90 +0.84%/+2.31%, and combined validation p90 -7.46%/+4.93%. | No new thread-count default. Execution waiting improves but whole-block benefit is not established. Original rejection preserved; no remote redispatch. |
| Direct access hints | [35189439999](https://github.com/tempoxyz/tempo/actions/runs/35189439999): replay-through-verification p90 -5.73%/-7.58%; block p90 -2.72%/-0.13%, p99 worse. | Narrow promising signal, not a general CPU or tail win. |
| Storage-only proof forwarding | [35182260935](https://github.com/tempoxyz/tempo/actions/runs/35182260935): account-worker CPU/tx about -30%, but storage queuing increases and block results mixed. | Work can move between pools; do not equate account CPU reduction with critical-path improvement. |
| Inline singleton storage proofs | [35202318927](https://github.com/tempoxyz/tempo/actions/runs/35202318927): ownership-corrected comparison; replay-through-verification p90 +5.02%/+9.18%. | PR closed and branch retired; no repeated node benefit. |
| Borrow builder context | [35210439349](https://github.com/tempoxyz/tempo/actions/runs/35210439349), [PR7688](https://github.com/tempoxyz/tempo/pull/7688): local allocation traffic -672 bytes/job; node replay-through-verification p90 +17.25%/-11.94%. | PR closed and branch retired; local saving without conclusive node benefit. |
| Borrow engine tracing parent | [35211480399](https://github.com/tempoxyz/tempo/actions/runs/35211480399), [PR7690](https://github.com/tempoxyz/tempo/pull/7690): local CPU reduction; node replay-through-verification p90 -10.84%/+0.71%. | PR closed and branch retired; no repeated gain. |
| Borrow builder command sender | [35215249258](https://github.com/tempoxyz/tempo/actions/runs/35215249258), [PR7693](https://github.com/tempoxyz/tempo/pull/7693): local CPU reduction; node block p90 -5.09%/+15.88%. | PR closed and branch retired; no repeated gain. |
| Lazy recorder aggregates | [35183921712](https://github.com/tempoxyz/tempo/actions/runs/35183921712): block median +4.08%/+4.56% despite some tail improvements. | Keep separate; no uniform benefit. |
| Root scratch reuse, singleton dispatch, single-call capacity | Local allocation/work reductions with small, mixed, or adverse control timings. Root scratch removes one repeated allocation but nonempty CPU is essentially flat; singleton applicability is small. | No established node win; do not prioritize tiny local savings over measured >=5 ms regions. |
| Whole-process/leaf CPU observers | [Process observer](https://github.com/tempoxyz/tempo/actions/runs/35216600719), [leaf observer](https://github.com/tempoxyz/tempo/actions/runs/35201357258): useful coverage, but enabled comparisons show adverse latency movement. | Keep opt-in and retain instrumentation PRs; no zero-overhead claim. |

Typed recorder allocation reductions and offline report improvements remain
useful tooling changes. Offline report CPU improved about 7–8.5% with identical
output; that is not an EVM or whole-node speedup. The builder/engine worker-state
ownership repair is a reproduced correctness fix, not a benchmark hypothesis.

## Follow-ups after the scope clarification

- [PR7704](https://github.com/tempoxyz/tempo/pull/7704) adds an execution kernel-wait diagnostic. Initial [35231747665](https://github.com/tempoxyz/tempo/actions/runs/35231747665) stopped before transaction load: the latest collector had anonymous thread ordinals but lacked the native registration hook. The marker gate correctly rejected it. A separate missing timestamp-origin export was reproduced end to end. Neither failure is a node-performance result. The registration hook and timestamp export are now fixed and locally validated; corrected [35235891056](https://github.com/tempoxyz/tempo/actions/runs/35235891056) could not elect a runner with the unchanged 64 GiB build headroom, so it never built or loaded transactions. Read-only [inventory35237657777](https://github.com/tempoxyz/tempo/actions/runs/35237657777) confirms that none of the five runners can recover the required build headroom from its entire benchmark workspace. The separate prebuilt-only route is now implemented in [PR7712](https://github.com/tempoxyz/tempo/pull/7712) and [PR7713](https://github.com/tempoxyz/tempo/pull/7713): both kernel and root diagnostic producer builds succeeded, immutable bundles passed validation, and workload-tool binaries match byte-for-byte. It preserves 48 GiB capture reserve plus the exact transport/extraction budget with no compiler fallback. The first prebuilt node dispatch [35248545712](https://github.com/tempoxyz/tempo/actions/runs/35248545712) failed before node startup: four slots failed setup and the remaining slot had insufficient capacity. This produced no new timing data; it must not be treated as an unsuccessful optimization trial. After the runner owner repaired capacity, [35252651860](https://github.com/tempoxyz/tempo/actions/runs/35252651860) was dispatched with final cleanup required on every started slot. Cleanup follows artifact upload, stops owned processes, recovers touched schelk scratch volumes, removes selected-workspace files and exact unselected-slot receipts, and preserves shared caches and pristine snapshots. It failed before node startup on outdated workflow test fixtures. The fixture correction passed locally, and [35253440211](https://github.com/tempoxyz/tempo/actions/runs/35253440211) then reached the snapshot preflight but stopped because it checked existing volumes before mounting them. Both attempts completed final cleanup successfully on all five slots; neither contains node timing data. A mount-only follow-up mounts existing initialized scratch volumes before metadata admission, rejects inconsistent mount state, and retains the ban on dataset generation. It also forwards an explicit owned TMPDIR value into systemd scopes; 178 lifecycle and 92 scheduler tests pass. The follow-up [35255365658](https://github.com/tempoxyz/tempo/actions/runs/35255365658) still failed snapshot readiness before node startup, and all five final cleanups succeeded. Read-only [inventory35256428759](https://github.com/tempoxyz/tempo/actions/runs/35256428759) then covered five distinct runners: both volumes mounted, schelk available to Nu and sudo, but all nine required files for `tempo_e2e_102400mb` missing to both runner and root, with no permission or unsafe-path errors. Mount and PATH availability do not explain this failure. All inventory-owned files were removed after upload. Further node captures need the exact 100 GiB dataset restored or explicitly prepared; the prebuilt consumer still forbids silent regeneration. Its explicit portable target is a new build contract; comparisons must use that contract on both arms, separately from historical native builds.
- [PR7705](https://github.com/tempoxyz/tempo/pull/7705) tests bounded reuse of successfully synced parent-directory identities. [Matched trial35232632085](https://github.com/tempoxyz/tempo/actions/runs/35232632085) passes all ordinary and dedicated raw-source audits: 250 eligible blocks, 12 successful Perfetto imports, 316 loaded root-directory barriers avoided. Control voter-root sync maxima reached 19.508/12.212 ms on one validator, but typical root syncs were only 7–11 microseconds. On the common 23.500-second horizon (43/42 and 44/46 loaded blocks), block p90 improved 1.58%/20.12% and replay-through-verification p90 improved 6.08%/13.38%; block medians moved +4.23%/-3.38%, and verification-to-vote p90 worsened 18.81→44.83 and 17.10→27.02 ms. **Retain isolated for demonstrated barrier avoidance; mixed node latency, no merge/default endorsement.** Full-load component distributions have unequal capture lengths. The discarded one-entry cache had no hits for alternating partitions (16 syncs for 16 creations); the bounded 16-entry fixture required two syncs and reused 14 proofs. First creation and partition/header barriers remain; this does not prove the historical 39.8 ms root sync was avoidable.
- [PR7706](https://github.com/tempoxyz/tempo/pull/7706) adds exact builder-to-root-task links, final-hash boundaries, and bounded readiness observations. Its prebuilt diagnostic is prepared and queued after the kernel capture; runner capacity is repaired. A separate local early-hash prototype checks roots **and retained database updates** under delayed/reordered proofs and later mutations; root equality alone is insufficient. A negative fixture shows why eligibility matters: early hashing followed by deleting the entire same subtree can retain extra database removals despite a correct root. The prototype excludes prefixes with pending proofs; arbitrary late writes are not claimed safe. No node benefit has been measured.
- [PR7707](https://github.com/tempoxyz/tempo/pull/7707) isolates archive/execution overlap (10 gate tests and a full Tempo compile check pass; node benchmark pending). The candidate starts the existing archive durability operation after structural checks, overlaps it with execution, and still requires both successful execution and durability before voting. It must also skip recovered views containing cached candidates, because the archive can contain candidates that failed execution. Invalid/canceled work may consume extra I/O; this tradeoff must be measured alongside any reduced durability tail.
- [PR7708](https://github.com/tempoxyz/tempo/pull/7708) isolates journal-section preparation (storage/recovery, actual voter-loop ordering tests and a full Tempo compile check pass; node benchmark pending): one owned preparation task can overlap creation with an already-dispatched application request, and all append/prune/sync consumers recover the same journal before using it. It must preserve vote-sync ordering, cancellation and pruning; it has no measured node result yet.
- The fixed-lookahead comparison now passes all ordinary audits and 12 Perfetto imports after a reviewed source-bound legacy-header compatibility correction. Its original controller rejection remains archived unchanged. More prewarming reduced loop waiting, but did not establish improved whole-block latency; see its row above.

The durability trial's exact common-cohort follow-up found zero archive fsync
overlap with body-ready-to-verification in all 175 blocks, as expected from the
unchanged serial ordering. Its feature p90 examples contain 41.789 ms and
15.195 ms of owned archive fsync union; the latter also has 2.326/3.455 ms of
partition/header sync. These are actual per-block intervals, not summed stage
quantiles or a causal explanation of the feature/control shift. They support
testing archive overlap separately from parent-directory proof reuse.

A remaining attribution gap is the new-payload request boundary: Tempo retains
the verification request context, but Reth's queued message does not carry it.
Execution still has exact block identity; repeated verification attempts cannot
be distinguished by block identity alone. The overlap analysis therefore keeps
block CPU separate and marks attempt-specific replay overlap unavailable across
that gap. Body-ready-to-verification and owned archive ancestry remain measurable.

## Current questions above 5 ms

[Full-lineage run35212362924](https://github.com/tempoxyz/tempo/actions/runs/35212362924)
contains four captures of identical code. The common complete loaded cohort is
175 blocks; these phase labels are not optimization/control comparisons.

1. **Final sparse-storage-root work.** Its tail union is 14–15 ms at the phase
   medians and 19–23 ms at p90; 173/175 blocks retain at least 5 ms after the last
   storage proof. Both across-address and within-subtrie parallelism already
   exist. The proposal is to first measure ready dirty subtries, hashing versus
   pool delay, and repeated work, then test bounded earlier hashing during
   existing proof-drain gaps if safe. This is a hypothesis, not a proven saving.
   Do not publish a partial root or treat pending updates as complete.
2. **Proposer root completion.** The synchronous state-root receive waits at
   least 5 ms in 101/175 builds; phase p90s 41–53 ms, with a 93 ms example. Root
   tasks start before builder attempts and currently lack an exact exported
   task-to-attempt link. Add that link before attributing the wait to receiver
   hashing, proof retrieval, or scheduling. Existing root completion already
   overlaps transition merging.
3. **Execution stalls.** The paired loop-wall-minus-thread-CPU residual has phase
   medians 33–47 ms and p90s 88–109 ms. One loop takes 462 ms wall but 123 ms CPU;
   transaction-iterator wait is only 2.5 ms. The residual is time not spent on
   that thread's CPU, not proof of one continuous pause, disk cause, or removable
   work. Earlier kernel evidence identifies I/O-path sleeping in other captured
   outliers, without identifying a provider/device or persistence cause.

The separately prepared root-only proof observer measures
`StorageProofCalculator`/encoder fallback work. It does not measure the final
sparse-trie dirty hashing above and must not be used as its attribution.

Proposal filling follows an adaptive work budget. A faster component can change
admitted transaction work, so compare equivalent work, CPU, and stage latency;
do not manufacture a speedup by shrinking the budget. The present capture does
not establish each block's binding budget/gas/pool stop reason.

Long span lifetimes are not necessarily work: receipt-root computation streams
alongside replay and ends at most about 3.4 ms afterward in this cohort. Engine
conversion finishes at least about 74 ms before replay completes. Nested spans
and independently calculated quantiles are not additive savings.

An exact-owner follow-up also rules out the execution-overlay accessor as a
>=5 ms explanation for these receiver-loop stalls. Raw aggregate counts and
nanosecond sums match all 175 execution owners; per-phase maxima are only
0.346/0.415/0.444/0.437 ms. The same blocks can have much larger overlay sums
under later validator-configuration reads (54.925 and 70.139 ms examples), which
must not be assigned to the earlier transaction loop. Deprioritize removing the
cold-overlay worker handoff as a remedy for these measured loops. Hot accessors
are aggregated, so their broad first-to-last-call envelopes cannot be joined to
kernel waits as individual calls. A future materially slow owner would first
need narrow cold-initialization and compute-versus-existing-waiter spans.

[PR7715](https://github.com/tempoxyz/tempo/pull/7715) retains exact verification-request context through the executor and Reth queue/service boundary, including response cancellation and cross-dispatch tracing cleanup. Focused Tempo and Reth tests pass; this is attribution instrumentation, not a measured speedup, and is not part of the pinned runtime in capture 35252651860.

The portable archive control/overlap builds (35255262493 / 35255264728) and
journal preparation build (35256348538) all passed bundle/source validation and
final cleanup. Each removed both owned build directories; no owned processes
remained. Workload tools and CPU-check binaries match byte-for-byte across these
arms and the prior portable control. The archive consumer branch
`joshie/bench-prebuilt-archive-only` is prepared for the two counterbalanced
orders with unchanged measurement code. These are build and cleanup results,
not optimization wins; node execution remains blocked on the missing 100 GiB
snapshots established by inventory 35256428759. No snapshot generation fallback
or change to the pre-backpressure cutoff was introduced.

## Evidence rules

- Preserve failed captures, rejected audits, source refs and negative results.
- Require strict source-time pre-backpressure pruning and privacy allowlists.
- Revisit an unsuccessful path only for a new source-supported hypothesis,
  changed implementation, or identified measurement defect; no unchanged retry.
- Do not infer throughput from time until backpressure. Small-cohort p99 often
  equals the observed maximum and is not a stable population-tail estimate.
