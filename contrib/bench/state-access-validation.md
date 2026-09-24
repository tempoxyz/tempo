# State-access benchmark validation

Validate the existing workload on an isolated local benchmark host before
interpreting its performance as a worst case. This suite does not establish a
universal worst case across transactions, hardware, or cache configurations.

## Controls

Keep the node binary, full database snapshots, machine configuration, offered
load, transaction shape, and run duration fixed. Run the existing dependent case
again, then the `--predictable` and `--resident` controls using
`bench-e2e.nu general-state-access-worst-case` with `--validate-state-access`.
The control flags are mutually exclusive. Do not run the cases concurrently.

- The dependent repeat checks reproducibility against the archived baseline.
- Predictable selection removes the cursor dependency from page selection while
  retaining the cursor read/write, 4096 data reads, and full active state space.
- Resident selection retains the dependent method and full database but fixes
  page count to one. EVM data reads remain cold within each transaction even when
  their data is resident in application/OS caches across transactions.

The current analysis assumes the standard 20-minute run and excludes its first
10 minutes. Snapshot restoration is outside the load window. Preserve the virgin
snapshots; no new state import is needed when valid snapshots already exist.

## Correctness Evidence

The optional harness audit runs after load collection and before stopping the
follower. It accepts loopback RPC on the local benchmark chain only. It verifies:

- Contiguous reported blocks and total cursor advancement equal to the reported
  included transaction count.
- Canonical receipts from eight distributed workload blocks, successful status,
  and agreement between receipt, block, and report gas totals.
- Three included transactions' method, calldata, fixture bytecode, actual
  storage access set, populated values, and successful call output.
- Exactly 4096 unique data SLOADs charged 2100 gas each and one cursor increment
  in a parent-state call replay, matched to the included transaction's prestate
  and output. Selected transactions are first in their blocks.

The current Tempo AA default transaction opcode logger returns no opcode steps
and an inconsistent failed flag. Supported transaction prestate/call tracers are
used with the matched call replay instead. Replay wrapper gas differs from real
transaction gas and is never used as the performance denominator. Compressed
trace evidence and `correctness-feature-1.json` are saved beside the run report.
Detailed receipt/opcode checks are sampled, not exhaustive.

## Analysis

After the load has stopped, analyze an individual run from the repository root:

```sh
node contrib/bench/analyze-state-access.cjs bench-results/RUN_ID CASE_LABEL
node --test contrib/bench/state-access-validation.test.cjs contrib/bench/analyze-state-access.test.cjs
```

For a suite, create a directory containing `manifest.json` with this shape, then
pass that directory as the analyzer's only argument. `reference_results` is
optional. Paths are relative to the repository root.

```json
{
  "reference_results": "bench-results/ORIGINAL_RUN_ID",
  "cases": [
    {"scenario": "dependent-repeat", "results_dir": "bench-results/REPEAT_RUN_ID", "exit_code": 0},
    {"scenario": "predictable", "results_dir": "bench-results/PREDICTABLE_RUN_ID", "exit_code": 0},
    {"scenario": "resident", "results_dir": "bench-results/RESIDENT_RUN_ID", "exit_code": 0}
  ]
}
```

The analyzer saves aligned raw counter endpoints, normalized ratios, five
two-minute slices, and a Markdown comparison. Counter resets and same-node scrape
misalignment fail analysis. Gas/time ratios use sums, not averages of per-block
throughput. RPC acceptance counts are explicitly not execution-success counts.
Device names currently match this host: `nvme1n1` for proposer A and `nvme2n1` for
follower B. Adapt that mapping before using device-I/O results on another host.

## Interpretation

- Logical cold-access gas, application-cache misses, and major page faults are
  different measurements. Do not divide major faults by major plus minor faults
  to claim a page-cache miss percentage.
- Fault counters cover the follower's new-payload processing thread, including
  work besides SLOAD and excluding other threads. They do not measure builder
  execution faults. Device I/O includes background work on that device.
- Pipeline catch-up contributes to the gas/time denominator without using the
  payload-thread fault scope or engine cache. The analyzer suppresses those
  per-gas ratios when pipeline starts or execution are observed in the window.
  The post-load audit allows up to ten minutes for the follower to reach the
  final reported block; this does not extend the archived measurement window.
  Payloads returning SYNCING also conservatively suppress fault/gas ratios,
  because downloaded-block execution can bypass the resource guard.
- The follower has no mempool ingress or builder cache sharing. Its engine
  prewarming is a separate path. Evaluate predictable-control behavior on the
  builder, where prewarming is enabled; a null control result does not establish
  that dependency defeated prewarming.
- Confirm AA2D pool availability, build-stop reasons, idle time, reverts, and
  invalid attempts. Builder saturation does not imply follower saturation.
- Resident control should substantially reduce physical faults and execution
  time per gas. If it does not, the cold-state explanation is not established.
- Inspect repeat differences and time slices. A transient peak or drifting
  interval is not a demonstrated sustained bound.
- The current two-node host shares RAM even though CPUs and database devices are
  separate. Its effective cache budget is not that of a single-node deployment.
- The SLOAD-only density bound is not a bound on physical reads or execution
  cost per gas for arbitrary state operations.
