# Validation plan

This suite validates the current workload. It does not intensify it or claim
to prove a universal worst case across all transactions and hardware.

## Fixed configuration

- Tempo node revision: f62969a95e8a787d2956f3509d25c533bdaac746.
- Same original 100000 MiB state-access snapshots and contract bytecode.
- Same independent proposer and certified-follower databases and CPU allocations.
- Same sender accounts, transaction gas limit, offered load, seed, and expiring-nonce settings.
- Twenty-minute loads, with ten minutes excluded from metrics as warmup.
- Clean snapshot restores between cases; no fresh state import.
- Correctness traces run after the measured load; a warmup-only preflight may
  be used to validate the audit's RPC compatibility.
- Builder prewarming is enabled. The follower has no mempool ingress and
  disables builder prewarming/cache sharing; its engine prewarmer is separate.

## Cases

1. Repeat the original state-dependent case, comparing with the archived run.
2. Predictable control: change the contract method, keeping the same 399999-page
   active space, 4096 reads, cursor write, and full database.
3. Resident control: use the state-dependent method with page count one, while
   retaining the same full database, 4096 reads, and cursor write.

## Evidence required

- Sample real canonical receipts, not RPC-submission success. Verify receipt
  status and gas sums against the reported blocks. Report sampling limits.
- Verify contiguous reported blocks and the whole-run committed cursor delta
  against the total included transaction count, since each workload call must
  increment the cursor once.
- Trace sampled included transactions and verify 4096 unique, populated slots,
  the cursor write, the intended selector, and page selection calculated from
  calldata and pre-state cursor. The AA transaction opcode logger was found
  to return no steps and an inconsistent failed flag. Use the supported
  transaction prestate/call tracers, plus parent-state opcode call replay
  cross-checked against the actual access set and output, to check cold SLOAD
  charging. Do not use call-replay wrapper gas as a measurement denominator.
- Compare aligned cumulative execution time, major faults, and execution-cache
  misses per gas separately for proposer and follower.
- Inspect two-minute slices, not just a single average, for drift or ramps.
- Inspect the AA2D pending pool (the ordinary nonce pool does not contain these
  transactions), build-stop reasons, idle time, and reverted/invalid counts.
- Treat a predictable-control speedup as evidence of an effect from dependency
  only on paths with an actual prewarming opportunity. A null result does not
  demonstrate defeat of prewarming.
- Expect the resident control to substantially reduce physical faults and
  execution time per gas. If it does not, investigate rather than declaring
  the cold-state hypothesis validated.
- Treat large repeat differences or within-window drift as limitations on
  steady-state representativeness. Do not label a short peak a sustained bound.

Additional instrumentation or repeat runs are warranted only if these checks
leave a concrete ambiguity. No production/public-chain traffic is involved.
