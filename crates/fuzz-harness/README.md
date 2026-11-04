# Tempo Fuzz Harness (v1.16.1 backport)

A stateless Tempo block executor, built as a cdylib for differential fuzzing
and for replaying blocks taken from a node. The input and outcome types and
their contracts are in [`tempo-fuzz-types`](../fuzz-types).

This branch is the v1.16.1 release plus main's fuzz harness, so tuner can
compare the release with main. It speaks main's harness schema (version 4), so
both load side by side:

- `tempo-fuzz-types` and `tempo-invariants` are main's, except that
  `InstrStop` is a local copy of evm2's (same variants, same order, so the same
  encoding) and the configurable account interface is copied in, since this
  release has neither evm2 nor that precompile (it activates at T14).
- The harness executes with revm, as this release does: it is main's harness
  from before the evm2 switch (tempoxyz/tempo#7871), with main's later invariant
  checks (invariants-core, step checks, view cache and counts) ported onto revm.
  revm halt reasons map onto `InstrStop`; `CallTooDeep`, `OutOfFunds` and
  `OverflowPayment` count as reverts, as main counts them.

```bash
cargo build -p tempo-fuzz-harness --release
```

The library exports two bincode-encoded C ABI functions:

- `tempo_fuzz_execute_with_result_v1`: a `TempoHarnessInput` in, a
  `TempoHarnessOutcome` out.
- `tempo_fuzz_capabilities_v1`: the harness's `TempoHarnessCapabilities`, so a
  runner that loads several revisions can generate inputs all of them support.
