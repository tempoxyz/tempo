# Async Execution Performance Experiment

- Scope: test the happy-path performance shape of async execution using the existing `bench-e2e` GitHub workflow.

- Benchmark workload: use the two-node network and txgen-generated valid transactions from `bench-e2e`.

- Block building: optimistically add real txpool transactions to the next block until the validation budget estimates a full 250ms slot.

- Block building does not execute transactions and does not require the state produced by the previous block.

- Block validation: run real `new_payload` validation asynchronously after the block is committed by consensus.

- Consensus voting: notarization and finalization commit the block to the chain without waiting for validation to finish.

- Validation failures: treat them as out of scope for this happy-path benchmark.

- `crates/consensus/src/consensus/application/actor.rs`: add async-exec experiment mode where block `N+1` can build while block `N` is validating.

- `crates/consensus/src/consensus/application/actor.rs`: track only two in-flight slots: `currently_validating` and `currently_building`.

- `crates/consensus/src/consensus/application/actor.rs`: when build `N+1` finishes before validation `N`, hold it until validation advances.

- `crates/consensus/src/consensus/application/actor.rs`: when validation `N` finishes, immediately promote built `N+1` into validation and start building `N+2`.

- Metrics: build duration, validation duration, block interval, time spent waiting for validation, time spent waiting for build, and execution lag of the single validating block.

- Benchmark comparison: compare current sync behavior against async behavior where `new_payload(N)` overlaps with `build(N+1)`.
