# Tempo Fuzz Testing

Parallel fuzzing for txpool and payload builder components.

## Quick Start

```bash
# Build fuzz targets
cd crates/transaction-pool/fuzz && cargo fuzz build

# Run a single target
cargo fuzz run merge_best_ordering -- -max_total_time=300

# Run parallel fuzzing (8 processes, 30 min each)
./scripts/fuzz/run-parallel.sh crates/transaction-pool/fuzz merge_best_ordering 8 1800

# Reproduce a crash
./scripts/fuzz/repro.sh crates/transaction-pool/fuzz merge_best_ordering path/to/crash-file
```

## Targets

### Transaction Pool (`crates/transaction-pool/fuzz/`)
- `merge_best_ordering` — MergeBestTransactions ordering correctness
- `aa2d_state_machine` — AA2dPool state machine fuzzing (add/remove/replace/nonce changes)
- `paused_fee_token_pool` — PausedFeeTokenPool insert/drain/eviction invariants

### Payload Builder (`crates/payload/builder/fuzz/`)
- `payload_limits` — `is_more_subblocks` comparison and subblock expiry logic
- `payload_subblock_lifecycle` — subblock filtering and expiry invariants

## Running on dev-yk

```bash
ssh -o StrictHostKeyChecking=no ubuntu@dev-yk
cd /path/to/tempo
./scripts/fuzz/run-parallel.sh crates/transaction-pool/fuzz aa2d_state_machine 16 3600
```
