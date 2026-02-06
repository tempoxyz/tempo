---
id: TIP-YYYY
title: Multi-Phase Conflict Detection for 2D Nonce Pool
description: A 3-phase conflict detection pattern that separates prefetching, locking, and committing to prevent race conditions in the AA2dPool while maximizing parallelism.
author: Artem Bogomaz (artembogomaz@gmail.com)
status: Draft
related:
protocolVersion: TBD
---

# TIP-YYYY: Multi-Phase Conflict Detection for 2D Nonce Pool

## Abstract

This TIP introduces a `ConflictDetector` for the AA2dPool that separates transaction admission into three distinct phases: prefetch, check-and-lock, and finalize. When a batch of 2D nonce transactions arrives, the detector prefetches sender nonce state in parallel, acquires per-nonce-key locks atomically, and either commits or rolls back the locks based on execution outcome. The mechanism is confined to the mempool — it does not alter consensus, block validity, or on-chain state.

## Motivation

The AA2dPool manages 2D nonce transactions where each transaction is identified by `(sender, nonce_key, sequence_id)`. Under high load, concurrent admission of transactions sharing the same sender or nonce key creates race conditions:

1. **Redundant state reads**: Multiple transactions from the same sender each trigger independent nonce lookups at `NONCE_PRECOMPILE_ADDRESS`. For a batch of 50 transactions from 5 senders, this means ~50 reads instead of ~5.

2. **Nonce-key races**: Two transactions targeting the same `(sender, nonce_key)` with the same `sequence_id` can both pass validation concurrently and both be admitted to the pool, creating a conflict that is only caught later during block execution.

3. **No rollback on batch failure**: If one transaction in a batch fails validation after others have already been admitted, there is no mechanism to atomically roll back the entire batch. This leaves the pool in an inconsistent state where some transactions from a failed batch occupy slots.

The current pool relies on insertion-order conflict resolution (`by_id: BTreeMap`) and post-hoc eviction, which works but leads to wasted validation work and unnecessary pool churn.

**Alternatives considered:**

- **Pessimistic locking (lock-per-sender)**: Simple but serializes all transactions from the same sender, eliminating parallelism for high-throughput senders like market makers.
- **Optimistic concurrency control**: Validate in parallel then detect conflicts post-hoc. This is roughly what the current pool does, but it wastes work when conflicts are common.
- **Database-level MVCC**: Would require the state provider to support snapshot isolation. The 3-phase approach achieves similar isolation without upstream changes.

---

# Specification

## Three Phases

| Phase | Name | Purpose |
|-------|------|---------|
| 1 | `prefetch` | Prefetch all required sender nonce states from persistent storage in parallel |
| 2 | `check_and_lock` | Validate nonces and acquire per-nonce-key locks atomically |
| 3 | `finalize` | Commit locks on success or rollback on failure |

## Sender Nonce State

The prefetched state per sender aggregates all data needed for conflict detection:

```rust
pub struct SenderNonceState {
    pub nonces: HashMap<U256, u64>,
    pub keychain_valid: bool,
}
```

- `nonces`: Maps each nonce key to its current on-chain sequence ID
- `keychain_valid`: Whether the sender's keychain authorization is still active

## NonceLock

A lock represents a claim on a specific `(sender, nonce_key)` pair:

```rust
pub struct NonceLock {
    sender: Address,
    nonce_key: U256,
    sequence_id: u64,
    locked_at: Instant,
}
```

Locks are held in a `HashMap<(Address, U256), NonceLock>` protected by `RwLock`. A lock exists for the duration between phase 2 (acquisition) and phase 3 (commit or rollback).

## LockSet

A `LockSet` groups all locks acquired during a single batch admission. It implements `Drop` to guarantee lock release even on panic or early return:

```rust
pub struct LockSet {
    locks: Vec<NonceLock>,
    detector: Arc<ConflictDetector>,
}
```

| Operation | Behavior |
|-----------|----------|
| `commit()` | Releases all locks and invalidates prefetch cache for affected senders. Consumes the `LockSet` without triggering `Drop`. |
| `rollback()` | Releases all locks via `Drop`. Prefetch cache entries are preserved for reuse. |

On `Drop`, all locks in the set are released by removing them from the `locked_nonces` map. The `commit()` path uses `mem::forget(self)` after draining locks to prevent double-release.

## ConflictDetector

```rust
pub struct ConflictDetector {
    locked_nonces: RwLock<HashMap<(Address, U256), NonceLock>>,
    pending_prefetch: RwLock<HashMap<Address, PrefetchPromise<SenderNonceState>>>,
    state_store: Arc<dyn StateStore>,
}
```

### Phase 1: Prefetch

```rust
pub async fn phase1_prefetch(&self, senders: HashSet<Address>) -> Result<(), ConflictError>
```

For each unique sender in the batch:
1. Check if a `PrefetchPromise` already exists (double-checked locking)
2. If not, create a new `Pending` promise and spawn a fetch task
3. The fetch task reads nonce state from persistent storage and completes the promise

Multiple batches arriving concurrently share the same promise for a given sender — only one fetch is issued.

### Phase 2: Check and Lock

```rust
pub async fn phase2_check_and_lock(
    &self,
    txs: &[Transaction2D],
) -> Result<LockSet, ConflictError>
```

For each transaction in the batch:
1. Await the sender's prefetch promise to get `SenderNonceState`
2. Verify keychain is valid; return `KeychainRevoked` if not
3. Verify `sequence_id >= expected` for the nonce key; return `NonceTooLow` if not
4. Attempt to acquire a lock on `(sender, nonce_key)`:
   - If already locked by another batch, return `AlreadyLocked`
   - Otherwise, insert the lock and add it to the `LockSet`

If any transaction fails validation, all locks acquired so far in this batch are released (the partial `LockSet` is dropped).

### Phase 3: Finalize

```rust
pub fn phase3_finalize(&self, lock_set: LockSet, success: bool)
```

| Outcome | Action |
|---------|--------|
| `success = true` | `lock_set.commit()` — removes locks and invalidates prefetch cache for affected senders (state is now stale) |
| `success = false` | `lock_set.rollback()` — removes locks, preserves prefetch cache (state unchanged) |

## Error Types

```rust
pub enum ConflictError {
    AlreadyLocked { sender: Address, nonce_key: U256 },
    NonceTooLow { expected: u64, got: u64 },
    KeychainRevoked,
    PrefetchFailed(String),
}
```

## Batch Admission Flow

The full flow for admitting a transaction batch to the AA2dPool:

```
process_transaction_batch(txs):
  senders = unique senders from txs

  phase1_prefetch(senders)                          // parallel state fetch
  lock_set = phase2_check_and_lock(txs)?            // validate + lock
  match execute_batch(txs):
    Ok(hashes) -> phase3_finalize(lock_set, true)   // commit
    Err(e)     -> phase3_finalize(lock_set, false)   // rollback
```

For single-transaction admission, the same flow applies with a batch of size 1.

## Lock Expiry

Locks that are neither committed nor rolled back (e.g., due to a crash between phase 2 and phase 3) are cleaned up by a periodic sweep. Any lock older than a configurable timeout (default: 30 seconds) is forcibly released. This prevents permanent lock leaks.

## Implementation Location

- New file: `crates/transaction-pool/src/conflict_detector.rs`
- Integrate in: `crates/transaction-pool/src/tempo_pool.rs` — batch admission in `add_validated_transactions`
- Integrate in: `crates/transaction-pool/src/tt_2d_pool.rs` — single-tx admission in `add_transaction`
- Prefetch path: `crates/transaction-pool/src/validator.rs` — batch validation in `validate_transactions_with_origin`

## Integration Notes

This TIP aligns with the existing AA 2D pool flow as follows:

1. **Phase 1 (prefetch)**  
   Use `TempoTransactionValidator::validate_transactions_with_origin` to build a per-batch cache of
   `nonce_key_slot` reads (`NONCE_PRECOMPILE_ADDRESS`) and reuse across AA 2D transactions in the
   same batch. This minimizes redundant storage reads without changing validation semantics.

2. **Phase 2 (check-and-lock)**  
   Add a `ConflictDetector` lock check in `TempoTransactionPool::add_validated_transactions` for
   AA 2D transactions before inserting into `AA2dPool`. This is the only place where a batch of
   validated transactions is available. For non-batch paths, add a lightweight lock check in
   `AA2dPool::add_transaction`.

3. **Phase 3 (finalize)**  
   On successful insert, `commit()` releases locks and invalidates any prefetch cache entries for
   affected senders. On failure, `rollback()` releases locks and retains cache entries for reuse.

This TIP does not modify consensus rules, block validity, transaction execution, storage layout, gas costs, or subblock encoding. The conflict detector operates exclusively within the mempool. Actual nonce validation for block execution happens separately in `tempo-revm/src/handler.rs`. Transactions that bypass the pool (e.g., injected directly into a block by a validator) are still validated by the EVM handler.

---

# Invariants

1. **Lock exclusivity**: At most one `LockSet` may hold a lock on any given `(sender, nonce_key)` pair at any time. Concurrent `phase2_check_and_lock` calls for the same nonce key MUST fail with `AlreadyLocked`.

2. **Lock cleanup on drop**: If a `LockSet` is dropped without calling `commit()`, all its locks MUST be released from the `locked_nonces` map. No lock may leak.

3. **Commit invalidates cache**: After `commit()`, the prefetch cache entries for all affected senders MUST be removed. The next admission for those senders MUST trigger a fresh state fetch.

4. **Rollback preserves cache**: After `rollback()`, prefetch cache entries MUST be preserved. The state has not changed, so cached values remain valid.

5. **Prefetch deduplication**: For any sender, at most one state fetch MUST be in-flight at any time. Concurrent batches referencing the same sender MUST share the same `PrefetchPromise`.

6. **Nonce monotonicity**: `phase2_check_and_lock` MUST reject transactions where `sequence_id < on_chain_sequence_id` for the given nonce key. Transactions at or above the on-chain sequence ID are permitted.

7. **Atomicity per batch**: If any transaction in a batch fails `phase2_check_and_lock`, all locks acquired for preceding transactions in that batch MUST be released before the error is returned.

8. **No consensus impact**: The conflict detector operates exclusively within the mempool. It MUST NOT affect block building, block validation, or transaction execution in the EVM handler.

9. **Lock expiry**: Locks that are neither committed nor rolled back MUST be forcibly released after the configured timeout. Expired locks MUST NOT block new admission attempts.

10. **Idempotent finalize**: Calling `phase3_finalize` with `success = false` on an already-dropped `LockSet` MUST be safe (no double-release, no panic).
