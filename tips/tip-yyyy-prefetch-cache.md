---
id: TIP-YYYY
title: Promise-Based State Prefetching for Transaction Validation
description: Deduplicate database reads during transaction pool validation by sharing a single state fetch across multiple transactions from the same sender.
author: Artem Bogomaz (artembogomaz@gmail.com)
status: Draft
related:
protocolVersion: TBD
---

# TIP-YYYY: Promise-Based State Prefetching for Transaction Validation

## Abstract

This TIP introduces a `PrefetchCache` that deduplicates state reads during transaction pool validation. When multiple transactions from the same sender arrive in a batch, they share a single database fetch via a promise-based mechanism instead of each triggering independent queries. The optimization is confined to the mempool validator — it does not alter consensus, block validity, or on-chain state.

## Motivation

The transaction pool validator (`validator.rs`) performs ~7–10 storage reads per transaction during `validate_one()`:

1. Keychain authorization at `ACCOUNT_KEYCHAIN_ADDRESS` (1–2 reads)
2. Fee token configuration: `get_fee_token()`, `is_valid_fee_token()`, `is_fee_token_paused()`, `can_fee_payer_transfer()` (4 reads)
3. Token balance: `get_token_balance()` (1 read)
4. Nonce state at `NONCE_PRECOMPILE_ADDRESS` (1–2 reads)
5. AMM liquidity check (1 read)

The batch validation path (`validate_transactions()`) already shares a single `state_provider` across all transactions, but there is no deduplication of reads. For N transactions from the same sender, the same keychain, fee token, and balance slots are read N times.

Under high load (e.g., market-making bots submitting 50+ transactions per sender), this causes:
- ~500 redundant database reads per batch
- I/O bottleneck on the state provider
- Increased latency for transaction admission

With a prefetch cache, the same batch requires ~10 reads total per unique sender regardless of transaction count.

**Alternatives considered:**

- **Synchronous `HashMap` cache**: Simple but requires serializing all reads. The promise-based approach allows the first reader to initiate the fetch while subsequent readers wait on the same result without blocking the validation loop.
- **Thread-local caching**: Avoids synchronization but does not share across concurrent validator tasks. Multiple validation tasks for the same sender would still duplicate reads.
- **State provider-level caching**: Would require modifying the reth `StateProvider` trait. The prefetch cache sits above this boundary and requires no upstream changes.

---

# Specification

## PrefetchPromise

A promise represents a pending, completed, or failed state fetch. Multiple consumers can subscribe to the same promise; all receive the result when it resolves.

### States

```rust
enum PromiseState<T> {
    Pending(Vec<oneshot::Sender<Arc<T>>>),
    Ready(Arc<T>),
    Failed(String),
}
```

| State | Description |
|-------|-------------|
| `Pending` | Fetch in progress; waiters accumulate in the channel list |
| `Ready` | Fetch completed; value available via `Arc<T>` |
| `Failed` | Fetch failed; error message stored for all waiters |

### Operations

| Operation | Behavior |
|-----------|----------|
| `get()` | If `Ready`, return value immediately. If `Pending`, subscribe and await. If `Failed`, return error. |
| `complete(value)` | Transition from `Pending` to `Ready`; notify all waiters. |
| `fail(error)` | Transition from `Pending` to `Failed`. |

The internal state is protected by a `parking_lot::RwLock`. The lock is held only for the state check and waiter registration (not during the fetch itself), so contention is minimal.

## PrefetchCache

A concurrent map from key to `PrefetchPromise`. The `get_or_create` method provides double-checked locking: read lock first, then write lock only if the key is absent.

### Operations

| Operation | Behavior |
|-----------|----------|
| `get_or_create(key)` | Returns `(promise, should_fetch)`. If the key exists, returns the existing promise with `should_fetch = false`. Otherwise creates a new `Pending` promise and returns `should_fetch = true`. |
| `invalidate(key)` | Removes the entry. Used when a block commits and the cached state becomes stale. |
| `clear()` | Removes all entries. Used on chain reorg or validator restart. |

## Sender State

The cached value per sender aggregates all state reads needed for validation:

```rust
pub struct SenderState {
    pub balance: U256,
    pub nonce: u64,
    pub keychain_keys: Vec<KeyAuthorization>,
    pub fee_token: Option<Address>,
    pub fee_token_paused: bool,
}
```

This is fetched once per unique sender per batch, then shared across all that sender's transactions.

## Validation Flow

### Current Flow (per transaction)

```
validate_one(tx):
  sender = tx.sender()
  balance = state_provider.get_token_balance(sender)          // SLOAD
  nonce = state_provider.storage(NONCE_PRECOMPILE, slot)       // SLOAD
  keychain = state_provider.storage(KEYCHAIN_ADDRESS, slot)    // SLOAD
  fee_token = state_provider.get_fee_token(sender)             // SLOAD
  ... (7-10 reads total)
  validate_against_state(tx, balance, nonce, keychain, ...)
```

For 50 transactions from the same sender: ~500 reads.

### Updated Flow (per transaction)

```
validate_one(tx):
  sender = tx.sender()
  (promise, should_fetch) = prefetch_cache.get_or_create(sender)
  if should_fetch:
    spawn(fetch_sender_state(sender) -> promise.complete/fail)
  state = promise.get().await
  validate_against_state(tx, state)
```

For 50 transactions from the same sender: ~10 reads (one fetch) + 49 cache hits.

### Batch Prefetch

For incoming batches, senders can be prefetched before individual validation begins:

```rust
pub async fn prefetch_batch(&self, senders: Vec<Address>) {
    let mut to_fetch = Vec::new();
    for sender in senders {
        let (promise, should_fetch) = self.prefetch_cache.get_or_create(&sender);
        if should_fetch {
            to_fetch.push((sender, promise));
        }
    }
    for (sender, promise) in to_fetch {
        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            match Self::fetch_sender_state(&db, sender).await {
                Ok(state) => promise.complete(state),
                Err(e) => promise.fail(e.to_string()),
            }
        });
    }
}
```

This enables all fetches to start in parallel before any validation begins.

## Cache Invalidation

The cache MUST be invalidated when the underlying state changes:

| Event | Action |
|-------|--------|
| Block committed | `invalidate(sender)` for each sender touched in the block |
| Chain reorg | `clear()` the entire cache |
| Validator restart | Cache starts empty (no persistence) |

Stale cache entries would cause validation to accept transactions that should be rejected (e.g., balance already spent) or reject transactions that should be accepted (e.g., nonce already advanced). Since mempool validation is re-checked during block execution, stale entries cannot cause invalid blocks — but they degrade pool quality.

## Implementation Location

- Add `PrefetchPromise` and `PrefetchCache` to: `tempo-transaction-pool/src/prefetch.rs` (new file)
- Integrate in: `tempo-transaction-pool/src/validator.rs` — wrap `validate_one()` and batch methods
- Invalidation hook: `tempo-transaction-pool/src/validator.rs` — existing `on_new_state` / block notification path

This TIP does not modify consensus rules, block validity, transaction execution, storage layout, gas costs, or subblock encoding. The mempool validator is explicitly off-chain — consensus-level validation happens separately in `tempo-revm/src/handler.rs`. Stale prefetch entries cannot cause invalid blocks because all transactions are re-validated during EVM execution.

---

# Invariants

1. **Fetch deduplication**: For any sender `S`, at most one database fetch MUST be in-flight at any time within the cache. Concurrent `get_or_create(S)` calls MUST share the same promise.

2. **Waiter notification**: When a promise transitions from `Pending` to `Ready`, all registered waiters MUST receive the value. No waiter may be silently dropped.

3. **Failure propagation**: When a promise transitions from `Pending` to `Failed`, all registered waiters MUST receive the error. Waiters registered after failure MUST also receive the error.

4. **Invalidation completeness**: After `invalidate(sender)`, the next `get_or_create(sender)` MUST return a fresh `Pending` promise with `should_fetch = true`. Stale values MUST NOT be returned.

5. **Validation equivalence**: The validation result for any transaction MUST be identical whether the state was fetched directly or via the prefetch cache. The cache is a performance optimization, not a behavioral change.

6. **No consensus impact**: The prefetch cache operates exclusively within the mempool validator. It MUST NOT affect block building, block validation, or transaction execution in the EVM handler.

7. **Lock scope**: The `RwLock` on promise state MUST NOT be held during the database fetch. Only the state check and waiter registration are performed under the lock.

8. **Cache lifetime**: Cache entries MUST NOT survive block boundaries without explicit invalidation. The cache MUST be fully cleared on chain reorg.
