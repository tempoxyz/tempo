# PR #2696 Review: Move Peer Handling to Peer Manager

**Author:** Richard Janis Goldschmidt (@SuperFluffy)  
**Branch:** `janis/reconcile-in-peer-actor`  
**Stats:** +625 / -431 across 10 files  
**Related:** #2181, #2617 (prep for TIP 1017 Val Config V2)

---

## Summary

This PR extracts peer reconciliation logic (reading the validator config contract, constructing peer sets, and calling `track()` on the P2P manager) **out of the DKG actor** and **into the peer manager actor**. Previously, the DKG actor owned the full lifecycle: on every epoch boundary it read the contract, built a peer set from `{dealers, players, active validators}`, and registered it. Now that responsibility lives in the peer manager — a cleaner separation of concerns in preparation for Val Config V2.

---

## Architecture Change

```
BEFORE:
  Marshal ──(finalized blocks)──► DKG Actor ──(read contract, build peer set, track)──► P2P Oracle

AFTER:
  Marshal ──(finalized blocks)──► Peer Manager Actor ──(read contract, build peer set, track)──► P2P Oracle
  Marshal ──(finalized blocks)──► DKG Actor  (no longer touches peers)
```

The peer manager is now a full `Reporter` subscriber of the marshal, receiving finalized block updates alongside the DKG actor, executor, and epoch manager.

---

## Key Changes

### 1. New `validators.rs` module (crate-level)
- **File:** `crates/commonware-node/src/validators.rs` (270 lines, new)
- Extracted from `dkg/manager/validators.rs` and the DKG actor
- Contains:
  - `ReadTarget` enum (`AtLeast { height }`, `Exact { height }`) — replaces the old `Target` enum
  - `read_validator_config_with_retry()` — the retry loop for reading the contract
  - `read_validator_config_at_height()` — EVM state read at a specific block
  - `read_from_contract_at_height()` — decodes raw validators from contract
  - `DecodedValidator` struct + `decode_from_contract()`
- Visibility is `pub(crate)` — shared between DKG actor and peer manager

### 2. Peer Manager Actor (`peer_manager/actor.rs`)
- **Gained:** `TContext` generic (needs `Clock + Metrics + Spawner`), `ContextCell`, epoch strategy, `last_finalized_height`, metrics (`contract_read_attempts`, `peers` gauge)
- **New method:** `bootstrap_initial_peers()` — reads the boundary block's DKG outcome + validator config at startup
- **New method:** `handle_finalized_block()` — on each epoch boundary, reads DKG outcome from `extra_data`, reads validator config, constructs peer set, calls `track()`
- **New function:** `construct_peer_set()` — builds `{dealers ∪ players ∪ active validators}` mapped to `Address::Symmetric(outbound)`
- **New stub:** `is_past_hardfork()` — returns `false`; placeholder for V2 logic

### 3. Peer Manager Config (`peer_manager/mod.rs`)
- Config now includes `epoch_strategy` and `last_finalized_height`
- `init()` now takes a `TContext` (previously stateless)
- Actor construction moved **after** marshal init in `engine.rs` so `last_finalized_height` is available

### 4. DKG Actor Cleanup
- **Removed:** `peer_manager` field from `Config<TPeerManager>` → `Config` (no longer generic over peer manager)
- **Removed:** `Actor<TContext, TPeerManager>` → `Actor<TContext>`
- **Removed:** `construct_peer_set()`, `read_validator_config_with_retry()`, `Target` enum from DKG actor
- **Removed:** `boundary_of_parent_epoch()` from `state.rs`
- **Removed:** `peers` gauge metric from DKG metrics
- DKG actor's `run_dkg_loop` no longer calls `track()` — it only builds DKG state
- DKG `validators.rs` reduced to thin re-exports + `read_next_full_dkg_ceremony()`

### 5. Engine Wiring (`consensus/engine.rs`)
- `epoch_strategy` created earlier (before marshal init)
- Peer manager init moved **after** marshal init to receive `last_finalized_height`
- `resolver_config` also moved after peer manager init
- Marshal's `Reporters` chain includes `peer_manager_mailbox` (was already there)
- DKG `Config` no longer takes `peer_manager` field

### 6. E2E Tests (`e2e/src/tests/sync.rs`)
- Minor: snapshot-sync tests now preserve `peer_manager` from `consensus_config` across identity swaps

---

## Review Findings

### ✅ Positives

1. **Clean separation of concerns** — Peer management is now fully owned by one actor. The DKG actor focuses purely on cryptographic ceremony logic.
2. **Consistent peer set construction** — `construct_peer_set()` uses `outcome.dealers()` + `outcome.next_players()` + active validators, which matches the documented semantics.
3. **Bootstrap on startup** — The peer manager now bootstraps from the last boundary block's DKG outcome, which is critical for nodes starting from a snapshot.
4. **Good error handling** — `bootstrap_initial_peers()` returns an error that halts the actor if initial peer set can't be built. `handle_finalized_block()` errors propagate and shut down the actor.
5. **Metrics preserved** — `peers` gauge and `contract_read_attempts` counter migrated correctly.

### ⚠️ Items to Verify / Potential Concerns

#### 1. Semantic difference in `construct_peer_set` — `state.players()` vs `outcome.next_players()`
- **Old (DKG actor):** Used `state.dealers()`, `state.players()`, and `state.syncers` (all from `State`)
- **New (peer manager):** Uses `outcome.dealers()`, `outcome.next_players()`, and active validators from contract
- These _should_ be equivalent since `State.players` comes from `onchain_outcome.next_players` and `State.syncers` comes from active validators. But worth confirming the old `State` fields map 1:1 to the on-chain outcome fields used now.

#### 2. `ReadTarget::AtLeast` vs old `Target::Best` semantics
- **Old:** `Target::Best { min_height }` — read from `best_block_number()` if ≥ `min_height`, else use `min_height`
- **New:** `ReadTarget::AtLeast { height }` — identical logic
- ✅ Semantically equivalent, just renamed.

#### 3. DKG actor still reads validators at boundary (but for different purpose)
- The DKG actor still calls `read_validator_config_with_retry()` at epoch boundary to build `syncers` for the new `State`. It uses `ReadTarget::Exact { height }`.
- The peer manager _also_ reads at the boundary using `ReadTarget::AtLeast { height }`.
- **This means double contract reads at every epoch boundary.** This is likely fine (idempotent EVM reads), but worth noting for future optimization.

#### 4. Bootstrap boundary calculation
- The peer manager calculates `last_boundary` differently than the old DKG code:
  - If `last_finalized_height == epoch_info.last()` → use it directly
  - Otherwise → use previous epoch's last block (or genesis)
- The old DKG code used `state.boundary_of_parent_epoch()` which was `epoch.previous().map_or(Height::zero, |prev| epoch_strategy.last(prev))`
- These serve different purposes (bootstrap vs ongoing), so the difference is expected.

#### 5. `is_past_hardfork` stub
- Currently always returns `false`. Has a TODO comment about reading Val Config V2.
- Fine for now, but the hardfork branch `warn!`s and **falls through without tracking any peers**. After the hardfork, if this isn't implemented, the peer set won't update.

#### 6. Panic in `construct_peer_set`
- `validators.get_value(key).expect(...)` will panic if a DKG participant is not in the contract validator set. This matches the old behavior and the invariant is documented. The comment is clear about the expectation.

#### 7. Error on bootstrap prevents actor from starting
- If `bootstrap_initial_peers()` fails, the peer manager logs an error and returns, which causes the `try_join_all` in the engine to fail and shut down the node. This is the correct behavior — a node can't operate without peers.

#### 8. Header retry loop in `bootstrap_initial_peers`
- Uses a manual retry with exponential backoff (1s to 30s) waiting for the header at the boundary height. This is necessary because the execution layer may lag behind the consensus layer's `last_finalized_height`. Matches the pattern used elsewhere.

#### 9. `ack.acknowledge()` placement in `handle_finalized_block`
- Acknowledgment is called **after** the peer set is tracked, which is correct — the block is only acknowledged after processing is complete.

---

## Testing

- E2E sync tests updated to preserve `peer_manager` config across identity swaps
- No new unit tests for `construct_peer_set()` or `bootstrap_initial_peers()` — these are integration-tested through existing E2E tests
- **Recommendation:** Consider adding a unit test for `construct_peer_set()` to validate the union logic and the `expect` panic path

---

## Verdict

**Approve with minor comments.** The refactor is well-structured and correctly migrates peer handling to its dedicated actor. The key invariants are preserved, error handling is solid, and it cleanly prepares the codebase for Val Config V2. The double contract read at epoch boundaries is a minor inefficiency but acceptable for correctness and separation of concerns.
