# Page-state branch fix: split trie input from persisted hashed state

Status: fix design for `codex/page-state-implementation`, 2026-07-06. Diagnosis of the failed
benchmark run (3 blocks vs baseline 508, zero metric samples) and the concrete changes.

## Root cause

On storage v2, `HashedPostState` is three things at once:

1. the trie input for state-root computation;
2. the write-set persisted to `HashedStorages` — which is also the execution **read** path;
3. what `MemoryOverlayStateProvider` serves for un-persisted blocks.

The branch rewrites the single object (`sentinel::apply` replaces each touched page account's
`HashedStorage` with sentinel-only) to fix (1), which corrupts (2) and (3). Three symptoms:

- **Stale reads killed the run.** The transformed hashed state is what both paths hand to the
  engine (`crates/node/src/page_state.rs:219` `with_hashed_state(...)`;
  `crates/payload/builder/src/lib.rs:1333` `hashed_state: Arc::new(hashed_state)`), so
  page-account slot writes never reach the overlay or the tables. The first tx reading a value
  written in an earlier post-activation block sees pre-activation state → executor rejects →
  nonce errors → stall at block ~3. Deterministic, not a perf symptom.
- **`wiped=false` leaves init bloat in the trie** (`manager.rs:175`), so the commitment is
  bloat + sentinel; the benchmark measures nothing even when it runs.
- **Discarded mutations / unseeded page store.** The validator mutates a clone of `output.state`
  and drops it (`page_state.rs:198`); `init-from-binary-dump` never seeds the page store, so
  first-touch pages start from `Page::default()` and SMT roots don't commit seeded state.

## Key insight

`wiped: true` is only destructive because the same object reaches persistence. In reth's trie
computation, a wiped `HashedStorage` makes the overlay cursor (`HashedPostStateStorageCursor`,
i.e. the self-destruct machinery) ignore **all DB rows** for that account and rebuild its storage
trie purely from post-state entries. `HashedStorages` rows are only deleted if the wiped flag
reaches `write_hashed_state`. So: compute the root from a **trie-only view** with
`wiped=true` + sentinel, and hand the **untouched original** to the engine. Both properties —
raw storage readable, sentinel-only commitment — with no custom cursors and no reth changes.

## Changes

### 1. `crates/page-state/src/manager.rs`

```rust
pub struct PageBlockOutput {
    pub updates: PageStateUpdates,
    /// hashed_state clone with each touched page account's storage replaced by
    /// HashedStorage { wiped: true, storage: { sentinel_hashed: new_root } }.
    pub trie_input: HashedPostState,
}

pub fn process_block(
    &self,
    timestamp: u64,
    parent_hash: B256,
    bundle: &BundleState,           // no longer &mut
    hashed_state: &HashedPostState, // no longer &mut — NEVER modified
) -> Result<PageBlockOutput, PageStateError>;
```

- Delete `insert_sentinel_plain_storage`. The sentinel is no longer a readable slot or a bundle
  write; it exists only as a synthesized leaf in `trie_input` (keep the defensive sentinel-slot
  skip in dirty-word collection or drop it — it can no longer occur).
- `sentinel::apply` loses the `wiped` closure param: it always sets `wiped: true` and only ever
  writes into the trie view.

### 2. `crates/node/src/page_state.rs` — `TempoPageStateRootJob::finish`

```rust
let out = self.manager.process_block(
    self.timestamp, block.parent_hash(), &output.state, hashed_state.get().as_ref())?;
let provider = self.provider_builder.clone().build()?;
let (state_root, trie_updates) = provider.state_root_with_updates(out.trie_input)?;
// outcome carries the ORIGINAL hashed state (pass the lazy's inner through unchanged)
Ok(StateRootJobOutcome::new(state_root, Arc::new(trie_updates))
    .with_hashed_state(Some(/* original, untransformed */)))
```

Drop the `output.state.clone()` — no bundle mutation exists anymore.

### 3. `crates/payload/builder/src/lib.rs`

- Keep `hashed_state` untransformed. When active:
  `let page_out = manager.process_block(ts, parent_header.hash(), &db.bundle_state, &hashed_state)?`.
- Root call (`:1119`): `state_root_with_updates(page_out.trie_input)` when active, else
  `hashed_state.clone()` as today.
- Packaging (`:1333`) keeps the untransformed `hashed_state`.

### 4. Trie-table cleanup comes free

`wiped=true` per touched account emits `StorageTrieUpdates { is_deleted: true, .. }`, so
persistence clears that account's `StoragesTrie` rows and writes the sentinel-only nodes —
lazily evicting init bloat from the trie tables on first touch. (With the init fix below, fresh
benchmark DBs never contain bloat trie nodes in the first place.)

### 5. `bin/tempo/src/init_state.rs`

- **Seed the page store** while streaming the dump (entries are plain `(address, slot, value)`):
  ETL-sort by `(address, page_index, offset)`, assemble pages, bulk-build each account's SMT
  (add `PageSmt::build_bulk(sorted_pages)` or feed `update` in batches), write
  `PageBlobs`/`PageNodes`/`PageRoots`, set the page-env watermark to block 0.
- **Filter the trie build** (the manual `DbStateRoot` construction at `:394` is the seam): wrap
  the from_tx cursor factories with reth's standard `HashedPostStateCursorFactory` whose overlay
  post-state contains `HashedStorage { wiped: true, storage: { sentinel: page_root } }` for every
  page account (roots from the just-built SMTs). `HashedStorages` keeps ALL raw rows (reads);
  `StoragesTrie` and account leaves commit sentinel-only storage roots. Thread the overlay
  through the chunked/resume path.
- Keep writing plain-keyed storage changesets/history — they are the preimage source recovery
  depends on (below).

### 6. `crates/page-state/src/recovery.rs` — v2 corrections

- Per-page rebuild (`page(address, index)`) stays: 128 point lookups via
  `StateProvider::storage(address, slot)` work on v2 (the provider hashes the slot).
- Full-account rebuild (`account_pages`, `page_accounts`) requires plain-slot **enumeration**,
  which hashed tables cannot provide. The plain-keyed changesets + the init-seeded baseline are
  the only recovery mechanism: make the watermark-`None` path a hard error ("re-run
  init-from-binary-dump") instead of a silent full scan.
- `sentinel_root` self-check: there is no plain sentinel slot anymore — read the committed root
  from the account's storage-trie leaf (or recompute the account storage root), or defer the
  self-check to a follow-up.

## Rerun checklist (bench validity)

- Regression for the stale-read bug: read a pre-activation bloat slot and a block-N page write at
  block N+2; both must return correct values.
- Same token touched in consecutive un-persisted blocks commits correctly (exercises
  wiped-storage propagation through `StateTrieOverlayManager` — the self-destruct/recreate path).
- `HashedStorages` row count stays ~flat while per-account `StoragesTrie` shrinks on first touch.
- Builder/validator page metrics record nonzero samples; feature branch block count comparable to
  baseline before comparing latencies.
- No double commitment: assert page accounts' storage tries contain exactly one leaf after touch.
