//! Tests for [`Hybrid`] focused on:
//!
//! - [`Blocks`] semantics (`put`, `get`, `sync`, `prune`, `missing_items`,
//!   `next_gap`, `last_index`),
//! - the prunable → reth fallback on the read path,
//! - the rollback-safety contract: legacy is dual-written before prunable,
//!   never read from on `get`, and a legacy write failure must abort the
//!   put before the prunable archive is advanced,
//! - retention pruning kicks in once enough blocks have been put.
//!
//! Tests use [`commonware_runtime::deterministic`] for reproducible runs
//! and a hand-rolled [`StubProvider`] (see [`utils`]) to isolate [`Hybrid`]
//! from reth's full provider stack. The same helpers are also reused by
//! [`crate::storage::legacy`]'s tests, hence the `pub(in crate::storage)`
//! visibility on the [`utils`] module.

pub(in crate::storage) mod utils;

use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::NZU64;

use super::*;
use utils::{
    StubProvider, fresh_legacy, fresh_prunable, fresh_prunable_with_section_size, make_block,
    make_chain,
};

/// Force every height into its own section so the prunable archive's
/// `prune(min)` (which rounds down to the nearest section boundary) acts
/// at single-height granularity. Required for any test that asserts on
/// pruning/retention behavior.
const PER_HEIGHT_SECTION: std::num::NonZeroU64 = NZU64!(1);

/// Default retention used by most tests; small enough to exercise the
/// pruning path with a handful of blocks while still leaving room to
/// observe pre-prune behavior.
const RETENTION: u64 = 4;

fn build_hybrid<TContext>(
    prunable: Prunable<TContext>,
    legacy: Option<Legacy<TContext>>,
    provider: StubProvider,
    retention_blocks: u64,
) -> Hybrid<TContext, StubProvider>
where
    TContext: BufferPooler + Storage + Metrics + Clock + Send + Sync + 'static,
{
    Hybrid::new(Config {
        prunable,
        legacy,
        provider,
        retention_blocks,
    })
}

/// Round-trip: a freshly-put block is reachable via [`Blocks::get`] both
/// by index and by digest, without consulting the reth provider.
#[test_traced]
fn get_returns_block_from_prunable_archive() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "get_prunable_hit").await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider.clone(), RETENTION);

        let blocks = make_chain(1, 3);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // By index.
        let by_index = hybrid
            .get(Identifier::Index(2))
            .await
            .expect("get by index")
            .expect("present");
        assert_eq!(by_index, blocks[1]);

        // By digest.
        let digest = blocks[2].digest();
        let by_digest = hybrid
            .get(Identifier::Key(&digest))
            .await
            .expect("get by digest")
            .expect("present");
        assert_eq!(by_digest, blocks[2]);
    });
}

/// On a prunable miss the read falls back to reth, both for index and
/// digest lookups. The "canonical only" restriction on hash lookups is
/// enforced inside the [`super::FinalizedBlocksProvider`] blanket impl
/// (see [`super`]); the test stub doesn't model `BlockSource` at all
/// because [`Hybrid`] never sees that detail any more.
#[test_traced]
fn get_falls_back_to_reth_on_prunable_miss() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "get_reth_miss").await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider.clone(), RETENTION);

        // Seed reth with an "old" block that the prunable archive will
        // never know about.
        let chain = make_chain(1, 5);
        let only_in_reth = &chain[0];
        provider.add_block(only_in_reth);

        // Also put one block into the prunable archive so we can assert
        // the prunable hit path was tried first.
        let in_prunable = chain[4].clone();
        hybrid.put(in_prunable.clone()).await.expect("put");

        // Index path: prunable miss → reth hit.
        let height = only_in_reth.height();
        let fetched = hybrid
            .get(Identifier::Index(height.get()))
            .await
            .expect("get by index")
            .expect("present in reth");
        assert_eq!(fetched, *only_in_reth);

        // Digest path: prunable miss → reth hit.
        let digest = only_in_reth.digest();
        let fetched = hybrid
            .get(Identifier::Key(&digest))
            .await
            .expect("get by digest")
            .expect("present in reth");
        assert_eq!(fetched, *only_in_reth);
    });
}

/// When neither the prunable archive nor reth has the block, [`Blocks::get`]
/// returns `Ok(None)` — never an error.
#[test_traced]
fn get_returns_none_when_neither_archive_nor_reth_has_block() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "get_full_miss").await;
        let provider = StubProvider::new();
        let hybrid = build_hybrid(prunable, None, provider, RETENTION);

        let result = hybrid.get(Identifier::Index(7)).await.expect("get");
        assert!(result.is_none());

        let digest = make_chain(1, 1).pop().unwrap().digest();
        let result = hybrid.get(Identifier::Key(&digest)).await.expect("get");
        assert!(result.is_none());
    });
}

/// A `put` past the retention window evicts the oldest entries from the
/// prunable cache once reth's finalized watermark advances past them.
/// Eviction is triggered on each `put`, so we seed the cache, advance
/// reth's watermark, and then drive one more put to trigger eviction.
/// The evicted blocks then transparently roll over to the reth fallback
/// (see [`get_falls_back_to_reth_on_prunable_miss`]).
#[test_traced]
fn put_trims_prunable_archive_to_retention() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable =
            fresh_prunable_with_section_size(&context, "put_trim", PER_HEIGHT_SECTION).await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider.clone(), RETENTION);

        // Phase 1: seed heights 1..=N. With reth's finalized watermark
        // unset, no eviction happens.
        let blocks = make_chain(1, (RETENTION as usize) + 3);
        let highest = blocks.last().unwrap().height().get();
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // Phase 2: advance reth's watermark to `highest` and trigger
        // eviction with one more put. Eviction floor =
        // `highest - RETENTION + 1`. With PER_HEIGHT_SECTION there is no
        // section overshoot, so the cache snaps to that floor.
        provider.set_reth_finalized(highest);
        let trigger = make_block(highest + 1, blocks.last().unwrap().block_hash());
        hybrid.put(trigger).await.expect("put trigger");

        // The newest `RETENTION` seeded blocks plus the trigger must
        // remain.
        for height in (highest + 1 - RETENTION)..=(highest + 1) {
            let hit = hybrid
                .get(Identifier::Index(height))
                .await
                .expect("get retained");
            assert!(hit.is_some(), "height {height} should remain in prunable");
        }

        // Anything older must have been evicted. Because reth was never
        // seeded with the actual blocks, those reads now return None.
        for height in 1..(highest + 1 - RETENTION) {
            let miss = hybrid
                .get(Identifier::Index(height))
                .await
                .expect("get evicted");
            assert!(miss.is_none(), "height {height} should have been evicted");
        }

        assert_eq!(hybrid.last_index(), Some(Height::new(highest + 1)));
    });
}

/// Index-, gap-, and last-index-reporting must reflect the prunable
/// archive only. Reth is treated as opaque to the marshal's gap repair
/// logic.
#[test_traced]
fn missing_items_next_gap_and_last_index_reflect_prunable_only() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "gaps").await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider.clone(), 32);

        // Seed reth with a contiguous low-height chain so we can confirm
        // these methods do NOT see it.
        let reth_chain = make_chain(1, 5);
        for block in &reth_chain {
            provider.add_block(block);
        }

        // Put a non-contiguous set of heights (10 and 12) into prunable.
        let blocks = make_chain(10, 3); // heights 10, 11, 12
        hybrid.put(blocks[0].clone()).await.expect("put 10");
        hybrid.put(blocks[2].clone()).await.expect("put 12");

        // Even though reth has 1..=5, missing_items starting at 9 only
        // reports gaps in the prunable archive's view of the world.
        let missing = hybrid.missing_items(Height::new(9), 8);
        assert_eq!(missing, vec![Height::new(9), Height::new(11)]);

        // next_gap reports the contiguous run around the queried height.
        let (current_end, next_start) = hybrid.next_gap(Height::new(10));
        assert_eq!(current_end, Some(Height::new(10)));
        assert_eq!(next_start, Some(Height::new(12)));

        // last_index reflects prunable, not reth.
        assert_eq!(hybrid.last_index(), Some(Height::new(12)));
    });
}

/// When a legacy archive is configured, every successful [`Blocks::put`]
/// is also written to it. Reads must still come from prunable/reth
/// (legacy is purely a write-through ledger for the previous binary's
/// sake).
#[test_traced]
fn put_dual_writes_to_legacy_when_present_and_get_skips_legacy() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable_with_section_size(
            &context,
            "dual_write_prunable",
            PER_HEIGHT_SECTION,
        )
        .await;
        let legacy = fresh_legacy(&context, "dual_write_legacy").await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, Some(legacy), provider.clone(), RETENTION);

        let blocks = make_chain(1, 3);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // The dual-write put-into-legacy is observable through the
        // hybrid's own legacy field.
        let legacy_ref = hybrid.legacy.as_ref().expect("legacy still attached");
        for block in &blocks {
            let stored =
                archive::Archive::get(legacy_ref, Identifier::Index(block.height().get()))
                    .await
                    .expect("legacy get");
            assert_eq!(stored.as_ref(), Some(block));
        }

        // Now blow the seeded heights out of the prunable cache by
        // advancing reth's finalized watermark far past them and
        // triggering eviction with one more put. With PER_HEIGHT_SECTION
        // the section-rounding overshoot is zero, so heights 1..=3 are
        // dropped cleanly. Because reads go prunable → reth (NOT
        // legacy), every height should now miss even though they
        // remain in legacy.
        let last = blocks.last().unwrap();
        provider.set_reth_finalized(last.height().get() + 100);
        let trigger = make_block(last.height().get() + 1, last.block_hash());
        hybrid.put(trigger).await.expect("put trigger");

        for block in &blocks {
            let result = hybrid
                .get(Identifier::Index(block.height().get()))
                .await
                .expect("get after evict");
            assert!(
                result.is_none(),
                "legacy must not be consulted on get; height {} should miss \
                 once prunable is evicted and reth is empty",
                block.height().get()
            );
        }
    });
}

/// `Hybrid::sync` must flush legacy too — otherwise a crash could leave
/// the previous binary's view inconsistent with what the new binary
/// reports as finalized.
#[test_traced]
fn sync_flushes_both_archives() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "sync_prunable").await;
        let legacy = fresh_legacy(&context, "sync_legacy").await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, Some(legacy), provider, RETENTION);

        let blocks = make_chain(1, 2);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }
        hybrid.sync().await.expect("sync should flush both archives");
    });
}

/// A repeated `put` at an existing index is silently no-op'd by the
/// prunable archive (it uses `skip_if_index_exists = true` internally).
/// This is intentional — the marshal calls `put` whenever it observes a
/// finalization, including replays — and we document the behavior here
/// so a future regression that started returning an error would be
/// caught immediately.
#[test_traced]
fn put_at_existing_index_is_idempotent() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "idempotent").await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider, RETENTION);

        let blocks = make_chain(1, 1);
        hybrid.put(blocks[0].clone()).await.expect("first put");
        hybrid.put(blocks[0].clone()).await.expect("idempotent put");

        let stored = hybrid
            .get(Identifier::Index(1))
            .await
            .expect("get")
            .expect("present");
        assert_eq!(stored, blocks[0]);
    });
}

/// Putting a block at a height below the prunable cache's
/// `oldest_allowed` floor must succeed as a silent no-op rather than
/// surfacing the prunable archive's `AlreadyPrunedTo` error. The cache
/// is just a cache; below its window reth is authoritative, so the
/// block is already durably persisted there (by reth's finality
/// contract that anything `≤ reth.finalized` cannot be reorged) and
/// the marshal's subsequent `get` will be served from the reth
/// fallback. Failing the put would crash the node via marshal's
/// `panic!("failed to finalize")` on a perfectly recoverable
/// condition. See the put implementation in [`super::Hybrid::put`].
///
/// Eviction is reth-driven, so the cache only collapses past height 1
/// once reth's finalized watermark advances; we pin it before putting.
#[test_traced]
fn put_below_retention_silently_succeeds_when_reth_covers_the_height() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable =
            fresh_prunable_with_section_size(&context, "below_retention", PER_HEIGHT_SECTION)
                .await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider.clone(), /* retention */ 2);

        // Phase 1: seed heights 1..=6 with reth's watermark unset
        // (no eviction yet).
        let blocks = make_chain(1, 6);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // Phase 2: advance reth's watermark and trigger eviction with
        // one more put. With PER_HEIGHT_SECTION the cache snaps to
        // exactly the requested floor (no section overshoot), so heights
        // <5 are dropped.
        provider.set_reth_finalized(6);
        let trigger = make_block(7, blocks.last().unwrap().block_hash());
        hybrid.put(trigger).await.expect("put trigger");

        // Phase 3: model "reth has the evicted height" by seeding the
        // stub provider with the original block. The marshal would
        // have observed this exact state in production: the block sits
        // in reth's storage at or below its finalized boundary, so
        // re-putting it must succeed silently.
        provider.add_block(&blocks[0]);
        hybrid
            .put(blocks[0].clone())
            .await
            .expect("re-put of an already-durable height must be a no-op success");

        // The block must still be reachable via `get` — but via the
        // reth fallback, not the prunable cache.
        let fetched = hybrid
            .get(Identifier::Index(blocks[0].height().get()))
            .await
            .expect("get after no-op put")
            .expect("block must be served from reth fallback");
        assert_eq!(fetched, blocks[0]);
    });
}

/// The prunable cache evicts in section-aligned batches, so the retained
/// window oscillates in `[R, R + S − 1]` rather than collapsing exactly
/// to `R` after every reth-watermark advance. With `S = 8` and `R = 16`
/// the test pins down both the maximum overshoot at
/// `reth_finalized = 30` (window of size `R + S − 1 = 23`) and the
/// immediate snap back to exactly `R` at `reth_finalized = 31`, where
/// the next section becomes evictable.
///
/// Stale puts (heights below the section-aligned `oldest_allowed`)
/// silently succeed because the corresponding block is already durable
/// in reth — see [`put_below_retention_silently_succeeds_when_reth_covers_the_height`]
/// for the rationale and the module docs ("Section-rounding") for the
/// eviction story.
#[test_traced]
fn prune_respects_section_boundary() {
    const SECTION: u64 = 8;
    const RETENTION: u64 = 16; // 2 * SECTION

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable_with_section_size(
            &context,
            "section_boundary",
            std::num::NonZeroU64::new(SECTION).unwrap(),
        )
        .await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider.clone(), RETENTION);

        // Phase 0: seed heights 1..=30 with reth's watermark unset
        // (no eviction yet).
        let blocks = make_chain(1, 30);
        for block in &blocks {
            hybrid.put(block.clone()).await.unwrap();
        }

        // Phase 1: advance reth's watermark to 23. Requested eviction
        // floor = 23 - 16 + 1 = 8, which is already a section boundary.
        // Trigger eviction with one more put. After this, sections
        // [0, 7] are dropped and the cache holds heights 8..=31.
        provider.set_reth_finalized(23);
        let next31 = make_block(31, blocks.last().unwrap().block_hash());
        hybrid.put(next31.clone()).await.expect("put 31");

        for height in 8..=31 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .expect("get retained")
                    .is_some(),
                "height {height} should remain after first eviction"
            );
        }
        for height in 1..8 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .expect("get evicted")
                    .is_none(),
                "height {height} should have been evicted (below section start)"
            );
        }

        // A re-put at height 7 (section-aligned `oldest_allowed = 8`,
        // so 7 is below it) must succeed silently — the block is below
        // the cache window, and reth's finality contract guarantees
        // it's durable in reth's storage.
        hybrid
            .put(blocks[6].clone())
            .await
            .expect("stale put at height 7 must silently succeed (reth covers it)");
        // A re-put at the section boundary still succeeds (silent
        // dedupe inside the prunable archive itself).
        hybrid
            .put(blocks[7].clone())
            .await
            .expect("re-put at oldest_allowed should dedupe, not error");

        // Phase 2: advance reth's watermark to 31. Requested eviction
        // floor = 31 - 16 + 1 = 16, which is the next section boundary.
        // Section [8, 15] is dropped after we trigger eviction; the
        // cache snaps to heights 16..=32.
        provider.set_reth_finalized(31);
        let next32 = make_block(32, next31.block_hash());
        hybrid.put(next32).await.expect("put 32");

        for height in 16..=32 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .expect("get retained")
                    .is_some(),
                "height {height} should remain after section roll"
            );
        }
        for height in 8..16 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .expect("get evicted")
                    .is_none(),
                "height {height} should be dropped after section roll"
            );
        }
        // Same silent-success contract after the next eviction roll.
        hybrid
            .put(blocks[14].clone())
            .await
            .expect("stale put at height 15 must silently succeed after section roll");
    });
}

/// A failure on the reth fallback path must propagate up as
/// [`Error::Provider`] from [`Blocks::get`] — the marshal turns this
/// into a panic (see this module's "Marshal panic behavior" docs), so
/// hiding it behind a silent `Ok(None)` would let a corrupted reth
/// database drive the marshal into resolver-driven gap repair against
/// data the operator probably needs to know is broken.
///
/// We assert both the index and digest paths because they go through
/// distinct provider methods.
#[test_traced]
fn reth_provider_errors_propagate_to_caller() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "reth_err").await;
        let provider = StubProvider::new();
        let hybrid = build_hybrid(prunable, None, provider.clone(), RETENTION);

        provider.set_fail(true);

        // Index path.
        let result = hybrid.get(Identifier::Index(99)).await;
        assert!(
            matches!(result, Err(Error::Provider(_))),
            "expected Error::Provider on index path, got {result:?}"
        );

        // Digest path.
        let digest = make_chain(99, 1).pop().unwrap().digest();
        let result = hybrid.get(Identifier::Key(&digest)).await;
        assert!(
            matches!(result, Err(Error::Provider(_))),
            "expected Error::Provider on digest path, got {result:?}"
        );
    });
}
