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
use commonware_runtime::{Runner as _, Spawner, deterministic};
use commonware_utils::NZU64;

use super::*;
use crate::storage::PRUNABLE_ITEMS_PER_SECTION;
use utils::{StubProvider, fresh_legacy, fresh_prunable_with_section_size, make_block, make_chain};

/// Force every height into its own section so the prunable archive's
/// `prune(min)` (which rounds down to the nearest section boundary) acts
/// at single-height granularity. Required for any test that asserts on
/// pruning/retention behavior.
const PER_HEIGHT_SECTION: std::num::NonZeroU64 = NZU64!(1);

/// Default retention used by most tests; small enough to exercise the
/// pruning path with a handful of blocks while still leaving room to
/// observe pre-prune behavior.
const RETENTION: u64 = 4;

struct SetupHybrid {
    retention: u64,
    section_size: std::num::NonZeroU64,
}

impl Default for SetupHybrid {
    fn default() -> Self {
        Self {
            retention: RETENTION,
            section_size: PRUNABLE_ITEMS_PER_SECTION,
        }
    }
}

impl SetupHybrid {
    async fn build<TContext>(
        self,
        context: &TContext,
    ) -> (Hybrid<TContext, StubProvider>, StubProvider)
    where
        TContext:
            BufferPooler + Storage + Metrics + Clock + Spawner + Clone + Send + Sync + 'static,
    {
        let prunable = fresh_prunable_with_section_size(context, self.section_size).await;
        let legacy = fresh_legacy(context).await;
        let provider = StubProvider::new();
        let hybrid = Hybrid::new(Config {
            prunable,
            legacy,
            execution_block_provider: provider.clone(),
            retention_blocks: self.retention,
        });
        (hybrid, provider)
    }
}

#[test_traced]
fn get_returns_block_from_prunable_archive() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, _) = SetupHybrid::default().build(&context).await;

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

#[test_traced]
fn get_falls_back_to_reth_on_prunable_miss() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid::default().build(&context).await;

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

#[test_traced]
fn get_returns_none_when_neither_archive_nor_reth_has_block() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (hybrid, _) = SetupHybrid::default().build(&context).await;

        let result = hybrid.get(Identifier::Index(7)).await.expect("get");
        assert!(result.is_none());

        let digest = make_chain(1, 1).pop().unwrap().digest();
        let result = hybrid.get(Identifier::Key(&digest)).await.expect("get");
        assert!(result.is_none());
    });
}

#[test_traced]
fn put_trims_prunable_archive_to_retention() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            section_size: PER_HEIGHT_SECTION,
            ..Default::default()
        }
        .build(&context)
        .await;

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

#[test_traced]
fn missing_items_next_gap_and_last_index_reflect_prunable_only() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            retention: 32,
            ..Default::default()
        }
        .build(&context)
        .await;

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

#[test_traced]
fn put_dual_writes_to_legacy_and_get_skips_legacy() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            section_size: PER_HEIGHT_SECTION,
            ..Default::default()
        }
        .build(&context)
        .await;

        let blocks = make_chain(1, 3);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // The dual-write put-into-legacy is observable through the
        // hybrid's own legacy field.
        for block in &blocks {
            let stored =
                archive::Archive::get(&hybrid.legacy, Identifier::Index(block.height().get()))
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

#[test_traced]
fn sync_flushes_both_archives() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, _) = SetupHybrid::default().build(&context).await;

        let blocks = make_chain(1, 2);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }
        hybrid
            .sync()
            .await
            .expect("sync should flush both archives");
    });
}

#[test_traced]
fn put_at_existing_index_is_idempotent() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, _) = SetupHybrid::default().build(&context).await;

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

#[test_traced]
fn put_below_retention_silently_succeeds_when_reth_covers_the_height() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            retention: 2,
            section_size: PER_HEIGHT_SECTION,
        }
        .build(&context)
        .await;

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

#[test_traced]
fn prune_respects_section_boundary() {
    const SECTION: u64 = 8;
    const RETENTION: u64 = 16; // 2 * SECTION

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            retention: RETENTION,
            section_size: std::num::NonZeroU64::new(SECTION).unwrap(),
        }
        .build(&context)
        .await;

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

#[test_traced]
fn mid_section_prune_floor_keeps_live_tail_in_cache() {
    const SECTION: u64 = 4;
    const RETENTION: u64 = 5;

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            retention: RETENTION,
            section_size: std::num::NonZeroU64::new(SECTION).unwrap(),
        }
        .build(&context)
        .await;

        // Phase 0: seed heights 1..=10 with reth's watermark unset
        // (no eviction yet).
        let blocks = make_chain(1, 10);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // Phase 1: advance reth to 10 → requested floor = 6, which sits
        // inside section [4, 7]. Archive rounds 6 down to 4 and drops
        // only section [0, 3]. Trigger eviction with one more put.
        provider.set_reth_finalized(10);
        let trigger = make_block(11, blocks.last().unwrap().block_hash());
        hybrid.put(trigger).await.expect("put trigger");

        // Make the reth fallback fail loudly so we can distinguish
        // prunable hits from reth hits — anything that survives the
        // eviction must be served from the cache, not from reth.
        provider.set_fail(true);

        // Heights 4..=11 must come from the prunable cache. Heights 4
        // and 5 are the "live tail": below the requested retention
        // floor (6) but at or above the section-aligned oldest_allowed
        // (4).
        for height in 4..=11 {
            let block = hybrid
                .get(Identifier::Index(height))
                .await
                .unwrap_or_else(|err| {
                    panic!("height {height} should hit prunable cache, got {err:?}")
                })
                .unwrap_or_else(|| panic!("height {height} should be present in cache"));
            assert_eq!(block.height().get(), height);
        }

        // Heights 1..=3 sat in the dropped section [0, 3] and now fall
        // through to reth, which is failing — confirms the eviction
        // boundary is exactly the section start, not the requested
        // floor.
        for height in 1..=3 {
            let result = hybrid.get(Identifier::Index(height)).await;
            assert!(
                matches!(result, Err(Error::Provider(_))),
                "height {height} should fall through to reth fallback, got {result:?}"
            );
        }
    });
}

#[test_traced]
fn mid_section_silent_no_op_floor_is_section_aligned_not_requested() {
    const SECTION: u64 = 4;
    const RETENTION: u64 = 5;

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            retention: RETENTION,
            section_size: std::num::NonZeroU64::new(SECTION).unwrap(),
        }
        .build(&context)
        .await;

        // Same setup as the live-tail test: seed 1..=10, advance reth
        // to 10, trigger eviction. After this oldest_allowed=4 and
        // requested_floor=6.
        let blocks = make_chain(1, 10);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }
        provider.set_reth_finalized(10);
        let trigger = make_block(11, blocks.last().unwrap().block_hash());
        hybrid.put(trigger).await.expect("put trigger");

        // Heights 1..=3 sit below the section-aligned `oldest_allowed`
        // (4) and must silently no-op — surfacing the prunable's
        // `AlreadyPrunedTo` here would crash the marshal on a
        // perfectly recoverable condition.
        for height in 1..=3 {
            hybrid
                .put(blocks[(height - 1) as usize].clone())
                .await
                .unwrap_or_else(|err| {
                    panic!("stale put at height {height} must succeed silently, got {err:?}")
                });
        }

        // Heights 4 and 5 sit in the live tail of the partially-evicted
        // section. The archive accepts these puts directly (4 ≥
        // oldest_allowed=4); they do NOT take the `AlreadyPrunedTo`
        // branch even though they are below the requested retention
        // floor of 6.
        for height in 4..=5 {
            hybrid
                .put(blocks[(height - 1) as usize].clone())
                .await
                .unwrap_or_else(|err| {
                    panic!("re-put at live-tail height {height} must dedupe, got {err:?}")
                });
        }
    });
}

#[test_traced]
fn eviction_no_op_when_advancing_reth_within_same_section() {
    const SECTION: u64 = 4;
    const RETENTION: u64 = 5;

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid {
            retention: RETENTION,
            section_size: std::num::NonZeroU64::new(SECTION).unwrap(),
        }
        .build(&context)
        .await;

        // Phase 0: seed heights 1..=15 with reth's watermark unset.
        let blocks = make_chain(1, 15);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // Phase 1: reth=10 → rounded floor = 4 → drop section [0, 3].
        // Trigger eviction with put at 16; cache now spans 4..=16.
        provider.set_reth_finalized(10);
        let next16 = make_block(16, blocks.last().unwrap().block_hash());
        hybrid.put(next16.clone()).await.expect("put 16");
        for height in 4..=16 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .unwrap()
                    .is_some(),
                "height {height} should remain after first eviction"
            );
        }

        // Phase 2: reth=11 → requested floor = 7, still rounded to 4 →
        // no further eviction. Trigger with put at 17; section [4, 7]
        // must still be in the cache.
        provider.set_reth_finalized(11);
        let next17 = make_block(17, next16.block_hash());
        hybrid.put(next17.clone()).await.expect("put 17");
        for height in 4..=17 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .unwrap()
                    .is_some(),
                "height {height} should remain after intra-section reth advance"
            );
        }

        // Phase 3: reth=12 → rounded floor = 8 → drop section [4, 7].
        // Trigger with put at 18; cache snaps to 8..=18.
        provider.set_reth_finalized(12);
        let next18 = make_block(18, next17.block_hash());
        hybrid.put(next18).await.expect("put 18");
        for height in 8..=18 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .unwrap()
                    .is_some(),
                "height {height} should remain after section roll"
            );
        }
        for height in 4..=7 {
            assert!(
                hybrid
                    .get(Identifier::Index(height))
                    .await
                    .unwrap()
                    .is_none(),
                "height {height} should be dropped after section [4, 7] is evicted"
            );
        }
    });
}

#[test_traced]
fn reth_provider_errors_propagate_to_caller() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (hybrid, provider) = SetupHybrid::default().build(&context).await;

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
