//! Tests for [`Hybrid`] focused on:
//!
//! - [`Blocks`] semantics (`put`, `get`, `sync`, `prune`, `missing_items`,
//!   `next_gap`, `last_index`),
//! - the prunable → reth fallback on the read path,
//! - retention pruning kicks in once enough blocks have been put.
//!
//! Tests use [`commonware_runtime::deterministic`] for reproducible runs
//! and a hand-rolled [`StubProvider`] (see [`utils`]) to isolate [`Hybrid`]
//! from reth's full provider stack.

pub(in crate::storage) mod utils;

use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Spawner, deterministic};
use commonware_utils::NZU64;

use super::*;
use crate::storage::PRUNABLE_ITEMS_PER_SECTION;
use utils::{StubProvider, fresh_prunable_with_section_size, make_block, make_chain};

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
        let provider = StubProvider::new();
        let hybrid = Hybrid::new(Config {
            prunable,
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
        // never know about. Advance reth's finalized watermark so the
        // by-height fallback path is allowed to return the seeded
        // block (the production provider gates `block_by_height` on
        // the finalized watermark).
        let chain = make_chain(1, 5);
        let only_in_reth = &chain[0];
        provider.add_block(only_in_reth);
        provider.set_reth_finalized(only_in_reth.height().get());

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
fn get_by_height_skips_reth_blocks_above_reth_finalized_watermark() {
    // The reth provider seeded a canonical-but-not-yet-finalized
    // block; the marshal must never see it. `block_by_height` is
    // gated on reth's finalized watermark — heights above it (and
    // everything but genesis when the watermark is unset) miss,
    // regardless of what is in reth's canonical chain.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (hybrid, provider) = SetupHybrid::default().build(&context).await;

        // Seed reth with a block at height 10 but leave reth's
        // finalized watermark unset (fresh chain) so the by-height
        // fallback is not allowed to surface it.
        let block = make_chain(10, 1).pop().unwrap();
        provider.add_block(&block);

        let result = hybrid
            .get(Identifier::Index(block.height().get()))
            .await
            .expect("get by index");
        assert!(
            result.is_none(),
            "by-height fallback must miss when reth has not finalized anything",
        );

        // Now advance reth's finalized watermark, but only up to
        // height 9 — still below the seeded block. The fallback must
        // still miss.
        provider.set_reth_finalized(block.height().get() - 1);
        let result = hybrid
            .get(Identifier::Index(block.height().get()))
            .await
            .expect("get by index");
        assert!(
            result.is_none(),
            "by-height fallback must miss when reth's finalized watermark is below the requested height",
        );

        // Finally, advance the watermark to cover the block — now the
        // fallback is allowed to return it.
        provider.set_reth_finalized(block.height().get());
        let fetched = hybrid
            .get(Identifier::Index(block.height().get()))
            .await
            .expect("get by index")
            .expect("present in reth at or below the finalized watermark");
        assert_eq!(fetched, block);
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
fn gap_tracking_treats_reth_finalized_as_covered_prefix() {
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

        provider.set_reth_finalized(5);

        // Put a non-contiguous tail into prunable. Heights 6 and 7
        // extend reth's covered prefix, while 10 and 12 leave real
        // gaps above the execution layer's finalized watermark.
        let blocks = make_chain(6, 7); // heights 6..=12
        for offset in [0, 1, 4, 6] {
            let block = blocks[offset].clone();
            hybrid.put(block).await.expect("put block");
        }

        // Heights 1..=5 are covered by reth and 6..=7 by prunable, so
        // only gaps above that merged range are reported.
        let missing = hybrid.missing_items(Height::new(1), 8);
        assert_eq!(
            missing,
            vec![Height::new(8), Height::new(9), Height::new(11)]
        );

        let (current_end, next_start) = hybrid.next_gap(Height::new(1));
        assert_eq!(current_end, Some(Height::new(7)));
        assert_eq!(next_start, Some(Height::new(10)));

        let (current_end, next_start) = hybrid.next_gap(Height::new(8));
        assert_eq!(current_end, None);
        assert_eq!(next_start, Some(Height::new(10)));

        let (current_end, next_start) = hybrid.next_gap(Height::new(10));
        assert_eq!(current_end, Some(Height::new(10)));
        assert_eq!(next_start, Some(Height::new(12)));

        // last_index reports the highest covered block from either source.
        assert_eq!(hybrid.last_index(), Some(Height::new(12)));
    });
}

#[test_traced]
fn gap_tracking_merges_prunable_run_overlapping_reth_watermark() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid::default().build(&context).await;

        // Reth covers 1..=5 and the prunable archive holds 3..=7 plus a
        // detached 10 — the production shape, where the retention window
        // overlaps reth coverage. `next_gap`'s probe at `watermark + 1`
        // (height 6) lands mid-run, so the merged covered range must be
        // reported as 1..=7 with the next run starting at 10.
        provider.set_reth_finalized(5);
        let blocks = make_chain(3, 8); // heights 3..=10
        for offset in [0, 1, 2, 3, 4, 7] {
            hybrid.put(blocks[offset].clone()).await.expect("put block");
        }

        assert_eq!(
            hybrid.next_gap(Height::new(1)),
            (Some(Height::new(7)), Some(Height::new(10)))
        );
        assert_eq!(
            hybrid.missing_items(Height::new(1), 8),
            vec![Height::new(8), Height::new(9)]
        );
        assert_eq!(hybrid.last_index(), Some(Height::new(10)));
    });
}

#[test_traced]
fn gap_tracking_works_when_only_reth_has_blocks() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (hybrid, provider) = SetupHybrid::default().build(&context).await;

        provider.set_reth_finalized(5);

        assert_eq!(hybrid.missing_items(Height::new(1), 8), Vec::new());
        assert_eq!(
            hybrid.next_gap(Height::new(1)),
            (Some(Height::new(5)), None)
        );
        assert_eq!(hybrid.last_index(), Some(Height::new(5)));
    });
}

/// Walks every case of [`Blocks::next_gap`]'s documented `# Behavior`
/// section against [`Hybrid`]'s merged view of coverage, where reth's
/// finalized watermark forms a range starting at genesis and the prunable
/// archive contributes the ranges above it.
#[test_traced]
fn next_gap_upholds_blocks_trait_behavior_contract() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (mut hybrid, provider) = SetupHybrid::default().build(&context).await;

        // "If the store is empty, both will be `None`." (Height 0 is the
        // one exception — genesis is implicitly covered; see
        // `genesis_is_implicitly_finalized_when_reth_watermark_is_unset`.)
        assert_eq!(hybrid.next_gap(Height::new(1)), (None, None));

        // "If `value` is before all ranges in the store,
        // `current_range_end` will be `None`" — and `next_range_start`
        // points at the first range.
        let blocks = make_chain(4, 6); // heights 4..=9
        hybrid.put(blocks[4].clone()).await.expect("put 8");
        hybrid.put(blocks[5].clone()).await.expect("put 9");
        assert_eq!(
            hybrid.next_gap(Height::new(2)),
            (None, Some(Height::new(8)))
        );

        // Coverage is now [0..=5] (reth 0..=3 merged with prunable 4..=5)
        // and [8..=9].
        provider.set_reth_finalized(3);
        hybrid.put(blocks[0].clone()).await.expect("put 4");
        hybrid.put(blocks[1].clone()).await.expect("put 5");

        // "If `value` falls within an existing range `[r_start, r_end]`,
        // `current_range_end` will be `Some(r_end)`."
        assert_eq!(
            hybrid.next_gap(Height::new(2)),
            (Some(Height::new(5)), Some(Height::new(8)))
        );

        // "If `value` falls in a gap between two ranges `[..., prev_end]`
        // and `[next_start, ...]`, `current_range_end` will be `None` and
        // `next_range_start` will be `Some(next_start)`."
        assert_eq!(
            hybrid.next_gap(Height::new(6)),
            (None, Some(Height::new(8)))
        );

        // "If `value` is [...] within the last range, `next_range_start`
        // will be `None`."
        assert_eq!(
            hybrid.next_gap(Height::new(8)),
            (Some(Height::new(9)), None)
        );

        // "If `value` is after all ranges in the store [...]" — no range
        // contains it and none starts after it, so both are `None`.
        assert_eq!(hybrid.next_gap(Height::new(11)), (None, None));
    });
}

#[test_traced]
fn genesis_is_implicitly_finalized_when_reth_watermark_is_unset() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (hybrid, provider) = SetupHybrid::default().build(&context).await;

        // Reth's finalized watermark is unset (fresh chain), but genesis
        // can never be reorged: `get` serves it and gap tracking reports
        // it as covered, keeping both views of coverage consistent.
        let genesis = make_block(0, B256::ZERO);
        provider.add_block(&genesis);

        let fetched = hybrid
            .get(Identifier::Index(0))
            .await
            .expect("get genesis")
            .expect("genesis is implicitly finalized");
        assert_eq!(fetched, genesis);

        assert_eq!(
            hybrid.next_gap(Height::zero()),
            (Some(Height::zero()), None)
        );
        assert_eq!(hybrid.missing_items(Height::zero(), 8), Vec::new());
    });
}

#[test_traced]
fn sync_flushes_prunable_archive() {
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
            .expect("sync should flush prunable archive");
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
