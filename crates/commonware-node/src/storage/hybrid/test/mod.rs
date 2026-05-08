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
    StubProvider, fresh_legacy, fresh_prunable, fresh_prunable_with_section_size, make_chain,
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

        // The provider was never consulted because every height was in
        // the prunable archive; in particular nothing was looked up by
        // hash via `find_block_by_hash`.
        assert!(provider.find_block_by_hash_calls().is_empty());
    });
}

/// On a prunable miss the read falls back to reth, both for index and
/// digest lookups. For digest lookups we additionally assert that
/// [`BlockSource::Canonical`] is used (not `Any`), so the marshal can
/// never be served a pending in-memory block.
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

        // Digest path: prunable miss → reth hit, with Canonical source.
        let digest = only_in_reth.digest();
        let fetched = hybrid
            .get(Identifier::Key(&digest))
            .await
            .expect("get by digest")
            .expect("present in reth");
        assert_eq!(fetched, *only_in_reth);

        let calls = provider.find_block_by_hash_calls();
        assert_eq!(calls.len(), 1, "expected exactly one fallback hash lookup");
        assert_eq!(calls[0].0, digest.0);
        assert_eq!(
            calls[0].1,
            BlockSource::Canonical,
            "hybrid must restrict reth lookups to the canonical chain"
        );
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

/// A `put` past the retention window prunes the oldest entries from the
/// prunable archive. The pruned blocks then transparently roll over to
/// the reth fallback (see [`get_falls_back_to_reth_on_prunable_miss`]).
#[test_traced]
fn put_trims_prunable_archive_to_retention() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable =
            fresh_prunable_with_section_size(&context, "put_trim", PER_HEIGHT_SECTION).await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider, RETENTION);

        // Put strictly more than `RETENTION` blocks.
        let blocks = make_chain(1, (RETENTION as usize) + 3);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // The newest `RETENTION` blocks must remain.
        let highest = blocks.last().unwrap().height().get();
        for height in (highest + 1 - RETENTION)..=highest {
            let hit = hybrid
                .get(Identifier::Index(height))
                .await
                .expect("get retained");
            assert!(hit.is_some(), "height {height} should remain in prunable");
        }

        // Anything older must have been pruned. Because reth was never
        // seeded, those reads now return None.
        for height in 1..(highest + 1 - RETENTION) {
            let miss = hybrid
                .get(Identifier::Index(height))
                .await
                .expect("get pruned");
            assert!(miss.is_none(), "height {height} should have been pruned");
        }

        assert_eq!(hybrid.last_index(), Some(Height::new(highest)));
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
        let mut hybrid = build_hybrid(prunable, Some(legacy), provider, RETENTION);

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

        // Now blow away the prunable archive's data by pruning past the
        // last index. Because reads go prunable → reth (NOT legacy),
        // every height should now miss even though they remain in legacy.
        hybrid
            .prune(Height::new(blocks.last().unwrap().height().get() + 1))
            .await
            .expect("prune past tip");

        for block in &blocks {
            let result = hybrid
                .get(Identifier::Index(block.height().get()))
                .await
                .expect("get after prune");
            assert!(
                result.is_none(),
                "legacy must not be consulted on get; height {} should miss \
                 once prunable is pruned and reth is empty",
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

/// Putting a block at a height below the prunable archive's
/// `oldest_allowed` floor must be rejected with
/// [`archive::Error::AlreadyPrunedTo`]. Combined with the dual-write
/// order in [`Hybrid::put`] (legacy first, then prunable), this
/// guarantees that a put which the *new* binary considers ancient never
/// silently advances *just* legacy — the put as a whole errors out.
#[test_traced]
fn put_below_retention_returns_error() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable =
            fresh_prunable_with_section_size(&context, "below_retention", PER_HEIGHT_SECTION)
                .await;
        let provider = StubProvider::new();
        let mut hybrid = build_hybrid(prunable, None, provider, /* retention */ 2);

        // Establish a tip far enough above 1 to push the retention floor
        // past it.
        let blocks = make_chain(1, 6);
        for block in &blocks {
            hybrid.put(block.clone()).await.expect("put");
        }

        // Re-putting an old (now-pruned) block must be rejected.
        let result = hybrid.put(blocks[0].clone()).await;
        assert!(
            matches!(result, Err(archive::Error::AlreadyPrunedTo(_))),
            "expected AlreadyPrunedTo, got {result:?}"
        );
    });
}

/// A [`block_by_number`] failure on the reth fallback path must surface
/// as `Ok(None)` from [`Blocks::get`] — the marshal will then drive
/// repair via its resolver. We keep the contract of "missing or unknown
/// → None" rather than propagating the reth error so transient provider
/// blips don't crash the marshal.
#[test_traced]
fn reth_provider_errors_are_surfaced_as_none() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let prunable = fresh_prunable(&context, "reth_err").await;
        let provider = StubProvider::new();
        let hybrid = build_hybrid(prunable, None, provider.clone(), RETENTION);

        provider.set_fail(true);

        // Index path.
        let result = hybrid.get(Identifier::Index(99)).await.expect("get");
        assert!(result.is_none());

        // Digest path.
        let digest = make_chain(99, 1).pop().unwrap().digest();
        let result = hybrid.get(Identifier::Key(&digest)).await.expect("get");
        assert!(result.is_none());
    });
}
