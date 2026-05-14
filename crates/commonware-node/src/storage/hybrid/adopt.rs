//! Opens (or creates) the [`Legacy`] archive for dual-write into the
//! [`Hybrid`] store on startup, preserving the rollback-safety contract.
//!
//! On every restart this module:
//!
//! 1. Opens the legacy immutable finalized blocks archive — creating its
//!    partitions on disk if they don't yet exist.
//! 2. Copies any of the most-recent `retention_blocks` heights from
//!    legacy into the prunable archive that aren't already there
//!    (idempotent; a no-op against an empty legacy archive).
//! 3. Returns the open legacy archive so the [`Hybrid`] store can keep
//!    writing every newly finalized block to it as well (dual-write).
//!
//! Whether the legacy archive is opened at all is the operator's choice
//! via the `--no-legacy-archive` flag (see [`crate::args`]); this module
//! is only invoked when dual-write is enabled. The legacy archive is
//! **never** destroyed automatically — an operator removes the legacy
//! partitions manually once they are confident they will not need to
//! roll back.
//!
//! Living in [`super`] (the `hybrid` module) keeps the dependency direction
//! clean: `legacy` knows nothing about hybrid, but hybrid knows about both
//! itself and legacy.
//!
//! [`Hybrid`]: super::Hybrid
//! [`Legacy`]: crate::storage::legacy::Legacy

use std::time::Instant;

use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::Identifier;
use eyre::WrapErr as _;
use tracing::{debug, info, instrument, warn};

use super::Prunable;
use crate::storage::legacy::{Legacy, init_legacy_finalized_blocks_archive};

/// Open (or create) the legacy immutable finalized blocks archive,
/// backfill any missing recent heights into the prunable archive, and
/// return the legacy archive so the caller can keep dual-writing into
/// it.
///
/// Always opens the archive when called — the decision of whether to
/// keep a legacy archive at all is made by the operator via the
/// `--no-legacy-archive` flag in [`crate::args`], not by probing the
/// disk for prior state. On a fresh node this creates empty legacy
/// partitions; the backfill step is then a no-op.
///
/// This step is idempotent: rerunning it after a successful boot only
/// re-checks the most recent `retention_blocks` heights and skips
/// entries that are already in the prunable archive.
#[instrument(skip_all, err)]
pub(in crate::storage) async fn open_legacy_for_dual_write<TContext>(
    context: &TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
    prunable: &mut Prunable<TContext>,
    retention_blocks: u64,
) -> eyre::Result<Legacy<TContext>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    info!(
        "opening legacy immutable finalized blocks archive for dual-write \
         and backfilling prunable archive with any missing recent heights"
    );
    let started = Instant::now();

    let legacy = init_legacy_finalized_blocks_archive(context, partition_prefix, page_cache)
        .await
        .wrap_err("failed opening legacy immutable finalized blocks archive")?;

    let copied = backfill_recent_into_prunable(&legacy, prunable, retention_blocks)
        .await
        .wrap_err("failed backfilling recent finalized blocks into prunable archive")?;

    info!(
        copied,
        elapsed = %tempo_telemetry_util::display_duration(started.elapsed()),
        "legacy archive ready for dual-write",
    );

    Ok(legacy)
}

/// Copy any of the most recent `retention_blocks` heights from `legacy`
/// into `prunable` that are not already present.
///
/// We walk the entire `[copy_from..=last]` range on every restart and
/// rely on a per-height `has` check against `prunable` to skip work that
/// has already happened. Reading the legacy archive only happens when the
/// prunable archive is actually missing the height, so the steady-state
/// cost is `retention_blocks` in-memory `has` calls — no legacy reads,
/// no prunable writes, no sync. This also covers any internal gaps that
/// may have been left in `prunable` by an interrupted prior backfill.
async fn backfill_recent_into_prunable<TContext>(
    legacy: &Legacy<TContext>,
    prunable: &mut Prunable<TContext>,
    retention_blocks: u64,
) -> eyre::Result<u64>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let Some(last) = commonware_storage::archive::Archive::last_index(legacy) else {
        info!("legacy archive present but empty; nothing to backfill");
        return Ok(0);
    };
    let first = commonware_storage::archive::Archive::first_index(legacy).unwrap_or(0);
    let retention_floor = last.saturating_sub(retention_blocks.saturating_sub(1));
    let copy_from = retention_floor.max(first);

    info!(
        first,
        last,
        copy_from,
        retention_blocks,
        "checking legacy archive for finalized blocks missing from prunable archive"
    );

    let mut copied = 0u64;
    for height in copy_from..=last {
        // Skip heights that the prunable archive already has — `has` on a
        // numeric index is an in-memory lookup, so this avoids reading from
        // legacy in the steady state when prunable already covers the
        // retention window.
        if commonware_storage::archive::Archive::has(prunable, Identifier::Index(height))
            .await
            .wrap_err_with(|| format!("checking prunable archive for height {height}"))?
        {
            continue;
        }

        match commonware_storage::archive::Archive::get(legacy, Identifier::Index(height))
            .await
            .wrap_err_with(|| format!("reading height {height} from legacy archive"))?
        {
            Some(block) => {
                match commonware_consensus::marshal::store::Blocks::put(prunable, block).await {
                    Ok(()) => copied += 1,
                    // The prunable archive rounds its prune floor *down*
                    // to a section boundary, so `oldest_allowed` may sit
                    // above the height we computed `copy_from` from. Any
                    // legacy entry that lands below it has already been
                    // pruned out of the working window and the copy is a
                    // no-op; treat it as covered and continue.
                    Err(commonware_storage::archive::Error::AlreadyPrunedTo(oldest_allowed)) => {
                        debug!(
                            height,
                            oldest_allowed,
                            "skipping legacy backfill: height is below prunable's oldest_allowed"
                        );
                    }
                    Err(err) => {
                        return Err(err).wrap_err_with(|| {
                            format!("backfilling height {height} into prunable archive")
                        });
                    }
                }
            }
            None => {
                // The legacy archive's `last_index` reports the highest
                // height ever written; gaps are possible. Skip them.
                warn!(height, "legacy archive has gap; skipping during backfill");
            }
        }
    }

    if copied > 0 {
        <Prunable<TContext> as commonware_consensus::marshal::store::Blocks>::sync(prunable)
            .await
            .wrap_err("syncing prunable archive after backfill")?;
    }

    Ok(copied)
}

#[cfg(test)]
mod tests {
    //! Tests for the legacy-archive adoption logic.
    //!
    //! Cover the guarantees described in the module header:
    //!
    //! - [`open_legacy_for_dual_write`] always returns an open archive,
    //!   creating empty partitions on a fresh node.
    //! - [`backfill_recent_into_prunable`]:
    //!     - copies only the newest `retention_blocks` heights from legacy,
    //!     - skips heights already present in prunable (idempotent),
    //!     - tolerates gaps within the legacy archive,
    //!     - is a no-op against an empty legacy archive.
    use commonware_consensus::Heightable as _;
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, deterministic};

    use super::{
        super::test::utils::{fresh_legacy, fresh_prunable, make_chain},
        *,
    };
    use crate::consensus::block::Block;

    /// Drop every block in `blocks` into `legacy` via the archive's raw
    /// `put` API (the legacy archive accepts arbitrary, non-monotonic
    /// indices).
    async fn seed_legacy<TContext>(legacy: &mut Legacy<TContext>, blocks: &[Block])
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    {
        for block in blocks {
            commonware_storage::archive::Archive::put(
                legacy,
                block.height().get(),
                block.digest(),
                block.clone(),
            )
            .await
            .expect("seed legacy");
        }
    }

    #[test_traced]
    fn open_legacy_for_dual_write_creates_empty_archive_on_fresh_node() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut prunable = fresh_prunable(&context).await;
            let cache = commonware_runtime::buffer::paged::CacheRef::from_pooler(
                &context,
                commonware_utils::NZU16!(4_096),
                commonware_utils::NZUsize!(64),
            );

            let legacy = open_legacy_for_dual_write(
                &context,
                "fresh_node",
                cache,
                &mut prunable,
                /* retention */ 4,
            )
            .await
            .expect("legacy open should succeed on a fresh node");

            assert!(
                commonware_storage::archive::Archive::last_index(&legacy).is_none(),
                "freshly-created legacy archive must be empty"
            );
        });
    }

    #[test_traced]
    fn backfill_copies_recent_heights_into_prunable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut legacy = fresh_legacy(&context).await;
            let mut prunable = fresh_prunable(&context).await;

            // Seed legacy with 6 contiguous blocks at heights 1..=6.
            let chain = make_chain(1, 6);
            seed_legacy(&mut legacy, &chain).await;
            commonware_storage::archive::Archive::sync(&mut legacy)
                .await
                .expect("sync legacy");

            // Backfill with retention 4 ⇒ copy heights 3..=6 only.
            let copied = backfill_recent_into_prunable(&legacy, &mut prunable, 4)
                .await
                .expect("backfill");
            assert_eq!(copied, 4, "should have copied retention_blocks heights");

            // Heights 3..=6 must now be present in prunable.
            for height in 3..=6 {
                let stored =
                    commonware_storage::archive::Archive::get(&prunable, Identifier::Index(height))
                        .await
                        .expect("get backfilled");
                let expected = &chain[(height - 1) as usize];
                assert_eq!(stored.as_ref(), Some(expected));
            }

            // Heights 1..=2 (below the retention floor) must NOT have been
            // copied.
            for height in 1..=2 {
                let stored =
                    commonware_storage::archive::Archive::get(&prunable, Identifier::Index(height))
                        .await
                        .expect("get below retention");
                assert!(
                    stored.is_none(),
                    "height {height} below retention floor should not be backfilled"
                );
            }
        });
    }

    #[test_traced]
    fn backfill_is_idempotent_and_skips_existing_heights() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut legacy = fresh_legacy(&context).await;
            let mut prunable = fresh_prunable(&context).await;

            // Seed legacy with 3 blocks.
            let chain = make_chain(1, 3);
            seed_legacy(&mut legacy, &chain).await;
            commonware_storage::archive::Archive::sync(&mut legacy)
                .await
                .expect("sync legacy");

            // First backfill copies all 3.
            let first = backfill_recent_into_prunable(&legacy, &mut prunable, 16)
                .await
                .expect("first backfill");
            assert_eq!(first, 3);

            // Second backfill (e.g. on the next restart) finds prunable
            // already covers the retention window and copies nothing.
            let second = backfill_recent_into_prunable(&legacy, &mut prunable, 16)
                .await
                .expect("second backfill");
            assert_eq!(second, 0, "rerunning backfill must be a no-op");
        });
    }

    #[test_traced]
    fn backfill_tolerates_gaps_in_legacy_archive() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut legacy = fresh_legacy(&context).await;
            let mut prunable = fresh_prunable(&context).await;

            // Seed legacy with non-contiguous heights {1, 3, 5}. The
            // immutable archive accepts arbitrary indices.
            let chain = make_chain(1, 5);
            let to_seed = [&chain[0], &chain[2], &chain[4]];
            for block in to_seed {
                commonware_storage::archive::Archive::put(
                    &mut legacy,
                    block.height().get(),
                    block.digest(),
                    block.clone(),
                )
                .await
                .expect("seed legacy");
            }
            commonware_storage::archive::Archive::sync(&mut legacy)
                .await
                .expect("sync legacy");

            // Backfill with retention 8 ⇒ scans heights 1..=5.
            let copied = backfill_recent_into_prunable(&legacy, &mut prunable, 8)
                .await
                .expect("backfill");
            assert_eq!(
                copied, 3,
                "only heights actually present in legacy should be copied"
            );

            // Heights 1, 3, 5 are present; 2 and 4 are gaps and must be
            // missing in prunable too.
            for height in [1u64, 3, 5] {
                let stored =
                    commonware_storage::archive::Archive::get(&prunable, Identifier::Index(height))
                        .await
                        .expect("get");
                assert!(stored.is_some(), "height {height} should be present");
            }
            for height in [2u64, 4] {
                let stored =
                    commonware_storage::archive::Archive::get(&prunable, Identifier::Index(height))
                        .await
                        .expect("get gap");
                assert!(
                    stored.is_none(),
                    "gap height {height} must not appear in prunable"
                );
            }
        });
    }

    #[test_traced]
    fn backfill_returns_zero_for_empty_legacy() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let legacy = fresh_legacy(&context).await;
            let mut prunable = fresh_prunable(&context).await;

            let copied = backfill_recent_into_prunable(&legacy, &mut prunable, 16)
                .await
                .expect("backfill empty");
            assert_eq!(copied, 0);
        });
    }
}
