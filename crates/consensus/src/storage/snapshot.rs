use commonware_consensus::{
    Heightable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier, immutable};
use eyre::{OptionExt as _, WrapErr as _, eyre};
use reth_provider::{BlockIdReader, BlockReader};

use crate::{
    consensus::{Digest, block::Block},
    storage::{
        BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
        init_prunable_finalized_blocks_archive,
    },
};

type FinalizationsArchive<TContext> =
    immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>;

/// Consensus state prepared for inclusion in an execution snapshot.
pub struct State {
    /// Highest finalized execution block in the EL snapshot source.
    pub execution_finalized_height: u64,
    /// Block digest for the highest finalized execution block in the EL
    /// snapshot source.
    pub execution_finalized_digest: Digest,
    /// Highest finalization certificate height known to consensus storage.
    pub tip_finalization_height: u64,
    /// Block digest carried by the highest finalization certificate known to
    /// consensus storage.
    pub tip_finalization_digest: Digest,
    /// Anchor finalization certificate height used to bootstrap consensus.
    pub anchor_finalization_height: u64,
    /// Block digest carried by the anchor finalization certificate.
    pub anchor_finalization_digest: Digest,
}

/// Consensus archive entry to copy into the snapshot archive.
pub struct ArchiveEntry(ArchiveEntryKind);

struct Certificate {
    height: u64,
    finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
}
enum ArchiveEntryKind {
    Certificate(Box<Certificate>),
    Block(Box<Block>),
}

/// Prepares consensus storage state for snapshot packaging.
///
/// Finalization certificates and finalized blocks are streamed to the supplied
/// archive writer. The returned state records both the latest consensus
/// finalization point and the anchor point. When the anchor is above execution
/// finalized, selection proves the source prunable archive contains a
/// contiguous path from execution finalized to the anchor.
pub async fn prepare<TContext, P>(
    context: &TContext,
    storage_partition_prefix: &str,
    execution_provider: P,
    archive_entries: tokio::sync::mpsc::Sender<ArchiveEntry>,
) -> eyre::Result<State>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    P: BlockIdReader + BlockReader<Block = tempo_primitives::Block> + Send + Sync,
{
    let page_cache = CacheRef::from_pooler(context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let execution_finalized = execution_provider
        .finalized_block_num_hash()
        .wrap_err("failed to read finalized execution block num hash")?
        .ok_or_eyre("no finalized execution state")?;
    let execution_finalized_height = execution_finalized.number;
    let execution_finalized_digest = Digest(execution_finalized.hash);

    let finalizations =
        init_finalizations_archive(context, storage_partition_prefix, page_cache.clone())
            .await
            .wrap_err("failed to open finalizations-by-height archive")?;
    let prunable =
        init_prunable_finalized_blocks_archive(context, storage_partition_prefix, page_cache)
            .await
            .wrap_err("failed to open prunable finalized blocks archive")?;

    let selected =
        find_anchor_and_tip_finalizations(&finalizations, &prunable, execution_finalized_height)
            .await?;

    stream_finalization_archive_entries(
        &finalizations,
        selected.anchor_height,
        selected.tip_height,
        &archive_entries,
    )
    .await?;

    stream_block_archive_entries(&prunable, execution_finalized_height, &archive_entries).await?;

    Ok(State {
        execution_finalized_height,
        execution_finalized_digest,
        tip_finalization_height: selected.tip_height,
        tip_finalization_digest: selected.tip_digest,
        anchor_finalization_height: selected.anchor_height,
        anchor_finalization_digest: selected.anchor_digest,
    })
}

/// Returns whether `name` is one of the finalized-block prunable storage
/// partitions that must be copied into a consensus snapshot archive.
pub fn is_prunable_finalized_blocks_partition(storage_partition_prefix: &str, name: &str) -> bool {
    name.starts_with(&archive_partition_prefix(
        storage_partition_prefix,
        super::PRUNABLE_FINALIZED_BLOCKS,
    ))
}

/// Returns whether `name` is a consensus storage partition that can appear in a
/// consensus snapshot archive.
pub fn is_snapshot_storage_partition(storage_partition_prefix: &str, name: &str) -> bool {
    name.starts_with(&archive_partition_prefix(
        storage_partition_prefix,
        super::FINALIZATIONS_BY_HEIGHT,
    )) || is_prunable_finalized_blocks_partition(storage_partition_prefix, name)
}

fn archive_partition_prefix(storage_partition_prefix: &str, archive_name: &str) -> String {
    format!("{storage_partition_prefix}-{archive_name}-")
}

/// Materialize consensus archive entries into fresh storage archives.
pub async fn write_archive<TContext>(
    context: &TContext,
    storage_partition_prefix: &str,
    mut entries: tokio::sync::mpsc::Receiver<ArchiveEntry>,
) -> eyre::Result<()>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let page_cache = CacheRef::from_pooler(context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let mut finalizations =
        init_finalizations_archive(context, storage_partition_prefix, page_cache.clone())
            .await
            .wrap_err("failed to open snapshot finalizations-by-height archive")?;
    let mut blocks =
        init_prunable_finalized_blocks_archive(context, storage_partition_prefix, page_cache)
            .await
            .wrap_err("failed to open snapshot prunable finalized blocks archive")?;

    while let Some(entry) = entries.recv().await {
        match entry.0 {
            ArchiveEntryKind::Certificate(cert) => {
                let Certificate {
                    height,
                    finalization,
                } = *cert;
                let key = finalization.proposal.payload;
                finalizations
                    .put(height, key, finalization)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed writing snapshot finalization certificate at height `{height}`",
                        )
                    })?;
            }
            ArchiveEntryKind::Block(block) => {
                let height = block.height().get();
                let key = block.digest();
                blocks.put(height, key, *block).await.wrap_err_with(|| {
                    format!("failed writing snapshot finalized block at height `{height}`")
                })?;
            }
        }
    }

    finalizations
        .sync()
        .await
        .wrap_err("failed syncing snapshot finalizations-by-height archive")?;
    blocks
        .sync()
        .await
        .wrap_err("failed syncing snapshot prunable finalized blocks archive")
}

#[cfg_attr(test, derive(Debug))]
struct AnchorAndTipFinalizations {
    tip_height: u64,
    tip_digest: Digest,
    anchor_height: u64,
    anchor_digest: Digest,
}

async fn stream_finalization_archive_entries<TContext>(
    finalizations: &FinalizationsArchive<TContext>,
    anchor_height: u64,
    tip_height: u64,
    archive_entries: &tokio::sync::mpsc::Sender<ArchiveEntry>,
) -> eyre::Result<()>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let mut height = anchor_height;

    loop {
        if let Some(finalization) = finalizations
            .get(Identifier::Index(height))
            .await
            .wrap_err_with(|| {
                format!("failed reading finalization certificate at height `{height}`")
            })?
        {
            archive_entries
                .send(ArchiveEntry(ArchiveEntryKind::Certificate(
                    Certificate {
                        height,
                        finalization,
                    }
                    .into(),
                )))
                .await
                .map_err(|_| {
                    eyre!(
                        "snapshot finalizations archive writer closed while sending certificate \
                        at height `{height}`"
                    )
                })?;
        }

        if height == tip_height {
            break;
        }

        height = height
            .checked_add(1)
            .ok_or_else(|| eyre!("tip finalization height cannot exceed u64::MAX"))?;
    }

    Ok(())
}

async fn stream_block_archive_entries<TContext>(
    prunable: &super::hybrid::Prunable<TContext>,
    execution_finalized_height: u64,
    archive_entries: &tokio::sync::mpsc::Sender<ArchiveEntry>,
) -> eyre::Result<()>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let Some(first_height) = execution_finalized_height.checked_add(1) else {
        return Ok(());
    };
    for (start, end) in prunable.ranges_from(first_height) {
        for height in start.max(first_height)..=end {
            if let Some(block) = prunable
                .get(Identifier::Index(height))
                .await
                .wrap_err_with(|| {
                    format!("failed reading prunable finalized block at height `{height}`")
                })?
            {
                archive_entries
                    .send(ArchiveEntry(ArchiveEntryKind::Block(Box::new(block))))
                    .await
                    .map_err(|_| {
                        eyre!(
                            "snapshot prunable archive writer closed while sending block at \
                            height `{height}`"
                        )
                    })?;
            }
        }
    }

    Ok(())
}

async fn find_anchor_and_tip_finalizations<TContext>(
    finalizations: &FinalizationsArchive<TContext>,
    prunable: &super::hybrid::Prunable<TContext>,
    execution_finalized_height: u64,
) -> eyre::Result<AnchorAndTipFinalizations>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let tip_height = finalizations
        .last_index()
        .ok_or_else(|| eyre!("no finalization certificates found"))?;
    let tip_finalization = finalizations
        .get(Identifier::Index(tip_height))
        .await
        .wrap_err_with(|| {
            format!("failed reading finalization certificate at height `{tip_height}`")
        })?
        .ok_or_else(|| {
            eyre!(
                "finalization archive reported latest height \
                `{tip_height}` but no certificate was present"
            )
        })?;

    let tip_digest = tip_finalization.proposal.payload;
    let mut candidate_height = tip_height;
    let mut candidate_digest = tip_digest;

    // Try to find a path from `candidate_height` to `execution_finalized_height`.
    // If there are no holes, then the anchor is the candidate.
    //
    // If there is a hole (missing block) find the certificate for the greatest
    // height below that the hole and try to find a path again.
    //
    // If no path can be found, then take the certificate at the execution height
    // or the closest cert below.
    loop {
        if candidate_height <= execution_finalized_height {
            return Ok(AnchorAndTipFinalizations {
                tip_height,
                tip_digest,
                anchor_height: candidate_height,
                anchor_digest: candidate_digest,
            });
        }

        let Some(hole) =
            find_first_prunable_hole(prunable, candidate_height, execution_finalized_height)
                .await?
        else {
            return Ok(AnchorAndTipFinalizations {
                tip_height,
                tip_digest,
                anchor_height: candidate_height,
                anchor_digest: candidate_digest,
            });
        };

        let Some((next_height, next_digest)) =
            find_nearest_finalization_below(finalizations, hole).await?
        else {
            return Err(eyre!(
                "no finalization certificate found in a contiguous prunable \
                finalized-block range from execution finalized \
                `{execution_finalized_height}` to tip finalization \
                `{tip_height}` or below execution finalized"
            ));
        };

        candidate_height = next_height;
        candidate_digest = next_digest;
    }
}

async fn find_first_prunable_hole<TContext>(
    prunable: &super::hybrid::Prunable<TContext>,
    mut height: u64,
    floor: u64,
) -> eyre::Result<Option<u64>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    while height > floor {
        if prunable
            .get(Identifier::Index(height))
            .await
            .wrap_err_with(|| {
                format!("failed reading prunable finalized block at height `{height}`")
            })?
            .is_none()
        {
            return Ok(Some(height));
        }

        let Some(next_height) = height.checked_sub(1) else {
            return Ok(None);
        };
        height = next_height;
    }

    Ok(None)
}

async fn find_nearest_finalization_below<TContext>(
    finalizations: &FinalizationsArchive<TContext>,
    mut height: u64,
) -> eyre::Result<Option<(u64, Digest)>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    loop {
        let Some(next_height) = height.checked_sub(1) else {
            return Ok(None);
        };
        height = next_height;
        if let Some(finalization) = finalizations
            .get(Identifier::Index(height))
            .await
            .wrap_err_with(|| {
                format!("failed reading finalization certificate at height `{height}`")
            })?
        {
            return Ok(Some((height, finalization.proposal.payload)));
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for [`find_anchor_and_tip_finalizations`] anchor selection:
    //!
    //! - tip at or below execution finalized → anchor == tip,
    //! - contiguous prunable path down to execution finalized → anchor == tip,
    //! - empty prunable archive → anchor falls back to the nearest
    //!   certificate at or below execution finalized,
    //! - hole mid-range → anchor lands on the nearest certificate below the
    //!   hole that still has a contiguous path to the floor,
    //! - no certificates at all / none reachable at or below the floor →
    //!   error.
    //!
    //! Certificates are fabricated with garbage threshold signatures via
    //! [`Lazy::deferred`]; anchor selection only ever reads
    //! `proposal.payload`, and the certificate bytes round-trip the archive
    //! codec without being decoded.

    use alloy_primitives::B256;
    use commonware_codec::{FixedSize, types::lazy::Lazy};
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::vrf::{
                Certificate as VrfCertificate, Signature as VrfSignature,
            },
            types::Proposal,
        },
        types::{Epoch, Round, View},
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, deterministic};

    use super::*;
    use crate::storage::{
        PRUNABLE_ITEMS_PER_SECTION,
        hybrid::{
            Prunable,
            test::utils::{fresh_page_cache, fresh_prunable_with_section_size, make_chain},
        },
        init_finalizations_archive,
    };

    async fn fresh_archives(
        context: &deterministic::Context,
    ) -> (
        FinalizationsArchive<deterministic::Context>,
        Prunable<deterministic::Context>,
    ) {
        let finalizations =
            init_finalizations_archive(context, "test-snapshot", fresh_page_cache(context))
                .await
                .expect("init finalizations archive");
        let prunable = fresh_prunable_with_section_size(context, PRUNABLE_ITEMS_PER_SECTION).await;
        (finalizations, prunable)
    }

    /// Build a finalization certificate carrying `digest` as its payload.
    ///
    /// The threshold signature is garbage bytes deferred behind [`Lazy`];
    /// anchor selection never decodes it.
    fn make_finalization(
        height: u64,
        digest: Digest,
    ) -> Finalization<Scheme<PublicKey, MinSig>, Digest> {
        let signature_bytes = [0u8; <VrfSignature<MinSig> as FixedSize>::SIZE];
        Finalization {
            proposal: Proposal::new(
                Round::new(Epoch::zero(), View::new(height)),
                View::zero(),
                digest,
            ),
            certificate: VrfCertificate {
                signature: Lazy::deferred(&mut &signature_bytes[..], ()),
            },
        }
    }

    async fn put_cert(
        finalizations: &mut FinalizationsArchive<deterministic::Context>,
        height: u64,
        digest: Digest,
    ) {
        finalizations
            .put(height, digest, make_finalization(height, digest))
            .await
            .expect("put finalization certificate");
    }

    /// Seed a certificate for every block in `blocks`, keyed by the block's
    /// digest — mirroring production where a certificate's payload is the
    /// finalized block's hash.
    async fn put_certs_for(
        finalizations: &mut FinalizationsArchive<deterministic::Context>,
        blocks: &[Block],
    ) {
        for block in blocks {
            put_cert(finalizations, block.height().get(), block.digest()).await;
        }
    }

    async fn put_block(prunable: &mut Prunable<deterministic::Context>, block: &Block) {
        prunable
            .put(block.height().get(), block.digest(), block.clone())
            .await
            .expect("put prunable finalized block");
    }

    /// A digest for heights that have a certificate but no backing test block.
    fn synthetic_digest(height: u64) -> Digest {
        Digest(B256::with_last_byte(height as u8))
    }

    #[test_traced]
    fn errors_when_no_finalization_certificates_exist() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (finalizations, prunable) = fresh_archives(&context).await;

            let err = find_anchor_and_tip_finalizations(&finalizations, &prunable, 5)
                .await
                .expect_err("empty finalizations archive must error");
            assert!(
                err.to_string()
                    .contains("no finalization certificates found"),
                "unexpected error: {err}"
            );
        });
    }

    #[test_traced]
    fn anchor_is_tip_when_tip_at_or_below_execution_finalized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, prunable) = fresh_archives(&context).await;
            for height in 1..=5 {
                put_cert(&mut finalizations, height, synthetic_digest(height)).await;
            }

            // Execution finalized is ahead of the certificate tip; the tip is
            // the anchor and the (empty) prunable archive is never consulted.
            let selected = find_anchor_and_tip_finalizations(&finalizations, &prunable, 8)
                .await
                .expect("selection must succeed");

            assert_eq!(selected.tip_height, 5);
            assert_eq!(selected.tip_digest, synthetic_digest(5));
            assert_eq!(selected.anchor_height, 5);
            assert_eq!(selected.anchor_digest, synthetic_digest(5));
        });
    }

    #[test_traced]
    fn anchor_is_tip_when_prunable_path_reaches_execution_finalized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, mut prunable) = fresh_archives(&context).await;
            let chain = make_chain(1, 10);
            put_certs_for(&mut finalizations, &chain).await;
            // Blocks 4..=10 are present: a contiguous path from execution
            // finalized (3) up to the tip.
            for block in &chain[3..] {
                put_block(&mut prunable, block).await;
            }

            let selected = find_anchor_and_tip_finalizations(&finalizations, &prunable, 3)
                .await
                .expect("selection must succeed");

            assert_eq!(selected.tip_height, 10);
            assert_eq!(selected.anchor_height, 10);
            assert_eq!(selected.anchor_digest, chain[9].digest());
        });
    }

    #[test_traced]
    fn below_watermark_prunable_blocks_do_not_extend_the_anchor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, mut prunable) = fresh_archives(&context).await;
            let chain = make_chain(1, 10);
            put_certs_for(&mut finalizations, &chain).await;
            // Only blocks at or below execution finalized (3) are present.
            // The hole search never probes at or below the floor, so these
            // blocks are irrelevant: selection must behave exactly as with an
            // empty prunable archive and fall back to the certificate at the
            // floor.
            for block in &chain[..3] {
                put_block(&mut prunable, block).await;
            }

            let selected = find_anchor_and_tip_finalizations(&finalizations, &prunable, 3)
                .await
                .expect("selection must succeed");

            assert_eq!(selected.tip_height, 10);
            assert_eq!(selected.tip_digest, chain[9].digest());
            assert_eq!(selected.anchor_height, 3);
            assert_eq!(selected.anchor_digest, chain[2].digest());
        });
    }

    #[test_traced]
    fn below_watermark_prunable_blocks_are_not_streamed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (_, mut prunable) = fresh_archives(&context).await;
            let chain = make_chain(1, 10);
            // Blocks 1..=5 straddle execution finalized (3): only 4 and 5 may
            // end up in the snapshot archive.
            for block in &chain[..5] {
                put_block(&mut prunable, block).await;
            }

            let (entries_tx, mut entries_rx) = tokio::sync::mpsc::channel(16);
            stream_block_archive_entries(&prunable, 3, &entries_tx)
                .await
                .expect("streaming must succeed");
            drop(entries_tx);

            let mut streamed = Vec::new();
            while let Some(entry) = entries_rx.recv().await {
                let ArchiveEntryKind::Block(block) = entry.0 else {
                    panic!("block streaming must not emit certificates");
                };
                streamed.push(block.height().get());
            }
            assert_eq!(streamed, vec![4, 5]);
        });
    }

    #[test_traced]
    fn empty_prunable_anchors_at_certificate_at_execution_finalized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, prunable) = fresh_archives(&context).await;
            let chain = make_chain(1, 10);
            put_certs_for(&mut finalizations, &chain).await;

            // No blocks at all: the descent must walk certificate by
            // certificate down to the execution finalized floor.
            let selected = find_anchor_and_tip_finalizations(&finalizations, &prunable, 3)
                .await
                .expect("selection must succeed");

            assert_eq!(selected.tip_height, 10);
            assert_eq!(selected.tip_digest, chain[9].digest());
            assert_eq!(selected.anchor_height, 3);
            assert_eq!(selected.anchor_digest, chain[2].digest());
        });
    }

    #[test_traced]
    fn empty_prunable_anchors_at_nearest_certificate_below_execution_finalized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, prunable) = fresh_archives(&context).await;
            // Certificates at 2 and 5..=10; nothing at 3 and 4, so with
            // execution finalized at 4 the descent must skip past the gap
            // and anchor at 2.
            put_cert(&mut finalizations, 2, synthetic_digest(2)).await;
            for height in 5..=10 {
                put_cert(&mut finalizations, height, synthetic_digest(height)).await;
            }

            let selected = find_anchor_and_tip_finalizations(&finalizations, &prunable, 4)
                .await
                .expect("selection must succeed");

            assert_eq!(selected.tip_height, 10);
            assert_eq!(selected.anchor_height, 2);
            assert_eq!(selected.anchor_digest, synthetic_digest(2));
        });
    }

    #[test_traced]
    fn hole_above_floor_anchors_at_nearest_certificate_below_hole() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, mut prunable) = fresh_archives(&context).await;
            let chain = make_chain(1, 10);
            put_certs_for(&mut finalizations, &chain).await;
            // Blocks 4..=6 and 8..=10 are present; 7 is a hole. The path from
            // the tip breaks at 7, so the anchor must drop to the certificate
            // at 6, from which the path down to the floor (3) is contiguous.
            for block in &chain[3..6] {
                put_block(&mut prunable, block).await;
            }
            for block in &chain[7..] {
                put_block(&mut prunable, block).await;
            }

            let selected = find_anchor_and_tip_finalizations(&finalizations, &prunable, 3)
                .await
                .expect("selection must succeed");

            assert_eq!(selected.tip_height, 10);
            assert_eq!(selected.tip_digest, chain[9].digest());
            assert_eq!(selected.anchor_height, 6);
            assert_eq!(selected.anchor_digest, chain[5].digest());
        });
    }

    #[test_traced]
    fn errors_when_no_certificate_at_or_below_execution_finalized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut finalizations, prunable) = fresh_archives(&context).await;
            // Certificates only above the floor, and no blocks to build a
            // path with: no anchor can be selected.
            for height in 5..=10 {
                put_cert(&mut finalizations, height, synthetic_digest(height)).await;
            }

            let err = find_anchor_and_tip_finalizations(&finalizations, &prunable, 3)
                .await
                .expect_err("unreachable floor must error");
            assert!(
                err.to_string()
                    .contains("no finalization certificate found"),
                "unexpected error: {err}"
            );
        });
    }
}
