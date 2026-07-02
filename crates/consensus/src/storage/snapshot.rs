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
    execution_provider: P,
    archive_entries: tokio::sync::mpsc::Sender<ArchiveEntry>,
) -> eyre::Result<State>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    P: BlockIdReader + BlockReader<Block = tempo_primitives::Block> + Send + Sync,
{
    prepare_with_partition_prefix(
        context,
        crate::PARTITION_PREFIX,
        execution_provider,
        archive_entries,
    )
    .await
}

/// Prepares consensus storage state for snapshot packaging using an explicit partition prefix.
pub async fn prepare_with_partition_prefix<TContext, P>(
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
pub fn is_prunable_finalized_blocks_partition(name: &str) -> bool {
    name.starts_with(&partition_prefix(super::PRUNABLE_FINALIZED_BLOCKS))
}

/// Returns whether `name` is a consensus storage partition that can appear in a
/// consensus snapshot archive.
pub fn is_snapshot_storage_partition(name: &str) -> bool {
    name.starts_with(&partition_prefix(super::FINALIZATIONS_BY_HEIGHT))
        || is_prunable_finalized_blocks_partition(name)
}

fn partition_prefix(archive_name: &str) -> String {
    format!("{}-{archive_name}-", crate::PARTITION_PREFIX)
}

/// Materialize consensus archive entries into fresh storage archives.
pub async fn write_archive<TContext>(
    context: &TContext,
    entries: tokio::sync::mpsc::Receiver<ArchiveEntry>,
) -> eyre::Result<()>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    write_archive_with_partition_prefix(context, crate::PARTITION_PREFIX, entries).await
}

/// Materialize consensus archive entries into fresh storage archives using an explicit partition prefix.
pub async fn write_archive_with_partition_prefix<TContext>(
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
