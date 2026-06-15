use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier, prunable};
use eyre::{WrapErr as _, ensure, eyre};

use crate::{
    consensus::Digest,
    storage::{
        BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
        init_prunable_finalized_blocks_archive,
    },
};

/// Consensus state prepared for inclusion in an execution snapshot.
pub struct State {
    /// Highest finalized execution block in the EL snapshot source.
    pub execution_finalized_height: u64,
    /// Latest finalization certificate height known to consensus storage.
    pub consensus_finalization_height: u64,
    /// Latest finalization certificate known to consensus storage.
    pub latest_finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
    /// First block height available in the snapshot prunable archive.
    ///
    /// NOTE: Is it not guaranteed that all blocks between
    /// `prunable_first_height` and `prunable_last_height` are available.
    pub consensus_start_block_height: Option<u64>,
    /// Last block height available in the snapshot prunable archive.
    ///
    /// NOTE: Is it not guaranteed that all blocks between
    /// `consensus_start_block_height` and `consensus_end_block_height` are
    /// available.
    ///
    /// It is also not guaranteed that
    /// `consensus_end_block_height == consensus_finalization_height` because
    /// that would require the archive to actually hold the block in addition to
    /// the cert.
    pub consensus_end_block_height: Option<u64>,
    /// On-disk commonware partitions that back the prunable finalized-block
    /// archive and must be bundled into the snapshot.
    pub consensus_blocks_partitions: [String; 2],
}

/// Prune and validate consensus finalized-block storage for snapshot packaging.
///
/// The prunable archive is left on disk for bundling, and the returned state
/// records the contiguous block range available in that snapshot. The startup
/// replay/reconciliation path is intentionally not handled here.
pub async fn prepare<TContext>(
    context: &TContext,
    execution_finalized_height: u64,
) -> eyre::Result<State>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let page_cache = CacheRef::from_pooler(context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

    let finalizations =
        init_finalizations_archive(context, crate::PARTITION_PREFIX, page_cache.clone())
            .await
            .wrap_err("failed to open finalizations-by-height archive")?;
    let consensus_finalization_height = finalizations
        .last_index()
        .ok_or_else(|| eyre!("no finalization certificates found"))?;
    ensure!(
        consensus_finalization_height >= execution_finalized_height,
        "latest finalization `{consensus_finalization_height}` is below execution \
        finalized `{execution_finalized_height}`",
    );
    let latest_finalization = finalizations
        .get(Identifier::Index(consensus_finalization_height))
        .await
        .wrap_err_with(|| {
            format!(
                "failed reading finalization certificate at height \
                    `{consensus_finalization_height}`"
            )
        })?
        .ok_or_else(|| {
            eyre!(
                "finalization archive reported latest height \
                    `{consensus_finalization_height}` but no certificate was present"
            )
        })?;

    let mut prunable =
        init_prunable_finalized_blocks_archive(context, crate::PARTITION_PREFIX, page_cache)
            .await
            .wrap_err("failed to open prunable finalized blocks archive")?;

    let first_required_block_height =
        execution_finalized_height.checked_add(1).ok_or_else(|| {
            eyre!("execution finalized height cannot be u64::MAX for snapshot pruning")
        })?;

    prunable::Archive::prune(&mut prunable, first_required_block_height)
        .await
        .wrap_err_with(|| {
            format!("failed pruning prunable finalized blocks below {first_required_block_height}")
        })?;

    let consensus_start_block_height = prunable.first_index();
    let consensus_end_block_height = prunable.last_index();

    prunable
        .sync()
        .await
        .wrap_err("failed syncing prunable finalized blocks archive")?;

    Ok(State {
        execution_finalized_height,
        consensus_finalization_height,
        latest_finalization,
        consensus_start_block_height,
        consensus_end_block_height,
        consensus_blocks_partitions: prunable_finalized_blocks_partitions(crate::PARTITION_PREFIX),
    })
}

fn prunable_finalized_blocks_partitions(partition_prefix: &str) -> [String; 2] {
    use super::PRUNABLE_FINALIZED_BLOCKS;
    [
        format!("{partition_prefix}-{PRUNABLE_FINALIZED_BLOCKS}-key"),
        format!("{partition_prefix}-{PRUNABLE_FINALIZED_BLOCKS}-value"),
    ]
}
