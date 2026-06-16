use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier, immutable};
use eyre::{WrapErr as _, eyre};

use crate::{
    consensus::Digest,
    storage::{
        BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
        init_prunable_finalized_blocks_archive,
    },
};

type FinalizationCertificate = Finalization<Scheme<PublicKey, MinSig>, Digest>;
type FinalizationsArchive<TContext> = immutable::Archive<TContext, Digest, FinalizationCertificate>;

/// Consensus state prepared for inclusion in an execution snapshot.
pub struct State {
    /// Highest finalized execution block in the EL snapshot source.
    pub execution_finalized_height: u64,
    /// Highest finalization certificate height known to consensus storage.
    pub tip_finalization_height: u64,
    /// Highest finalization certificate known to consensus storage.
    pub tip_finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
    /// Anchor finalization certificate height used to bootstrap consensus.
    pub anchor_finalization_height: u64,
    /// Anchor finalization certificate used to bootstrap consensus.
    pub anchor_finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
    /// On-disk commonware partitions that back the prunable finalized-block
    /// archive and must be bundled into the snapshot.
    pub consensus_blocks_partitions: [String; 2],
}

/// Prepares consensus finalized-block storage for snapshot packaging.
///
/// The prunable archive is left on disk for bundling. The returned state
/// records both the latest consensus finalization certificate and an anchor
/// certificate. When the anchor is above execution finalized, selection proves
/// the prunable archive contains a contiguous path from execution finalized to
/// the anchor.
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
    let prunable =
        init_prunable_finalized_blocks_archive(context, crate::PARTITION_PREFIX, page_cache)
            .await
            .wrap_err("failed to open prunable finalized blocks archive")?;

    let selected =
        find_anchor_and_tip_finalizations(&finalizations, &prunable, execution_finalized_height)
            .await?;

    Ok(State {
        execution_finalized_height,
        tip_finalization_height: selected.tip_height,
        tip_finalization: selected.tip_finalization,
        anchor_finalization_height: selected.anchor_height,
        anchor_finalization: selected.anchor_finalization,
        consensus_blocks_partitions: prunable_finalized_blocks_partitions(crate::PARTITION_PREFIX),
    })
}

struct AnchorAndTipFinalizations {
    tip_height: u64,
    tip_finalization: FinalizationCertificate,
    anchor_height: u64,
    anchor_finalization: FinalizationCertificate,
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

    let mut candidate_height = tip_height;
    let mut candidate_finalization = tip_finalization.clone();

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
                tip_finalization,
                anchor_height: candidate_height,
                anchor_finalization: candidate_finalization,
            });
        }

        let Some(hole) =
            find_first_prunable_hole(prunable, candidate_height, execution_finalized_height)
                .await?
        else {
            return Ok(AnchorAndTipFinalizations {
                tip_height,
                tip_finalization,
                anchor_height: candidate_height,
                anchor_finalization: candidate_finalization,
            });
        };

        let Some((next_height, next_finalization)) =
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
        candidate_finalization = next_finalization;
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
) -> eyre::Result<Option<(u64, FinalizationCertificate)>>
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
            return Ok(Some((height, finalization)));
        }
    }
}

fn prunable_finalized_blocks_partitions(partition_prefix: &str) -> [String; 2] {
    use super::PRUNABLE_FINALIZED_BLOCKS;
    [
        format!("{partition_prefix}-{PRUNABLE_FINALIZED_BLOCKS}-key"),
        format!("{partition_prefix}-{PRUNABLE_FINALIZED_BLOCKS}-value"),
    ]
}
