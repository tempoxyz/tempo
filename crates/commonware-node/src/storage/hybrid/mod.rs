//! [`Hybrid`] — a finalized-block store that merges a prunable archive
//! holding the most recent blocks with a reth provider lookup for older
//! finalized blocks.
//!
//! The marshal actor only ever interacts with the [`Blocks`] interface so it
//! is unaware whether a given block lives in the archive or in reth's
//! database. Recently finalized blocks are written to the prunable archive
//! synchronously; whenever a new height is observed the archive is pruned to
//! retain at most `retention_blocks` items. Older blocks are looked up
//! from reth via [`reth_provider::BlockReader`].

use commonware_consensus::{Heightable as _, marshal::store::Blocks, types::Height};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, Identifier, prunable},
    translator::TwoCap,
};
use reth_node_core::primitives::SealedBlock;
use reth_provider::{BlockReader, BlockSource};
use tracing::{debug, error, instrument, warn};

use crate::{
    consensus::{Digest, block::Block},
    storage::legacy::Legacy,
};

mod bootstrap;
pub(in crate::storage) use bootstrap::open_legacy_for_dual_write;

#[cfg(test)]
mod test;

/// Backing prunable archive type.
// TODO: Look into whether to take TwoCap or another translator. TwoCap is used
// by commonwar itself, but higher caps can reduce the likehood of collisions.
pub(crate) type Prunable<TContext> = prunable::Archive<TwoCap, TContext, Digest, Block>;

/// Configuration for [`Hybrid`].
pub(crate) struct Config<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
{
    /// Prunable archive backing the most recently finalized blocks. The
    /// archive is expected to already be opened (and the legacy backfill
    /// performed) by the caller; see [`super::init_hybrid_finalized_blocks`].
    pub(crate) prunable: Prunable<TContext>,

    /// Optional legacy immutable archive opened for write-through. Present
    /// only on existing nodes that still have legacy partitions on disk; new
    /// deployments and post-cleanup nodes pass `None`. See
    /// [`super::legacy::open_legacy_for_dual_write`].
    pub(crate) legacy: Option<Legacy<TContext>>,

    /// Reth provider used to look up finalized blocks below the prunable
    /// archive's retained window.
    pub(crate) provider: P,

    /// Number of most-recently-finalized blocks to keep in the prunable
    /// archive. Anything older is dropped from the archive on each [`put`]
    /// and served out of [`Self::provider`] instead.
    ///
    /// [`put`]: commonware_consensus::marshal::store::Blocks::put
    pub(crate) retention_blocks: u64,
}

/// Finalized blocks store backed by a prunable archive (recent blocks) and
/// reth (older finalized blocks).
///
/// Optionally also write-throughs to a legacy immutable archive on existing
/// nodes (for rollback safety). The legacy archive is never read from or
/// pruned by [`Hybrid`]; it is purely a backup ledger maintained for the
/// previous binary's sake until an operator cleans it up.
pub(crate) struct Hybrid<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
{
    /// Most recently finalized blocks. Bounded to at most `retention_blocks`
    /// items via [`Self::trim_to_retention`].
    prunable: Prunable<TContext>,

    /// Legacy immutable archive opened for write-through on existing nodes.
    /// `None` on fresh deployments and on nodes where the operator has
    /// removed the legacy partitions.
    legacy: Option<Legacy<TContext>>,

    /// Reth provider used to look up finalized blocks below the prunable
    /// archive's retained window.
    provider: P,

    /// Number of most-recently-finalized blocks to keep in the prunable
    /// archive. Anything older is dropped from the archive and served out of
    /// [`Self::provider`] instead.
    retention_blocks: u64,
}

impl<TContext, P> Hybrid<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
    P: BlockReader<Block = tempo_primitives::Block> + Sync + 'static,
{
    pub(crate) fn new(config: Config<TContext, P>) -> Self {
        let Config {
            prunable,
            legacy,
            provider,
            retention_blocks,
        } = config;
        Self {
            prunable,
            legacy,
            provider,
            retention_blocks,
        }
    }

    /// Drop archive entries that are older than `retention_blocks` blocks
    /// behind `tip`.
    async fn trim_to_retention(&mut self, tip: Height) -> Result<(), archive::Error> {
        let Some(min_to_keep) = tip.get().checked_sub(self.retention_blocks) else {
            return Ok(());
        };
        // `prune(min)` keeps `min` and above; we want at most
        // `retention_blocks` items so prune everything strictly below
        // `tip - retention_blocks + 1`.
        let prune_floor = min_to_keep.saturating_add(1);
        prunable::Archive::prune(&mut self.prunable, prune_floor).await
    }

    /// Look up a finalized block from reth by height.
    ///
    /// `block_by_number` returns whichever block sits in reth's canonical
    /// chain at `height` — it is not finality-aware on its own. We rely on
    /// it here because of the invariant of the prunable archive:
    ///
    /// - The marshal only ever writes finalized blocks to the prunable
    ///   archive, and the archive retains the most recent `retention_blocks`
    ///   of them.
    /// - A miss in the prunable archive therefore implies
    ///   `height < tip_finalized − retention_blocks`, i.e. the height sits
    ///   well below reth's finalized boundary.
    /// - Reth never reorgs blocks at or below its finalized boundary
    ///   (the engine API enforces this on every `forkchoice_updated`), so
    ///   the canonical block at such a depth is also the finalized block.
    #[instrument(skip_all, fields(%height))]
    fn block_from_reth_by_height(&self, height: Height) -> Option<Block> {
        match self.provider.block_by_number(height.get()) {
            Ok(Some(block)) => Some(Block::from_execution_block(SealedBlock::seal_slow(block))),
            Ok(None) => None,
            Err(error) => {
                error!(
                    %error,
                    %height,
                    "failed to look up finalized block in reth provider"
                );
                None
            }
        }
    }

    /// Look up a finalized block from reth by block hash (commonware digest).
    ///
    /// We restrict the lookup to [`BlockSource::Canonical`] (rather than
    /// `Any`) so we never hand the marshal a block that lives only in the
    /// pending in-memory tree: the marshal treats every block returned by
    /// the [`Blocks`] store as finalized. The same finality argument as in
    /// [`Self::block_from_reth_by_height`] applies — a miss in the prunable
    /// archive means the block, if it exists in reth at all, sits below
    /// reth's finalized boundary and thus cannot be reorged out.
    #[instrument(skip_all, fields(%digest))]
    fn block_from_reth_by_digest(&self, digest: Digest) -> Option<Block> {
        match self
            .provider
            .find_block_by_hash(digest.0, BlockSource::Canonical)
        {
            Ok(Some(block)) => Some(Block::from_execution_block(SealedBlock::seal_slow(block))),
            Ok(None) => None,
            Err(error) => {
                error!(
                    %error,
                    %digest,
                    "failed to look up finalized block in reth provider"
                );
                None
            }
        }
    }
}

impl<TContext, P> Blocks for Hybrid<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock + Send + Sync + 'static,
    P: BlockReader<Block = tempo_primitives::Block> + Sync + 'static,
{
    type Block = Block;
    type Error = archive::Error;

    #[instrument(skip_all, err)]
    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        let height = block.height();
        let digest = block.digest();
        // Dual-write to the legacy archive first when present. Failing here
        // before the prunable write keeps the rollback contract intact: if
        // the legacy write fails we never advance the prunable side past
        // what's in legacy, so the previous binary keeps a consistent view.
        if let Some(legacy) = self.legacy.as_mut() {
            archive::Archive::put(legacy, height.get(), digest, block.clone()).await?;
        }
        archive::Archive::put(&mut self.prunable, height.get(), digest, block).await?;

        if let Err(err) = self.trim_to_retention(height).await {
            // Pruning failures are not fatal; the next put will retry. We log
            // because they may indicate disk-level issues.
            warn!(
                %err,
                %height,
                retention = self.retention_blocks,
                "failed to prune prunable finalized blocks archive after put"
            );
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        if let Some(legacy) = self.legacy.as_mut() {
            archive::Archive::sync(legacy).await?;
        }
        archive::Archive::sync(&mut self.prunable).await
    }

    async fn get(&self, id: Identifier<'_, Digest>) -> Result<Option<Self::Block>, Self::Error> {
        // Try the prunable archive first; on miss, fall back to reth.
        match id {
            Identifier::Index(height) => {
                if let Some(block) =
                    archive::Archive::get(&self.prunable, Identifier::Index(height)).await?
                {
                    return Ok(Some(block));
                }
                debug!(
                    height,
                    "finalized block missing from prunable archive, falling back to reth"
                );
                Ok(self.block_from_reth_by_height(Height::new(height)))
            }
            Identifier::Key(digest) => {
                if let Some(block) =
                    archive::Archive::get(&self.prunable, Identifier::Key(digest)).await?
                {
                    return Ok(Some(block));
                }
                debug!(%digest, "finalized block missing from prunable archive, falling back to reth");
                Ok(self.block_from_reth_by_digest(*digest))
            }
        }
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        // Honor explicit prune requests from the marshal: prune up to `min`
        // (exclusive lower bound). Self-pruning in `put` keeps the archive
        // bounded by the configured retention regardless.
        prunable::Archive::prune(&mut self.prunable, min.get()).await
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        // Reth is treated as a contiguous source; gaps can only exist in the
        // prunable archive. The marshal only ever asks about heights at or
        // above `last_processed_height`, which the prunable archive must
        // cover.
        archive::Archive::missing_items(&self.prunable, start.get(), max)
            .into_iter()
            .map(Height::new)
            .collect()
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        let (a, b) = archive::Archive::next_gap(&self.prunable, value.get());
        (a.map(Height::new), b.map(Height::new))
    }

    fn last_index(&self) -> Option<Height> {
        // Only report what lives in the prunable archive. The marshal uses
        // this to drive repair against the certificates archive; reflecting
        // reth here would mask gaps the marshal needs to fill via the
        // resolver.
        archive::Archive::last_index(&self.prunable).map(Height::new)
    }
}
