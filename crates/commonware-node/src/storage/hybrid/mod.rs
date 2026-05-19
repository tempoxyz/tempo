//! [`Hybrid`] is a prunable archive of finalized blocks fronting reth.
//!
//! Reth is the source of truth. The prunable archive is a hot cache of
//! the most-recently finalized blocks that lets the marshal serve
//! gap-repair without round-tripping to reth on every read. The marshal
//! only sees the [`Blocks`] interface and is unaware which side served
//! a given read.
//!
//! # Eviction
//!
//! Eviction is reth-driven, not marshal-driven. Every [`Blocks::put`]
//! reads reth's finalized watermark and prunes the cache below
//! `reth.finalized − retention_blocks + 1`. [`Blocks::prune`] from the
//! marshal is a no-op.
//!
//! As a consequences, the cache never drops a block reth doesn't yet have.
//! If reth is lagging the marshal actor, the cache temporarily holds more than
//! `retention_blocks` items.
//!
//! # Section-rounding
//!
//! The prunable archive prunes in whole sections of
//! `items_per_section` items (4096 in production); `prune(min)` rounds
//! `min` down to a section boundary.
//!
//! Consequences:
//!
//! - Retention is approximate: the cache holds between `retention_blocks`
//!   and `retention_blocks + items_per_section − 1` items, evicted in
//!   one-section batches.
//! - The cache/reth boundary is the section-aligned `oldest_allowed`,
//!   not `tip − retention`. Reads in `[oldest_allowed, tip − retention)`
//!   still hit the cache. Same answer, slightly wasteful path.
//! - A re-`put` below the requested floor may still land in the cache
//!   (live tail section) or be silently absorbed (see "Stale puts"
//!   below).
//!
//! Pick `retention_blocks` as a few multiples of `items_per_section` so
//! section overshoot is a small fraction of the working set; see
//! [`super::DEFAULT_FINALIZED_BLOCKS_RETENTION`].
//!
//! # Stale puts
//!
//! [`Hybrid::put`] absorbs the prunable archive's
//! [`archive::Error::AlreadyPrunedTo`] as a silent success. The
//! eviction invariant
//! `oldest_allowed ≤ section_aligned(reth.finalized − retention + 1)
//! ≤ reth.finalized` guarantees that a put at `H < oldest_allowed`
//! also has `H ≤ reth.finalized`, so the block is durable in reth and
//! a subsequent [`Blocks::get`] will hit the reth fallback. Surfacing
//! the error would crash the node on a recoverable condition (e.g.
//! follow-mode catching up while reth has synced past the cache
//! window). The legacy archive (when present) accepts arbitrary
//! heights and is always written first, so rollback also still sees it.
//!
//! # Why reth pruning is not a concern
//!
//! Reth may be configured to retain only a window of recent history,
//! creating a `reth.pruned_below ≤ reth.finalized` watermark. The
//! marshal can never ask for a block panic-on-miss below
//! `reth.pruned_below`:
//!
//! - **`Blocks::put(H)`**: marshal's `last_processed_height` is floored
//!   to `max(stored_height, reth.finalized)` at startup
//!   ([`alias::marshal::init`]), so every put has
//!  `H > reth.finalized > reth.pruned_below`.
//! - **`Blocks::get(Index(H))`**: only ever asks for the next
//!   contiguous height or a `gap_end` already in the cache.
//! - **`Blocks::get(Key(digest))`**: gap-repair parent walks may ask
//!   for a digest below `reth.pruned_below`; on miss we return
//!   `Ok(None)` and the marshal falls back to peer resolution.
//!
//! Configuring reth with a smaller retention window than
//! `retention_blocks` is a perf concern (more peer fetches), not a
//! correctness one.
//!
//! [`alias::marshal::init`]: crate::alias::marshal::init

use alloy_primitives::B256;
use commonware_consensus::{Heightable as _, marshal::store::Blocks, types::Height};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, Identifier, immutable, prunable},
    translator::TwoCap,
};
use reth_node_core::primitives::SealedBlock;
use reth_provider::{
    BlockReader, BlockSource, ProviderResult,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tracing::{debug, instrument, warn};

use crate::consensus::{Digest, block::Block};

#[cfg(test)]
mod test;

/// Narrow view of reth that [`Hybrid`] needs: a finalized watermark and
/// canonical-by-height / canonical-by-hash block reads.
///
/// Exists to make unit testing easier. [`BlockchainProvider`] is used in
/// production.
pub(crate) trait FinalizedBlocksProvider: Send + Sync {
    /// Reth's last finalized block height, or `None` if reth has not yet
    /// finalized anything (fresh chain).
    fn finalized_height(&self) -> Option<u64>;

    /// Look up a finalized block by height in reth.
    ///
    /// Implementations MUST return `None` for any `height` above
    /// [`Self::finalized_height`] (and unconditionally when
    /// [`Self::finalized_height`] is `None`); the marshal relies on
    /// [`Hybrid`] only serving blocks reth has marked as finalized.
    fn block_by_height(&self, height: u64) -> ProviderResult<Option<Block>>;

    /// Look up a finalized block by hash in reth.
    ///
    /// Implementations MUST restrict the lookup to canonical blocks
    /// only — pending/in-flight blocks must never be returned, otherwise
    /// the marshal could be handed a non-finalized block.
    fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>>;
}

/// Production impl over reth's [`BlockchainProvider`] — the only type
/// passed to [`Hybrid`] in production. Generic over `N` only so the
/// impl works for any concrete `BlockchainProvider<N>` whose primitive
/// block type is [`tempo_primitives::Block`] (e.g. the
/// `BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>`
/// alias used by `tempo_node::TempoFullNode`).
impl<N> FinalizedBlocksProvider for BlockchainProvider<N>
where
    N: ProviderNodeTypes,
    Self: BlockReader<Block = tempo_primitives::Block>,
{
    fn finalized_height(&self) -> Option<u64> {
        // Direct read of `canonical_in_memory_state` — equivalent to
        // `BlockchainProvider`'s `BlockIdReader::finalized_block_num_hash`,
        // but typed as the genuinely infallible `Option<u64>` rather
        // than the `Result<Option<_>>` reth's trait demands.
        self.canonical_in_memory_state()
            .get_finalized_num_hash()
            .map(|nh| nh.number)
    }

    fn block_by_height(&self, height: u64) -> ProviderResult<Option<Block>> {
        // Gate the lookup on reth's finalized watermark so the marshal can
        // never be served a block that reth has not yet marked as
        // finalized. Without this, the canonical-by-number read would
        // happily return a block that is canonical-but-not-yet-finalized
        // (or even a block reth has accepted past its finalized tip),
        // violating [`Blocks`]'s "finalized only" contract.
        let Some(finalized) = self.finalized_height() else {
            // Reth has not finalized anything yet — nothing below the
            // (nonexistent) finalized watermark is reachable.
            return Ok(None);
        };
        if height > finalized {
            return Ok(None);
        }
        Ok(self
            .block_by_number(height)?
            .map(|block| Block::from_execution_block(SealedBlock::seal_slow(block))))
    }

    fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>> {
        // `Canonical` (not `Any`) so the marshal can never be served a
        // block that lives only in reth's pending in-memory tree — see
        // [`Blocks::get`] on [`Hybrid`].
        Ok(self
            .find_block_by_hash(hash, BlockSource::Canonical)?
            .map(|block| Block::from_execution_block(SealedBlock::seal_slow(block))))
    }
}

/// Error returned by [`Hybrid`]'s [`Blocks`] impl.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Archive(#[from] archive::Error),

    #[error(transparent)]
    Provider(#[from] reth_provider::ProviderError),
}

/// Backing prunable archive type.
// TODO: Look into whether to take TwoCap or another translator. TwoCap is used
// by commonware itself, but higher caps can reduce the likelihood of collisions.
pub(crate) type Prunable<TContext> = prunable::Archive<TwoCap, TContext, Digest, Block>;

/// Configuration for [`Hybrid`].
pub(crate) struct Config<TContext, TExecutionBlockProvider>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
{
    /// Prunable archive backing the most recently finalized blocks.
    pub(crate) prunable: Prunable<TContext>,

    /// Legacy immutable archive opened for write-through.
    pub(crate) legacy: Option<immutable::Archive<TContext, Digest, Block>>,

    /// Execution layer block provider used to look up finalized blocks below
    /// the cache window and to read reth's finalized watermark for cache
    /// eviction.
    pub(crate) execution_block_provider: TExecutionBlockProvider,

    /// Number of most-recently-finalized blocks (relative to the EL's
    /// finalized watermark) to keep in the prunable cache. Anything
    /// older is dropped from the cache and served out of
    /// [`Self::execution_block_provider`] instead.
    pub(crate) retention_blocks: u64,
}

/// Finalized blocks store backed by a prunable archive (a hot cache of
/// the most recently finalized blocks) and reth (the source of truth for
/// finalized blocks).
///
/// Optionally also write-throughs to a legacy immutable archive for
/// rollback safety. The legacy archive is never read from or pruned by
/// [`Hybrid`]; it is purely a backup ledger maintained for the previous
/// binary's sake until an operator cleans it up. The whole legacy code
/// path is slated for removal in an upcoming release.
pub(crate) struct Hybrid<TContext, TExecutionBlockProvider>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
{
    /// Hot cache of recently finalized blocks. Bounded to roughly
    /// `retention_blocks` items above reth's finalized watermark via
    /// [`Self::evict_below_execution_finalized_floor`].
    prunable: Prunable<TContext>,

    /// Legacy immutable archive opened for write-through. `None` when
    /// the operator opts out of dual-writing (see [`Config::legacy`]).
    legacy: Option<immutable::Archive<TContext, Digest, Block>>,

    /// Execution layer block provider used to look up finalized blocks below
    /// the cache window and to read reth's finalized watermark for cache
    /// eviction.
    execution_block_provider: TExecutionBlockProvider,

    /// Number of most-recently-finalized blocks (relative to the EL's
    /// finalized watermark) to keep in the prunable cache. Anything
    /// older is dropped from the cache and served out of
    /// [`Self::execution_block_provider`] instead.
    retention_blocks: u64,
}

impl<TContext, P> Hybrid<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
    P: FinalizedBlocksProvider + 'static,
{
    pub(crate) fn new(config: Config<TContext, P>) -> Self {
        let Config {
            prunable,
            legacy,
            execution_block_provider: provider,
            retention_blocks,
        } = config;
        Self {
            prunable,
            legacy,
            execution_block_provider: provider,
            retention_blocks,
        }
    }

    /// Drops blocks below the execution layer's finalized watermark.
    ///
    /// The cache is sized relative to the EL's finalized boundary, not to
    /// the height the marshal happens to put. This keeps two invariants:
    ///
    /// - We never evict a block the EL doesn't yet have. If the EL is lagging
    ///   the marshal, no eviction happens; the cache temporarily grows past
    ///   `retention_blocks`.
    /// - Eviction tracks the EL's progress monotonically. Once the EL
    ///   finalizes height `H`, the cache may drop everything below
    ///   `H - retention_blocks + 1` on the next put.
    async fn evict_below_execution_finalized_floor(&mut self) -> Result<(), archive::Error> {
        // Reth hasn't finalized anything yet (fresh chain) — nothing is
        // safe to evict.
        let Some(execution_finalized) = self.execution_block_provider.finalized_height() else {
            return Ok(());
        };
        let Some(min_to_keep) = execution_finalized.checked_sub(self.retention_blocks) else {
            return Ok(());
        };
        // `prune(min)` keeps `min` and above, and the archive rounds `min`
        // *down* to a section boundary, so the actual retained window can
        // exceed `retention_blocks` by up to `items_per_section − 1` items.
        // See the module docs ("Section-rounding") for the full story.
        let prune_floor = min_to_keep.saturating_add(1);
        prunable::Archive::prune(&mut self.prunable, prune_floor).await
    }
}

impl<TContext, TExecutionBlockProvider> Blocks for Hybrid<TContext, TExecutionBlockProvider>
where
    TContext: BufferPooler + Storage + Metrics + Clock + Send + Sync + 'static,
    TExecutionBlockProvider: FinalizedBlocksProvider + 'static,
{
    type Block = Block;
    type Error = Error;

    #[instrument(skip_all, err)]
    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        let height = block.height();
        let digest = block.digest();
        // Dual-write to the legacy archive first when present. Failing
        // here before the prunable write keeps the rollback contract
        // intact: if the legacy write fails we never advance the
        // prunable side past what's in legacy, so the previous binary
        // keeps a consistent view.
        if let Some(legacy) = self.legacy.as_mut() {
            archive::Archive::put(legacy, height.get(), digest, block.clone()).await?;
        }
        match archive::Archive::put(&mut self.prunable, height.get(), digest, block).await {
            Ok(()) => {}
            // The prunable cache has already evicted this height — but
            // by the cache's eviction invariant
            // (`oldest_allowed ≤ section_aligned(execution_finalized − retention + 1)
            // ≤ execution_finalized`), `height < oldest_allowed` implies
            // `height ≤ execution_finalized`. The EL's finality contract
            // guarantees every block at or below `execution_finalized` is
            // durably persisted, so the marshal's subsequent
            // `Blocks::get(height)` will be served out of the execution
            // layer fallback path. We can't write to EL ourselves (it owns
            // its own storage), but we don't have to — the block is
            // already durable. Treat the put as a successful no-op so
            // we don't trip the marshal's "failed to finalize" panic
            // on a perfectly recoverable condition.
            //
            // The legacy archive (when present) accepts arbitrary
            // heights and will already have captured the block above,
            // so a future rollback also still sees it.
            Err(archive::Error::AlreadyPrunedTo(oldest_allowed)) => {
                debug!(
                    %height,
                    oldest_allowed,
                    execution_finalized = ?self.execution_block_provider.finalized_height(),
                    "finalized block below prunable cache window; trusting the \
                    execution layer's finalized storage and treating put as a \
                    no-op"
                );
            }
            Err(other) => return Err(other.into()),
        }

        if let Err(err) = self.evict_below_execution_finalized_floor().await {
            // Eviction failures are not fatal; the next put will retry.
            // We log because they may indicate disk-level issues.
            warn!(
                %err,
                %height,
                retention = self.retention_blocks,
                "failed to evict prunable finalized blocks cache after put"
            );
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        if let Some(legacy) = self.legacy.as_mut() {
            archive::Archive::sync(legacy).await?;
        }
        archive::Archive::sync(&mut self.prunable).await?;
        Ok(())
    }

    /// Attempts to read `id` from the prunable archive, falling back to EL on miss.
    async fn get(&self, id: Identifier<'_, Digest>) -> Result<Option<Self::Block>, Self::Error> {
        // EL read errors propagate to the marshal — see this module's
        // doc comment ("Marshal panic behavior") for what happens then.
        match id {
            Identifier::Index(height) => {
                if let Some(block) =
                    archive::Archive::get(&self.prunable, Identifier::Index(height)).await?
                {
                    return Ok(Some(block));
                }
                Ok(self.execution_block_provider.block_by_height(height)?)
            }
            Identifier::Key(digest) => {
                if let Some(block) =
                    archive::Archive::get(&self.prunable, Identifier::Key(digest)).await?
                {
                    return Ok(Some(block));
                }
                Ok(self.execution_block_provider.block_by_hash(digest.0)?)
            }
        }
    }

    /// No-op: Cache eviction is EL-driven (see [`Self::evict_below_execution_finalized_floor`]).
    async fn prune(&mut self, _min: Height) -> Result<(), Self::Error> {
        Ok(())
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        // EL is treated as a contiguous source; gaps can only exist in the
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
        // EL here would mask gaps the marshal needs to fill via the
        // resolver.
        archive::Archive::last_index(&self.prunable).map(Height::new)
    }
}
