//! [`Hybrid`] — a finalized-block store that treats a prunable archive as
//! a cache on top of reth's block storage.
//!
//! Reth is the source of truth for finalized blocks. The prunable archive
//! is a hot cache for the most recently finalized blocks, sized so that
//! the marshal can serve gap-repair traffic without round-tripping to
//! reth for every read. The marshal actor only ever interacts with the
//! [`Blocks`] interface so it is unaware whether a given block is served
//! from the cache or from reth.
//!
//! # Eviction
//!
//! The cache is evicted as **reth's finalized watermark rises**, not on
//! the height the marshal happens to put. Each [`Blocks::put`] queries
//! [`BlockIdReader::finalized_block_number`] and asks the prunable
//! archive to drop everything below
//! `reth_finalized − retention_blocks + 1`. Two consequences:
//!
//! - The cache never drops a block reth doesn't yet have. If reth is
//!   lagging the marshal, the cache may temporarily hold more than
//!   `retention_blocks` items — that's safe and intentional.
//! - The cache eviction floor is decoupled from the marshal's view of
//!   "tip". An explicit [`Blocks::prune`] call from the marshal is
//!   intentionally a **no-op** ([`Hybrid::prune`]) — eviction is
//!   reth-driven only. The trait contract ("`min` must remain") is
//!   trivially satisfied because we keep at least `retention_blocks`
//!   items above reth's finalized boundary.
//!
//! # Section-rounding
//!
//! The prunable archive groups items into fixed-size *sections* of
//! `items_per_section` consecutive indices (production default 4096).
//! [`prunable::Archive::prune`] silently rounds its `min` argument *down*
//! to the nearest section boundary; only entire sections are dropped. As
//! a consequence:
//!
//! - Retention is approximate: at any moment the archive holds between
//!   `retention_blocks` and `retention_blocks + items_per_section − 1`
//!   items. Pruning fires roughly once per `items_per_section` puts, in
//!   one-section batches.
//! - The "prunable holds recent, reth holds old" boundary is the
//!   archive's section-aligned `oldest_allowed`, not `tip − retention`.
//!   Reads in `[oldest_allowed, tip − retention)` still hit prunable.
//!   Same finalized block, same correctness; just a slightly wasteful
//!   path versus the design intent.
//! - `Blocks::prune(min)` from the marshal is honored as a *lower bound*
//!   only: items at and above `min` are guaranteed to remain, but items
//!   in `[section_start, min)` may also survive. The trait's "min must
//!   remain" contract is satisfied either way.
//! - A re-`put` at a height below the *requested* retention floor may
//!   succeed via the prunable archive (if it sits in the still-live
//!   tail section) or be silently absorbed by [`Hybrid::put`] (if it
//!   is below `oldest_allowed`); see "Stale puts" below.
//!
//! Pick `retention_blocks` to be at least a few multiples of
//! `items_per_section` so the section overshoot is a small fraction of
//! the working set; see [`super::DEFAULT_FINALIZED_BLOCKS_RETENTION`].
//!
//! # Stale puts
//!
//! [`Hybrid::put`] turns the prunable archive's
//! [`archive::Error::AlreadyPrunedTo`] into a *silent success* rather
//! than propagating it. The reasoning, which also explains why we
//! don't worry about reth pruning the same height (next section):
//!
//! - The cache eviction invariant is
//!   `oldest_allowed ≤ section_aligned(reth_finalized − retention + 1)
//!   ≤ reth_finalized`.
//! - So a put at `H < oldest_allowed` implies `H ≤ reth_finalized`.
//! - Reth's finality contract guarantees every block at or below
//!   `reth_finalized` is durably persisted in reth's storage and
//!   cannot be reorged.
//! - We can't write to reth's storage ourselves, but we don't have to:
//!   the marshal's subsequent [`Blocks::get`] hits the prunable miss
//!   path and is served from the reth fallback.
//! - Surfacing the error instead would crash the node via marshal's
//!   `panic!("failed to finalize")` on a perfectly recoverable
//!   condition (e.g. follow-mode catching up while reth has
//!   independently synced past the cache window).
//!
//! The legacy archive (when present) accepts arbitrary heights and
//! has already captured the block before the prunable write is
//! attempted, so a future rollback also still sees it.
//!
//! # Why reth pruning is not a concern
//!
//! Reth has its own pruning configuration; an operator can configure
//! it to retain only a window of recent history. That introduces a
//! `reth.pruned_below` watermark below which reth has discarded block
//! data. By construction reth never prunes above `reth.finalized`, so
//! always `reth.pruned_below ≤ reth.finalized`.
//!
//! For [`Hybrid`]'s correctness the only relevant question is:
//! "can the marshal ever ask us for a block at a height below
//! `reth.pruned_below`?" The answer is no for any path that would
//! panic on a miss, because:
//!
//! - **`Blocks::put(H)`**: marshal's `last_processed_height` is
//!   floored to `max(stored_height, reth.finalized)` at startup
//!   ([`alias::marshal::init`]) and `store_finalization` drops puts
//!   at `H ≤ last_processed_height` (`actor.rs:1462`). So every put
//!   we see has `H > reth.finalized > reth.pruned_below`.
//! - **`Blocks::get(Index(H))` via `get_finalized_block`**: the
//!   dispatch path only asks for the next contiguous height
//!   (`last_processed_height + 1`). The gap-repair path only asks for
//!   the `gap_end` reported by `prunable.next_gap`, which only
//!   references heights the prunable archive already has, so the call
//!   hits the cache directly and never falls through to reth.
//! - **`Blocks::get(Key(digest))` via `find_block_in_storage`**: the
//!   only path where we *can* ask for a block whose canonical height
//!   is below `reth.pruned_below`. Used by gap-repair backward walks
//!   following parent pointers (`actor.rs:1563`/`actor.rs:1578`). If
//!   reth has pruned the block we return `Ok(None)`; the marshal
//!   treats that as "not local" and issues a resolver fetch from
//!   peers. Slow, but not a panic.
//!
//! Operationally, configuring reth with a smaller retention window
//! than `retention_blocks` will cause some digest-keyed gap-repair
//! reads to miss both the cache and reth and fall back to peer
//! resolution; that's a performance issue, not a correctness one.
//!
//! [`alias::marshal::init`]: crate::alias::marshal::init

use alloy_primitives::B256;
use commonware_consensus::{Heightable as _, marshal::store::Blocks, types::Height};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, Identifier, prunable},
    translator::TwoCap,
};
use reth_node_core::primitives::SealedBlock;
use reth_provider::{
    BlockReader, BlockSource, ProviderResult,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tracing::{debug, instrument, warn};

use crate::{
    consensus::{Digest, block::Block},
    storage::legacy::Legacy,
};

mod adopt;
pub(in crate::storage) use adopt::open_legacy_for_dual_write;

#[cfg(test)]
mod test;

/// Narrow view of reth that [`Hybrid`] needs: a finalized watermark and
/// canonical-by-height / canonical-by-hash block reads.
///
/// Used instead of the corresponding reth "provider" traits
/// (`BlockIdReader`, `BlockReader`):
///
/// - [`Self::finalized_height`] is genuinely infallible on
///   [`BlockchainProvider`] (it reads `canonical_in_memory_state`), so
///   returning `Option<u64>` here removes a `Result<Option<_>>`
///   ceremony that never fires.
/// - [`Self::block_by_height`] / [`Self::block_by_hash`] still go
///   through reth's database via `ConsistentProvider` and *can* fail.
///   We surface that as [`ProviderResult`] rather than swallowing it
///   silently — the marshal needs to see read failures so it can
///   decide between resolver-driven repair and a hard panic (see the
///   call-site notes in [`super::Hybrid::get`]).
///
/// [`BlockchainProvider`]: reth_provider::providers::BlockchainProvider
pub(crate) trait FinalizedBlocksProvider: Send + Sync {
    /// Reth's last finalized block height, or `None` if reth has not yet
    /// finalized anything (fresh chain).
    fn finalized_height(&self) -> Option<u64>;

    /// Look up a finalized block by height in reth.
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
///
/// Distinguishes the two failure domains so callers (and operators
/// reading panic logs) can tell them apart:
///
/// - [`Self::Archive`]: the prunable cache or the legacy archive
///   failed.
/// - [`Self::Provider`]: reth's database read failed on the fallback
///   path. These are typically transient (disk IO, snapshot
///   contention).
///
/// Both variants implement `std::error::Error`, satisfying
/// [`Blocks::Error`]'s bound. See the module-level "Marshal panic
/// behavior" notes for what the marshal does with each.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Archive(#[from] archive::Error),

    #[error(transparent)]
    Provider(#[from] reth_provider::ProviderError),
}

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

    /// Reth provider used to look up finalized blocks below the cache
    /// window and to read reth's finalized watermark for cache eviction.
    pub(crate) provider: P,

    /// Target number of most-recently-finalized blocks (relative to
    /// reth's finalized watermark) to keep in the prunable cache. The
    /// actual retained window is approximate due to the prunable
    /// archive's section-aligned pruning — see the module docs
    /// ("Section-rounding") for the exact bounds. Anything older is
    /// dropped from the cache on each [`put`] and served out of
    /// [`Self::provider`] instead.
    ///
    /// [`put`]: commonware_consensus::marshal::store::Blocks::put
    pub(crate) retention_blocks: u64,
}

/// Finalized blocks store backed by a prunable archive (a hot cache of
/// the most recently finalized blocks) and reth (the source of truth for
/// finalized blocks).
///
/// Optionally also write-throughs to a legacy immutable archive on existing
/// nodes (for rollback safety). The legacy archive is never read from or
/// pruned by [`Hybrid`]; it is purely a backup ledger maintained for the
/// previous binary's sake until an operator cleans it up.
pub(crate) struct Hybrid<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock,
{
    /// Hot cache of recently finalized blocks. Bounded to roughly
    /// `retention_blocks` items above reth's finalized watermark via
    /// [`Self::evict_below_reth_finalized_floor`].
    prunable: Prunable<TContext>,

    /// Legacy immutable archive opened for write-through on existing nodes.
    /// `None` on fresh deployments and on nodes where the operator has
    /// removed the legacy partitions.
    legacy: Option<Legacy<TContext>>,

    /// Reth provider used to look up finalized blocks below the cache
    /// window and to read reth's finalized watermark for cache eviction.
    provider: P,

    /// Number of most-recently-finalized blocks (relative to reth's
    /// finalized watermark) to keep in the prunable cache. Anything
    /// older is dropped from the cache and served out of
    /// [`Self::provider`] instead.
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

    /// Ask the prunable archive to drop entries below reth's finalized
    /// watermark minus `retention_blocks`.
    ///
    /// The cache is sized relative to reth's finalized boundary, not to
    /// the height the marshal happens to put. This keeps two invariants:
    ///
    /// - We never evict a block reth doesn't yet have. If reth is lagging
    ///   the marshal, `reth_finalized` is small (or zero) and no eviction
    ///   happens; the cache temporarily grows past `retention_blocks`.
    /// - Eviction tracks reth's progress monotonically. Once reth
    ///   finalizes height `H`, the cache may drop everything below
    ///   `H - retention_blocks + 1` on the next put.
    ///
    /// `prune(min)` keeps `min` and above, and the archive rounds `min`
    /// *down* to a section boundary, so the actual retained window can
    /// exceed `retention_blocks` by up to `items_per_section − 1` items.
    /// See the module docs ("Section-rounding") for the full story.
    async fn evict_below_reth_finalized_floor(&mut self) -> Result<(), archive::Error> {
        // Reth hasn't finalized anything yet (fresh chain) — nothing is
        // safe to evict.
        let Some(reth_finalized) = self.provider.finalized_height() else {
            return Ok(());
        };
        let Some(min_to_keep) = reth_finalized.checked_sub(self.retention_blocks) else {
            return Ok(());
        };
        let prune_floor = min_to_keep.saturating_add(1);
        prunable::Archive::prune(&mut self.prunable, prune_floor).await
    }
}

impl<TContext, P> Blocks for Hybrid<TContext, P>
where
    TContext: BufferPooler + Storage + Metrics + Clock + Send + Sync + 'static,
    P: FinalizedBlocksProvider + 'static,
{
    type Block = Block;
    type Error = Error;

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
        match archive::Archive::put(&mut self.prunable, height.get(), digest, block).await {
            Ok(()) => {}
            // The prunable cache has already evicted this height — but
            // by the cache's eviction invariant
            // (`oldest_allowed ≤ section_aligned(reth_finalized − retention + 1)
            // ≤ reth_finalized`), `height < oldest_allowed` implies
            // `height ≤ reth_finalized`. Reth's finality contract
            // guarantees every block at or below `reth_finalized` is
            // durably persisted, so the marshal's subsequent
            // `Blocks::get(height)` will be served out of the reth
            // fallback path. We can't write to reth ourselves (it owns
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
                    reth_finalized = ?self.provider.finalized_height(),
                    "finalized block below prunable cache window; trusting reth's \
                     finalized storage and treating put as a no-op"
                );
            }
            Err(other) => return Err(other.into()),
        }

        if let Err(err) = self.evict_below_reth_finalized_floor().await {
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

    async fn get(&self, id: Identifier<'_, Digest>) -> Result<Option<Self::Block>, Self::Error> {
        // Try the prunable archive first; on miss, fall back to reth.
        // Reth read errors propagate to the marshal — see this module's
        // doc comment ("Marshal panic behavior") for what happens then.
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
                Ok(self.provider.block_by_height(height)?)
            }
            Identifier::Key(digest) => {
                if let Some(block) =
                    archive::Archive::get(&self.prunable, Identifier::Key(digest)).await?
                {
                    return Ok(Some(block));
                }
                debug!(%digest, "finalized block missing from prunable archive, falling back to reth");
                Ok(self.provider.block_by_hash(digest.0)?)
            }
        }
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        // Cache eviction is reth-driven (see [`Self::evict_below_reth_finalized_floor`]),
        // not marshal-driven, so we ignore explicit prune requests from
        // the marshal. The `Blocks::prune` contract ("`min` must remain")
        // is trivially satisfied by doing nothing — we only ever keep
        // *more* than the marshal asks. See the module docs ("Eviction")
        // for the rationale.
        debug!(%min, "ignoring marshal prune request; cache eviction is reth-driven");
        Ok(())
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
