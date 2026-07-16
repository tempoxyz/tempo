//! Shared helpers for [`crate::storage::hybrid`] unit tests.
//!
//! Provides:
//! - deterministic [`Block`] construction utilities,
//! - a tiny [`StubProvider`] that implements only
//!   [`super::super::FinalizedBlocksProvider`] — the narrow seam that
//!   [`super::super::Hybrid`] reads reth through. The historical stub
//!   had to implement reth's full `BlockReader` / `BlockIdReader` /
//!   `HeaderProvider` / `TransactionsProvider` / … surface; switching
//!   to our own trait shrinks it to ~30 lines.
//! - a thin wrapper around the prunable archive constructor that hides
//!   the page-cache plumbing.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use alloy_consensus::Header;
use alloy_primitives::B256;
use commonware_consensus::Heightable as _;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZU16, NZUsize};
use parking_lot::Mutex;
use reth_node_core::primitives::SealedBlock;
use reth_provider::{ProviderError, ProviderResult};
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use crate::{
    consensus::block::Block,
    storage::{
        REPLAY_BUFFER, WRITE_BUFFER,
        hybrid::{FinalizedBlocksProvider, Prunable},
    },
};

/// Page size used for the test page cache. Mirrors the production default.
const TEST_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4_096);

/// Capacity of the test page cache. Tiny because tests only touch a handful
/// of blocks at a time.
const TEST_POOL_CAPACITY: std::num::NonZeroUsize = NZUsize!(64);

/// Partition prefix shared by every test's prunable archive. Each test
/// runs against its own [`commonware_runtime::deterministic`] context, so
/// the in-memory storage is already isolated per test.
const TEST_PARTITION_PREFIX: &str = "test";

/// Build a deterministic [`Block`] at `height` whose parent points at
/// `parent_hash`.
///
/// Bodies are empty; the only header field that varies between tests is the
/// height (and the implicit parent linkage). The block is then sealed via
/// [`SealedBlock::seal_slow`] so its hash matches what the production code
/// would compute.
pub(in crate::storage) fn make_block(height: u64, parent_hash: B256) -> Block {
    let header = TempoHeader {
        inner: Header {
            parent_hash,
            number: height,
            ..Default::default()
        },
        ..Default::default()
    };
    let body = BlockBody::default();
    let inner = TempoBlock { header, body };
    Block::from_execution_block(SealedBlock::seal_slow(inner), None)
        .expect("test block should not carry BAL side data")
}

/// Build a contiguous chain `[start..start+count]` of [`Block`]s, each
/// pointing at its predecessor.
pub(in crate::storage) fn make_chain(start: u64, count: usize) -> Vec<Block> {
    let mut chain = Vec::with_capacity(count);
    let mut parent = B256::ZERO;
    for offset in 0..count {
        let block = make_block(start + offset as u64, parent);
        parent = block.block_hash();
        chain.push(block);
    }
    chain
}

/// Hand-rolled minimal [`FinalizedBlocksProvider`] mock used for
/// [`super::Hybrid`] tests. Stores a map of seeded blocks keyed by both
/// height and hash, and an optional finalized-watermark used to drive
/// [`Hybrid`]'s cache eviction.
///
/// The optional `fail` flag flips every read to
/// `Err(ProviderError::BestBlockNotFound)` — used to exercise the
/// "reth fallback errored" branch in [`super::Hybrid::get`], which
/// propagates the error as [`super::Error::Provider`] up to the
/// marshal.
#[derive(Clone, Default)]
pub(in crate::storage::hybrid) struct StubProvider {
    by_number: Arc<Mutex<HashMap<u64, Block>>>,
    by_hash: Arc<Mutex<HashMap<B256, Block>>>,
    fail: Arc<AtomicBool>,
    /// Reth's finalized block height. `None` means reth has not yet
    /// finalized anything (fresh chain). Drives [`Hybrid`]'s cache
    /// eviction floor; default `None` keeps the cache from evicting
    /// anything in tests that don't care.
    reth_finalized: Arc<Mutex<Option<u64>>>,
}

impl StubProvider {
    pub(in crate::storage::hybrid) fn new() -> Self {
        Self::default()
    }

    /// Seed the stub so subsequent
    /// [`FinalizedBlocksProvider::block_by_height`] /
    /// [`FinalizedBlocksProvider::block_by_hash`] calls return `block`.
    pub(in crate::storage::hybrid) fn add_block(&self, block: &Block) {
        let height = block.height().get();
        let hash = block.block_hash();
        self.by_number.lock().insert(height, block.clone());
        self.by_hash.lock().insert(hash, block.clone());
    }

    /// Configure the stub to start failing every read with
    /// [`ProviderError::BestBlockNotFound`]. Used to exercise the
    /// "reth fallback errored" branch in [`super::Hybrid::get`].
    pub(in crate::storage::hybrid) fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    /// Set the finalized block height that the stub reports via
    /// [`FinalizedBlocksProvider::finalized_height`]. Drives
    /// [`Hybrid`]'s cache eviction floor in tests.
    pub(in crate::storage::hybrid) fn set_reth_finalized(&self, height: u64) {
        *self.reth_finalized.lock() = Some(height);
    }

    fn err_if_failing<T>(&self) -> Option<ProviderResult<T>> {
        self.fail
            .load(Ordering::SeqCst)
            .then(|| Err(ProviderError::BestBlockNotFound))
    }
}

impl FinalizedBlocksProvider for StubProvider {
    fn finalized_height(&self) -> Option<u64> {
        *self.reth_finalized.lock()
    }

    fn block_by_height(&self, height: u64) -> ProviderResult<Option<Block>> {
        if let Some(err) = self.err_if_failing() {
            return err;
        }
        // Mirror the production [`BlockchainProvider`] impl: only
        // blocks at or below reth's finalized watermark are reachable,
        // regardless of what was seeded via [`Self::add_block`]. An
        // unset watermark still covers genesis (height 0), which is
        // implicitly finalized.
        let finalized = self.reth_finalized.lock().unwrap_or_default();
        if height > finalized {
            return Ok(None);
        }
        Ok(self.by_number.lock().get(&height).cloned())
    }

    fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>> {
        if let Some(err) = self.err_if_failing() {
            return err;
        }
        Ok(self.by_hash.lock().get(&hash).cloned())
    }
}

/// Build a fresh page cache rooted in `context`.
pub(in crate::storage) fn fresh_page_cache<TContext>(context: &TContext) -> CacheRef
where
    TContext: BufferPooler,
{
    CacheRef::from_pooler(context, TEST_PAGE_SIZE, TEST_POOL_CAPACITY)
}

/// Initialize a fresh prunable finalized blocks archive against `context`
/// with a configurable `items_per_section`.
///
/// Tests that exercise the retention/prune machinery need a small
/// `items_per_section` (1, 2, …) so that section boundaries align with
/// individual heights — the prunable archive's `prune(min)` is rounded down
/// to the nearest section boundary, so a 4 096-item section would never
/// drop a handful of low-numbered test heights.
pub(in crate::storage) async fn fresh_prunable_with_section_size<TContext>(
    context: &TContext,
    items_per_section: std::num::NonZeroU64,
) -> Prunable<TContext>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let cache = fresh_page_cache(context);
    prunable::Archive::init(
        context.with_label("finalized_blocks_prunable"),
        prunable::Config {
            translator: TwoCap,
            key_partition: format!("{TEST_PARTITION_PREFIX}-prunable-key"),
            key_page_cache: cache,
            value_partition: format!("{TEST_PARTITION_PREFIX}-prunable-value"),
            // Tests use blocks small enough that compression overhead would
            // dominate; mirror production's compression to keep the codec
            // path identical.
            compression: Some(3),
            codec_config: (),
            items_per_section,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        },
    )
    .await
    .expect("init prunable archive")
}
