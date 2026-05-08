//! Shared helpers for [`crate::storage::hybrid`] and
//! [`crate::storage::legacy`] unit tests.
//!
//! Provides:
//! - deterministic [`Block`] construction utilities,
//! - a [`StubProvider`] hand-rolled minimum mock of
//!   [`reth_provider::BlockReader`] (only the `block`/`find_block_by_hash`
//!   paths exercised by [`crate::storage::Hybrid`] carry real behavior;
//!   everything else is a no-op stub),
//! - thin wrappers around the prunable/legacy archive constructors that
//!   hide the page-cache plumbing.
//!
//! We intentionally do not pull in `reth-provider/test-utils` to keep the
//! dev dependency footprint small.

use std::{
    collections::HashMap,
    ops::{Deref as _, RangeBounds, RangeInclusive},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use alloy_consensus::{Header, transaction::TransactionMeta};
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, B256, BlockHash, BlockNumber, TxHash, TxNumber};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    archive::prunable,
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZUsize};
use parking_lot::Mutex;
use reth_chainspec::ChainInfo;
use reth_db_api::models::StoredBlockBodyIndices;
use reth_node_core::primitives::SealedBlock;
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use reth_provider::{
    BlockBodyIndicesProvider, BlockHashReader, BlockNumReader, BlockReader, BlockSource,
    HeaderProvider, ProviderError, ProviderResult, ReceiptProvider, TransactionVariant,
    TransactionsProvider,
};
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader, TempoReceipt, TempoTxEnvelope};

use crate::{
    consensus::block::Block,
    storage::{
        PRUNABLE_ITEMS_PER_SECTION, REPLAY_BUFFER, WRITE_BUFFER,
        hybrid::Prunable,
        legacy::{Legacy, init_legacy_finalized_blocks_archive},
    },
};

/// Page size used for the test page cache. Mirrors the production default.
const TEST_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4_096);

/// Capacity of the test page cache. Tiny because tests only touch a handful
/// of blocks at a time.
const TEST_POOL_CAPACITY: std::num::NonZeroUsize = NZUsize!(64);

/// Build a deterministic [`Block`] at `height` whose parent points at
/// `parent_hash`.
///
/// Bodies are empty; the only header field that varies between tests is the
/// height (and the implicit parent linkage). The block is then sealed via
/// [`SealedBlock::seal_slow`] so its hash matches what the production code
/// would compute.
pub(in crate::storage::hybrid) fn make_block(height: u64, parent_hash: B256) -> Block {
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
    Block::from_execution_block(SealedBlock::seal_slow(inner))
}

/// Build a contiguous chain `[start..start+count]` of [`Block`]s, each
/// pointing at its predecessor.
pub(in crate::storage::hybrid) fn make_chain(start: u64, count: usize) -> Vec<Block> {
    let mut chain = Vec::with_capacity(count);
    let mut parent = B256::ZERO;
    for offset in 0..count {
        let block = make_block(start + offset as u64, parent);
        parent = block.block_hash();
        chain.push(block);
    }
    chain
}

/// Convert one of our [`Block`] wrappers back to the underlying
/// [`tempo_primitives::Block`] so it can be returned from [`StubProvider`].
fn unseal(block: &Block) -> TempoBlock {
    block.deref().clone().into_block()
}

/// Hand-rolled minimal [`BlockReader`] mock used for [`super::Hybrid`] tests.
///
/// Only the call sites exercised by [`super::Hybrid`] carry real behavior:
/// [`BlockReader::block`] (reached via `block_by_number`) and
/// [`BlockReader::find_block_by_hash`]. Every other trait method is a no-op
/// stub that returns the trivially-empty answer.
///
/// The stub also records every [`BlockReader::find_block_by_hash`] call so
/// tests can assert that we always pass [`BlockSource::Canonical`] (matches
/// the rationale in [`super::Hybrid::block_from_reth_by_digest`]).
#[derive(Clone, Default)]
pub(in crate::storage::hybrid) struct StubProvider {
    by_number: Arc<Mutex<HashMap<u64, TempoBlock>>>,
    by_hash: Arc<Mutex<HashMap<B256, TempoBlock>>>,
    find_block_by_hash_calls: Arc<Mutex<Vec<(B256, BlockSource)>>>,
    fail: Arc<AtomicBool>,
}

impl StubProvider {
    pub(in crate::storage::hybrid) fn new() -> Self {
        Self::default()
    }

    /// Seed the stub with `block` so subsequent
    /// [`BlockReader::block`]/[`BlockReader::find_block_by_hash`] calls return
    /// it.
    pub(in crate::storage::hybrid) fn add_block(&self, block: &Block) {
        let inner = unseal(block);
        let height = inner.header.inner.number;
        let hash = block.block_hash();
        self.by_number.lock().insert(height, inner.clone());
        self.by_hash.lock().insert(hash, inner);
    }

    /// Configure the stub to start failing every read with
    /// [`ProviderError::BestBlockNotFound`]. Used to exercise the
    /// "reth fallback fails" branches in [`super::Hybrid`].
    pub(in crate::storage::hybrid) fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    /// Snapshot of every [`BlockReader::find_block_by_hash`] argument received
    /// since construction.
    pub(in crate::storage::hybrid) fn find_block_by_hash_calls(&self) -> Vec<(B256, BlockSource)> {
        self.find_block_by_hash_calls.lock().clone()
    }

    fn err_if_failing<T>(&self) -> Option<ProviderResult<T>> {
        if self.fail.load(Ordering::SeqCst) {
            Some(Err(ProviderError::BestBlockNotFound))
        } else {
            None
        }
    }
}

impl BlockHashReader for StubProvider {
    fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
        Ok(None)
    }

    fn canonical_hashes_range(
        &self,
        _start: BlockNumber,
        _end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        Ok(Vec::new())
    }
}

impl BlockNumReader for StubProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        Ok(ChainInfo::default())
    }

    fn best_block_number(&self) -> ProviderResult<BlockNumber> {
        Ok(0)
    }

    fn last_block_number(&self) -> ProviderResult<BlockNumber> {
        Ok(0)
    }

    fn block_number(&self, _hash: B256) -> ProviderResult<Option<BlockNumber>> {
        Ok(None)
    }
}

impl HeaderProvider for StubProvider {
    type Header = TempoHeader;

    fn header(&self, _block_hash: BlockHash) -> ProviderResult<Option<Self::Header>> {
        Ok(None)
    }

    fn header_by_number(&self, _num: u64) -> ProviderResult<Option<Self::Header>> {
        Ok(None)
    }

    fn headers_range(
        &self,
        _range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Self::Header>> {
        Ok(Vec::new())
    }

    fn sealed_header(
        &self,
        _number: BlockNumber,
    ) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        Ok(None)
    }

    fn sealed_headers_while(
        &self,
        _range: impl RangeBounds<BlockNumber>,
        _predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
        Ok(Vec::new())
    }
}

impl BlockBodyIndicesProvider for StubProvider {
    fn block_body_indices(&self, _num: u64) -> ProviderResult<Option<StoredBlockBodyIndices>> {
        Ok(None)
    }

    fn block_body_indices_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<StoredBlockBodyIndices>> {
        Ok(Vec::new())
    }
}

impl TransactionsProvider for StubProvider {
    type Transaction = TempoTxEnvelope;

    fn transaction_id(&self, _tx_hash: TxHash) -> ProviderResult<Option<TxNumber>> {
        Ok(None)
    }

    fn transaction_by_id(&self, _id: TxNumber) -> ProviderResult<Option<Self::Transaction>> {
        Ok(None)
    }

    fn transaction_by_id_unhashed(
        &self,
        _id: TxNumber,
    ) -> ProviderResult<Option<Self::Transaction>> {
        Ok(None)
    }

    fn transaction_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<Self::Transaction>> {
        Ok(None)
    }

    fn transaction_by_hash_with_meta(
        &self,
        _hash: TxHash,
    ) -> ProviderResult<Option<(Self::Transaction, TransactionMeta)>> {
        Ok(None)
    }

    fn transactions_by_block(
        &self,
        _block_id: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Transaction>>> {
        Ok(None)
    }

    fn transactions_by_block_range(
        &self,
        _range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Transaction>>> {
        Ok(Vec::new())
    }

    fn transactions_by_tx_range(
        &self,
        _range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Transaction>> {
        Ok(Vec::new())
    }

    fn senders_by_tx_range(
        &self,
        _range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        Ok(Vec::new())
    }

    fn transaction_sender(&self, _id: TxNumber) -> ProviderResult<Option<Address>> {
        Ok(None)
    }
}

impl ReceiptProvider for StubProvider {
    type Receipt = TempoReceipt;

    fn receipt(&self, _id: TxNumber) -> ProviderResult<Option<Self::Receipt>> {
        Ok(None)
    }

    fn receipt_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<Self::Receipt>> {
        Ok(None)
    }

    fn receipts_by_block(
        &self,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Receipt>>> {
        Ok(None)
    }

    fn receipts_by_tx_range(
        &self,
        _range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Receipt>> {
        Ok(Vec::new())
    }

    fn receipts_by_block_range(
        &self,
        _block_range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Receipt>>> {
        Ok(Vec::new())
    }
}

impl BlockReader for StubProvider {
    type Block = TempoBlock;

    fn find_block_by_hash(
        &self,
        hash: B256,
        source: BlockSource,
    ) -> ProviderResult<Option<Self::Block>> {
        self.find_block_by_hash_calls.lock().push((hash, source));
        if let Some(err) = self.err_if_failing() {
            return err;
        }
        Ok(self.by_hash.lock().get(&hash).cloned())
    }

    fn block(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Self::Block>> {
        if let Some(err) = self.err_if_failing() {
            return err;
        }
        match id {
            BlockHashOrNumber::Hash(hash) => Ok(self.by_hash.lock().get(&hash).cloned()),
            BlockHashOrNumber::Number(num) => Ok(self.by_number.lock().get(&num).cloned()),
        }
    }

    fn pending_block(&self) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        Ok(None)
    }

    fn pending_block_and_receipts(
        &self,
    ) -> ProviderResult<Option<(RecoveredBlock<Self::Block>, Vec<Self::Receipt>)>> {
        Ok(None)
    }

    fn recovered_block(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        Ok(None)
    }

    fn sealed_block_with_senders(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        Ok(None)
    }

    fn block_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<Self::Block>> {
        Ok(Vec::new())
    }

    fn block_with_senders_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        Ok(Vec::new())
    }

    fn recovered_block_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        Ok(Vec::new())
    }

    fn block_by_transaction_id(&self, _id: TxNumber) -> ProviderResult<Option<BlockNumber>> {
        Ok(None)
    }
}

/// Build a fresh page cache rooted in `context`.
pub(in crate::storage::hybrid) fn fresh_page_cache<TContext>(context: &TContext) -> CacheRef
where
    TContext: BufferPooler,
{
    CacheRef::from_pooler(context, TEST_PAGE_SIZE, TEST_POOL_CAPACITY)
}

/// Initialize a fresh prunable finalized blocks archive against `context`
/// with the production-default `items_per_section` (large enough that no
/// pruning happens for the small chains used in most tests).
pub(in crate::storage::hybrid) async fn fresh_prunable<TContext>(
    context: &TContext,
    partition_prefix: &str,
) -> Prunable<TContext>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    fresh_prunable_with_section_size(context, partition_prefix, PRUNABLE_ITEMS_PER_SECTION).await
}

/// Initialize a fresh prunable finalized blocks archive against `context`
/// with a configurable `items_per_section`.
///
/// Tests that exercise the retention/prune machinery need a small
/// `items_per_section` (1, 2, …) so that section boundaries align with
/// individual heights — the prunable archive's `prune(min)` is rounded down
/// to the nearest section boundary, so a 4 096-item section would never
/// drop a handful of low-numbered test heights.
pub(in crate::storage::hybrid) async fn fresh_prunable_with_section_size<TContext>(
    context: &TContext,
    partition_prefix: &str,
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
            key_partition: format!("{partition_prefix}-prunable-key"),
            key_page_cache: cache,
            value_partition: format!("{partition_prefix}-prunable-value"),
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

/// Initialize a fresh legacy immutable finalized blocks archive against
/// `context`.
pub(in crate::storage::hybrid) async fn fresh_legacy<TContext>(
    context: &TContext,
    partition_prefix: &str,
) -> Legacy<TContext>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let cache = fresh_page_cache(context);
    init_legacy_finalized_blocks_archive(context, partition_prefix, cache)
        .await
        .expect("init legacy archive")
}
