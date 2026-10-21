//! Reth provider capabilities used by the Zone consensus engine.

use alloy_primitives::B256;
use reth_provider::{BlockSource, ProviderError, ProviderResult};
use reth_storage_api::{BlockIdReader, BlockReader, HeaderProvider, StateProviderFactory};
use tempo_consensus::{consensus::Block, storage::FinalizedBlocksProvider};
use tempo_primitives::TempoHeader;
use tracing::{error, info};

/// Reth provider capabilities required by the Zone consensus engine.
///
/// A zero-method convenience trait so the engine stays generic over the node's provider type.
pub trait ConsensusProvider:
    BlockReader<Block = tempo_primitives::Block>
    + HeaderProvider<Header = TempoHeader>
    + BlockIdReader
    + StateProviderFactory
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> ConsensusProvider for T where
    T: BlockReader<Block = tempo_primitives::Block>
        + HeaderProvider<Header = TempoHeader>
        + BlockIdReader
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Serves reth's finalized Zone blocks to marshal's hybrid finalized-block store.
///
/// Mirrors the L1 implementation over `BlockchainProvider`, which the generic node provider
/// type cannot name.
#[derive(Clone, Debug)]
pub(crate) struct FinalizedBlocks<P>(pub(crate) P);

impl<P: ConsensusProvider> FinalizedBlocksProvider for FinalizedBlocks<P> {
    fn finalized_height(&self) -> Option<u64> {
        match self.0.finalized_block_number() {
            Ok(number) => number,
            Err(error) => {
                // The trait is infallible; an unreadable watermark only defers eviction and
                // gap coverage to the prunable cache.
                error!(target: "zone::consensus", %error, "Failed reading the finalized Zone height");
                None
            }
        }
    }

    fn block_by_height(&self, height: u64) -> ProviderResult<Option<Block>> {
        // Marshal must never be served a block reth has not finalized; genesis is implicitly
        // finalized.
        if height > self.finalized_height().unwrap_or_default() {
            return Ok(None);
        }
        let hash = match self.0.block_hash(height) {
            Ok(Some(hash)) => hash,
            Ok(None) => return Ok(None),
            Err(err @ ProviderError::BlockExpired { .. }) => {
                info!(target: "zone::consensus", error = %eyre::Report::new(err), "cannot find block");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.block_by_hash(hash)
    }

    fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>> {
        match self
            .0
            .find_sealed_or_recovered_block(hash, BlockSource::Canonical)
        {
            Ok(Some(block)) => Block::try_from_execution_block(block)
                .map(Some)
                .map_err(ProviderError::other),
            Ok(None) => Ok(None),
            Err(err @ ProviderError::BlockExpired { .. }) => {
                info!(target: "zone::consensus", error = %eyre::Report::new(err), "cannot find block");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn header_by_height(&self, height: u64) -> ProviderResult<Option<TempoHeader>> {
        if height > self.finalized_height().unwrap_or_default() {
            return Ok(None);
        }
        self.0.header_by_number(height)
    }

    fn header_by_hash(&self, hash: B256) -> ProviderResult<Option<TempoHeader>> {
        self.0.header(hash)
    }
}
