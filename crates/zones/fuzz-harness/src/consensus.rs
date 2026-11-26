//! The zone node's block validation, for the blocks the harness executes.

use std::sync::Arc;

use alloy_primitives::B256;
use reth_chainspec::EthereumHardforks as _;
use reth_consensus::{Consensus, ConsensusError, HeaderValidator};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use tempo_evm::consensus::TempoConsensus;
use tempo_primitives::{Block, BlockBody, TempoHeader};
use zone_chainspec::ZoneChainSpec;

/// The checks `zone_node::ZoneConsensus` makes before a block executes: Tempo's, with blocks that
/// may share a timestamp, and the header fields the zone's stateless proving function derives. A
/// copy, since depending on the node would pull it into the cdylib; the two change together.
#[derive(Debug, Clone)]
pub struct ZoneConsensus {
    inner: TempoConsensus<ZoneChainSpec>,
    chain_spec: Arc<ZoneChainSpec>,
}

impl ZoneConsensus {
    /// Zone block validation on `chain_spec`.
    pub fn new(chain_spec: Arc<ZoneChainSpec>) -> Self {
        Self {
            inner: TempoConsensus::new(Arc::clone(&chain_spec)).with_allow_equal_timestamps(true),
            chain_spec,
        }
    }
}

impl HeaderValidator<TempoHeader> for ZoneConsensus {
    fn validate_header(&self, header: &SealedHeader<TempoHeader>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)?;

        let header = header.header();
        if header.consensus_context.is_some() {
            return Err(ConsensusError::other(Error::ConsensusContext));
        }
        if !header.inner.extra_data.is_empty() {
            return Err(ConsensusError::other(Error::ExtraData));
        }
        if header.inner.mix_hash != B256::ZERO {
            return Err(ConsensusError::other(Error::MixHash {
                actual: header.inner.mix_hash,
            }));
        }

        let expected_parent_beacon_block_root = self
            .chain_spec
            .is_cancun_active_at_timestamp(header.inner.timestamp)
            .then_some(B256::ZERO);
        if header.inner.parent_beacon_block_root != expected_parent_beacon_block_root {
            return Err(ConsensusError::other(Error::ParentBeaconBlockRoot {
                expected: expected_parent_beacon_block_root,
                actual: header.inner.parent_beacon_block_root,
            }));
        }

        Ok(())
    }

    /// The harness checks no header against its parent.
    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<TempoHeader>,
        parent: &SealedHeader<TempoHeader>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_header_against_parent(header, parent)
    }
}

impl Consensus<Block> for ZoneConsensus {
    fn validate_body_against_header(
        &self,
        body: &BlockBody,
        header: &SealedHeader<TempoHeader>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_body_against_header(body, header)
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<Block>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution(block)
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("zone header consensus context must be absent")]
    ConsensusContext,
    #[error("zone header extra data must be empty")]
    ExtraData,
    #[error("zone header mix hash must be zero, got {actual}")]
    MixHash { actual: B256 },
    #[error("zone header parent beacon block root must be {expected:?}, got {actual:?}")]
    ParentBeaconBlockRoot {
        expected: Option<B256>,
        actual: Option<B256>,
    },
}
