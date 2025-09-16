//! Tempo consensus implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::Header;
use alloy_evm::block::BlockExecutionResult;
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_eip1559_base_fee,
    validate_against_parent_gas_limit, validate_against_parent_hash_number,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_primitives::{Block, BlockBody, TempoPrimitives, TempoReceipt};

/// Tempo consensus implementation.
#[derive(Debug, Clone)]
pub struct TempoConsensus {
    /// Inner Ethereum consensus.
    inner: EthBeaconConsensus<TempoChainSpec>,
}

impl TempoConsensus {
    /// Creates a new [`TempoConsensus`] with the given chain spec.
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            inner: EthBeaconConsensus::new(chain_spec),
        }
    }
}

impl HeaderValidator<Header> for TempoConsensus {
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        validate_against_parent_hash_number(header.header(), parent)?;

        validate_against_parent_gas_limit(header, parent, self.inner.chain_spec())?;

        validate_against_parent_eip1559_base_fee(
            header.header(),
            parent.header(),
            self.inner.chain_spec(),
        )?;

        if let Some(blob_params) = self
            .inner
            .chain_spec()
            .blob_params_at_timestamp(header.timestamp)
        {
            validate_against_parent_4844(header.header(), parent.header(), blob_params)?;
        }

        Ok(())
    }
}

impl Consensus<Block> for TempoConsensus {
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        body: &BlockBody,
        header: &SealedHeader,
    ) -> Result<(), Self::Error> {
        Consensus::<Block>::validate_body_against_header(&self.inner, body, header)
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<Block>) -> Result<(), Self::Error> {
        self.inner.validate_block_pre_execution(block)
    }
}

impl FullConsensus<TempoPrimitives> for TempoConsensus {
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<Block>,
        result: &BlockExecutionResult<TempoReceipt>,
    ) -> Result<(), ConsensusError> {
        FullConsensus::<TempoPrimitives>::validate_block_post_execution(&self.inner, block, result)
    }
}
