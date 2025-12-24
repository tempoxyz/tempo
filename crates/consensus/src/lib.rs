//! Tempo consensus implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy_consensus::{BlockHeader, Transaction, transaction::TxHashRef};
use alloy_evm::{block::BlockExecutionResult, revm::primitives::Address};
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_eip1559_base_fee,
    validate_against_parent_gas_limit, validate_against_parent_hash_number,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;
use tempo_chainspec::{hardfork::TempoHardforks, spec::TempoChainSpec};
use tempo_contracts::precompiles::STABLECOIN_EXCHANGE_ADDRESS;
use tempo_primitives::{
    Block, BlockBody, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope,
};

// End-of-block system transactions
const SYSTEM_TX_COUNT: usize = 1;
const SYSTEM_TX_ADDRESSES: [Address; SYSTEM_TX_COUNT] = [Address::ZERO];

/// How far in the future the block timestamp can be.
pub const ALLOWED_FUTURE_BLOCK_TIME_SECONDS: u64 = 3;

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
            inner: EthBeaconConsensus::new(chain_spec)
                .with_max_extra_data_size(TEMPO_MAXIMUM_EXTRA_DATA_SIZE),
        }
    }
}

impl HeaderValidator<TempoHeader> for TempoConsensus {
    fn validate_header(&self, header: &SealedHeader<TempoHeader>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)?;

        let present_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time should never be before UNIX EPOCH")
            .as_secs();

        if header.timestamp() > present_timestamp + ALLOWED_FUTURE_BLOCK_TIME_SECONDS {
            return Err(ConsensusError::TimestampIsInFuture {
                timestamp: header.timestamp(),
                present_timestamp,
            });
        }

        if header.shared_gas_limit != header.gas_limit() / TEMPO_SHARED_GAS_DIVISOR {
            return Err(ConsensusError::Other(
                "Shared gas limit does not match header gas limit".to_string(),
            ));
        }

        // Validate the non-payment gas limit
        if header.general_gas_limit
            != (header.gas_limit() - header.shared_gas_limit) / TEMPO_GENERAL_GAS_DIVISOR
        {
            return Err(ConsensusError::Other(
                "Non-payment gas limit does not match header gas limit".to_string(),
            ));
        }

        // Validate the timestamp milliseconds part
        if header.timestamp_millis_part >= 1000 {
            return Err(ConsensusError::Other(
                "Timestamp milliseconds part must be less than 1000".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<TempoHeader>,
        parent: &SealedHeader<TempoHeader>,
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
            .blob_params_at_timestamp(header.timestamp())
        {
            validate_against_parent_4844(header.header(), parent.header(), blob_params)?;
        }

        if header.timestamp_millis() <= parent.timestamp_millis() {
            return Err(ConsensusError::TimestampIsInPast {
                parent_timestamp: parent.timestamp_millis(),
                timestamp: header.timestamp_millis(),
            });
        }

        Ok(())
    }
}

impl Consensus<Block> for TempoConsensus {
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        body: &BlockBody,
        header: &SealedHeader<TempoHeader>,
    ) -> Result<(), Self::Error> {
        Consensus::<Block>::validate_body_against_header(&self.inner, body, header)
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<Block>) -> Result<(), Self::Error> {
        let transactions = &block.body().transactions;

        if let Some(tx) = transactions.iter().find(|&tx| {
            tx.is_system_tx() && !tx.is_valid_system_tx(self.inner.chain_spec().chain().id())
        }) {
            return Err(ConsensusError::Other(format!(
                "Invalid system transaction: {}",
                tx.tx_hash()
            )));
        }

        // Get the last END_OF_BLOCK_SYSTEM_TX_COUNT transactions and validate they are end-of-block system txs
        let end_of_block_system_txs = transactions
            .get(transactions.len().saturating_sub(SYSTEM_TX_COUNT)..)
            .map(|slice| {
                slice
                    .iter()
                    .filter(|tx| tx.is_system_tx())
                    .collect::<Vec<&TempoTxEnvelope>>()
            })
            .unwrap_or_default();

        if end_of_block_system_txs.len() != SYSTEM_TX_COUNT {
            return Err(ConsensusError::Other(
                "Block must contain end-of-block system txs".to_string(),
            ));
        }

        // Validate that the sequence of end-of-block system txs is correct
        for (tx, expected_to) in end_of_block_system_txs.into_iter().zip(SYSTEM_TX_ADDRESSES) {
            if tx.to().unwrap_or_default() != expected_to {
                return Err(ConsensusError::Other(
                    "Invalid end-of-block system tx order".to_string(),
                ));
            }
        }

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

/// Divisor for calculating non-payment gas limit.
pub const TEMPO_GENERAL_GAS_DIVISOR: u64 = 2;

/// Divisor for calculating shared gas limit.
pub const TEMPO_SHARED_GAS_DIVISOR: u64 = 10;

/// Maximum extra data size for Tempo blocks.
pub const TEMPO_MAXIMUM_EXTRA_DATA_SIZE: usize = 10 * 1_024; // 10KiB
