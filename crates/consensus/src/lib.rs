//! Tempo consensus implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::{BlockHeader, EMPTY_OMMER_ROOT_HASH, Transaction};
use alloy_eips::eip7840::BlobParams;
use alloy_evm::{block::BlockExecutionResult, revm::primitives::Address};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::{
    validate_4844_header_standalone, validate_against_parent_4844,
    validate_against_parent_eip1559_base_fee, validate_against_parent_gas_limit,
    validate_against_parent_hash_number, validate_header_base_fee, validate_header_gas,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_contracts::precompiles::{
    STABLECOIN_EXCHANGE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_REWARDS_REGISTRY_ADDRESS,
};
use tempo_primitives::{
    Block, BlockBody, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope,
};

// End-of-block system transactions (required)
const END_OF_BLOCK_SYSTEM_TX_COUNT: usize = 3;
const END_OF_BLOCK_SYSTEM_TX_ADDRESSES: [Address; END_OF_BLOCK_SYSTEM_TX_COUNT] = [
    TIP_FEE_MANAGER_ADDRESS,
    STABLECOIN_EXCHANGE_ADDRESS,
    Address::ZERO,
];

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

    /// This is `<EthBeaconConsensus<TempoChainSpec> as EthBeaconConsensus<TempoChainSpec>>::validate_header`
    /// with the caps on the maximum extraData field removed.
    fn eth_beacon_validate_header(
        &self,
        header: &SealedHeader<TempoHeader>,
    ) -> Result<(), ConsensusError> {
        let header = header.header();
        let chain_spec = self.inner.chain_spec();

        let is_post_merge = chain_spec.is_paris_active_at_block(header.number());

        if is_post_merge {
            if !header.difficulty().is_zero() {
                return Err(ConsensusError::TheMergeDifficultyIsNotZero);
            }

            if !header.nonce().is_some_and(|nonce| nonce.is_zero()) {
                return Err(ConsensusError::TheMergeNonceIsNotZero);
            }

            if header.ommers_hash() != EMPTY_OMMER_ROOT_HASH {
                return Err(ConsensusError::TheMergeOmmerRootIsNotEmpty);
            }
        } else {
            // TODO(janis): std feature commented out - tempo is always std
            // #[cfg(feature = "std")]
            {
                let present_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if header.timestamp()
                    > present_timestamp + alloy_eips::merge::ALLOWED_FUTURE_BLOCK_TIME_SECONDS
                {
                    return Err(ConsensusError::TimestampIsInFuture {
                        timestamp: header.timestamp(),
                        present_timestamp,
                    });
                }
            }
        }

        validate_header_extra_data(header)?;
        validate_header_gas(header)?;
        validate_header_base_fee(header, chain_spec)?;

        // EIP-4895: Beacon chain push withdrawals as operations
        if chain_spec.is_shanghai_active_at_timestamp(header.timestamp())
            && header.withdrawals_root().is_none()
        {
            return Err(ConsensusError::WithdrawalsRootMissing);
        } else if !chain_spec.is_shanghai_active_at_timestamp(header.timestamp())
            && header.withdrawals_root().is_some()
        {
            return Err(ConsensusError::WithdrawalsRootUnexpected);
        }

        // Ensures that EIP-4844 fields are valid once cancun is active.
        if chain_spec.is_cancun_active_at_timestamp(header.timestamp()) {
            validate_4844_header_standalone(
                header,
                chain_spec
                    .blob_params_at_timestamp(header.timestamp())
                    .unwrap_or_else(BlobParams::cancun),
            )?;
        } else if header.blob_gas_used().is_some() {
            return Err(ConsensusError::BlobGasUsedUnexpected);
        } else if header.excess_blob_gas().is_some() {
            return Err(ConsensusError::ExcessBlobGasUnexpected);
        } else if header.parent_beacon_block_root().is_some() {
            return Err(ConsensusError::ParentBeaconBlockRootUnexpected);
        }

        if chain_spec.is_prague_active_at_timestamp(header.timestamp()) {
            if header.requests_hash().is_none() {
                return Err(ConsensusError::RequestsHashMissing);
            }
        } else if header.requests_hash().is_some() {
            return Err(ConsensusError::RequestsHashUnexpected);
        }

        Ok(())
    }
}

impl HeaderValidator<TempoHeader> for TempoConsensus {
    fn validate_header(&self, header: &SealedHeader<TempoHeader>) -> Result<(), ConsensusError> {
        self.eth_beacon_validate_header(header)?;

        let shared_gas_limit = header.gas_limit() / TEMPO_SHARED_GAS_DIVISOR;

        // Validate the non-payment gas limit
        if header.general_gas_limit
            != (header.gas_limit() - shared_gas_limit) / TEMPO_GENERAL_GAS_DIVISOR
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

        // Check for optional rewards registry system transaction at the start
        if let Some(first_tx) = transactions.first()
            && first_tx.is_system_tx()
            && first_tx.to().unwrap_or_default() != TIP20_REWARDS_REGISTRY_ADDRESS
        {
            return Err(ConsensusError::Other(
                "First transaction must be rewards registry if it's a system tx".to_string(),
            ));
        }

        // Get the last END_OF_BLOCK_SYSTEM_TX_COUNT transactions and validate they are end-of-block system txs
        let end_of_block_system_txs = transactions
            .get(
                transactions
                    .len()
                    .saturating_sub(END_OF_BLOCK_SYSTEM_TX_COUNT)..,
            )
            .map(|slice| {
                slice
                    .iter()
                    .filter(|tx| tx.is_system_tx())
                    .collect::<Vec<&TempoTxEnvelope>>()
            })
            .unwrap_or_default();

        if end_of_block_system_txs.len() != END_OF_BLOCK_SYSTEM_TX_COUNT {
            return Err(ConsensusError::Other(
                "Block must contain end-of-block system txs".to_string(),
            ));
        }

        // Validate that the sequence of end-of-block system txs is correct
        for (tx, expected_to) in end_of_block_system_txs
            .into_iter()
            .zip(END_OF_BLOCK_SYSTEM_TX_ADDRESSES)
        {
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

const MAXIMUM_EXTRA_DATA_SIZE: usize = 10 * 1_024; // 10KiB

/// Custom version of reth_consensus_common::validation::validate_header_extra_data
#[inline]
fn validate_header_extra_data<H: BlockHeader>(header: &H) -> Result<(), ConsensusError> {
    let extra_data_len = header.extra_data().len();
    if extra_data_len > MAXIMUM_EXTRA_DATA_SIZE {
        Err(ConsensusError::ExtraDataExceedsMax {
            len: extra_data_len,
        })
    } else {
        Ok(())
    }
}
