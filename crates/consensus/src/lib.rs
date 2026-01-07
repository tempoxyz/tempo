//! Tempo consensus implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy_consensus::{BlockHeader, Transaction, transaction::TxHashRef};
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
use tempo_chainspec::spec::{SYSTEM_TX_ADDRESSES, SYSTEM_TX_COUNT, TempoChainSpec};
use tempo_primitives::{
    Block, BlockBody, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{
        Header, Signed, TxLegacy, constants::EMPTY_ROOT_HASH, proofs::calculate_transaction_root,
        transaction::TxHashRef,
    };
    use alloy_primitives::{Address, B256, Signature, TxKind, U256};
    use reth_primitives_traits::SealedHeader;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_chainspec::spec::ANDANTINO;

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[derive(Default)]
    struct TestHeaderBuilder {
        gas_limit: u64,
        timestamp: u64,
        timestamp_millis_part: u64,
        number: u64,
        parent_hash: B256,
        shared_gas_limit: Option<u64>,
        general_gas_limit: Option<u64>,
    }

    impl TestHeaderBuilder {
        fn gas_limit(mut self, gas_limit: u64) -> Self {
            self.gas_limit = gas_limit;
            self
        }

        fn timestamp(mut self, timestamp: u64) -> Self {
            self.timestamp = timestamp;
            self
        }

        fn timestamp_millis_part(mut self, millis: u64) -> Self {
            self.timestamp_millis_part = millis;
            self
        }

        fn number(mut self, number: u64) -> Self {
            self.number = number;
            self
        }

        fn parent_hash(mut self, hash: B256) -> Self {
            self.parent_hash = hash;
            self
        }

        fn shared_gas_limit(mut self, limit: u64) -> Self {
            self.shared_gas_limit = Some(limit);
            self
        }

        fn general_gas_limit(mut self, limit: u64) -> Self {
            self.general_gas_limit = Some(limit);
            self
        }

        fn build(self) -> TempoHeader {
            let shared_gas_limit = self
                .shared_gas_limit
                .unwrap_or(self.gas_limit / TEMPO_SHARED_GAS_DIVISOR);
            let general_gas_limit = self.general_gas_limit.unwrap_or_else(|| {
                (self.gas_limit - self.gas_limit / TEMPO_SHARED_GAS_DIVISOR)
                    / TEMPO_GENERAL_GAS_DIVISOR
            });

            TempoHeader {
                inner: Header {
                    gas_limit: self.gas_limit,
                    timestamp: self.timestamp,
                    number: self.number,
                    parent_hash: self.parent_hash,
                    base_fee_per_gas: Some(tempo_chainspec::spec::TEMPO_BASE_FEE),
                    withdrawals_root: Some(EMPTY_ROOT_HASH),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    ..Default::default()
                },
                shared_gas_limit,
                general_gas_limit,
                timestamp_millis_part: self.timestamp_millis_part,
            }
        }
    }

    fn create_valid_block(header: TempoHeader, transactions: Vec<TempoTxEnvelope>) -> Block {
        let transactions_root = calculate_transaction_root(&transactions);
        let mut header = header;
        header.inner.transactions_root = transactions_root;

        Block {
            header,
            body: BlockBody {
                transactions,
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        }
    }

    fn create_system_tx(chain_id: u64, to: Address) -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: Default::default(),
        };
        let signature = Signature::new(U256::ZERO, U256::ZERO, false);
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, signature))
    }

    fn create_tx(chain_id: u64) -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 1,
            gas_price: 1_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(Address::repeat_byte(0x42)),
            value: U256::from(100),
            input: Default::default(),
        };
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    #[test]
    fn test_validate_header() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .timestamp_millis_part(500)
            .build();
        let sealed = SealedHeader::seal_slow(header);

        assert!(consensus.validate_header(&sealed).is_ok());
    }

    #[test]
    fn test_validate_header_timestamp_in_the_future() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let future_timestamp = current_timestamp() + ALLOWED_FUTURE_BLOCK_TIME_SECONDS + 10;
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(future_timestamp)
            .timestamp_millis_part(500)
            .build();
        let sealed = SealedHeader::seal_slow(header);

        let result = consensus.validate_header(&sealed);
        assert!(
            matches!(result, Err(ConsensusError::TimestampIsInFuture { timestamp, .. }) if timestamp == future_timestamp)
        );
    }

    #[test]
    fn test_validate_header_shared_gas_mismatch() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .shared_gas_limit(999)
            .build();
        let sealed = SealedHeader::seal_slow(header);

        let result = consensus.validate_header(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(
                "Shared gas limit does not match header gas limit".to_string()
            ))
        );
    }

    #[test]
    fn test_validate_header_non_payment_gas_mismatch() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .general_gas_limit(999)
            .build();
        let sealed = SealedHeader::seal_slow(header);

        let result = consensus.validate_header(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(
                "Non-payment gas limit does not match header gas limit".to_string()
            ))
        );
    }

    #[test]
    fn test_validate_header_timestamp_milli_gte_1000() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());

        // Test timestamp equal to 1000
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .timestamp_millis_part(1000)
            .build();
        let sealed = SealedHeader::seal_slow(header);

        let result = consensus.validate_header(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(
                "Timestamp milliseconds part must be less than 1000".to_string()
            ))
        );

        // Test timestamp > 1000
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .timestamp_millis_part(1001)
            .build();
        let sealed = SealedHeader::seal_slow(header);
        let result = consensus.validate_header(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(
                "Timestamp milliseconds part must be less than 1000".to_string()
            ))
        );
    }

    #[test]
    fn test_validate_header_against_parent() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let parent_ts = current_timestamp() - 1;
        let parent = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(parent_ts)
            .number(1)
            .timestamp_millis_part(500)
            .build();
        let parent_sealed = SealedHeader::seal_slow(parent);

        let child = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(parent_ts + 1)
            .timestamp_millis_part(600)
            .number(2)
            .parent_hash(parent_sealed.hash())
            .build();
        let child_sealed = SealedHeader::seal_slow(child);

        let result = consensus.validate_header_against_parent(&child_sealed, &parent_sealed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_header_against_parent_timestamp_not_increasing() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let parent_ts = current_timestamp();
        let parent = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(parent_ts)
            .timestamp_millis_part(500)
            .build();
        let parent_sealed = SealedHeader::seal_slow(parent);

        let child = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(parent_ts)
            .timestamp_millis_part(400)
            .number(1)
            .parent_hash(parent_sealed.hash())
            .build();
        let child_sealed = SealedHeader::seal_slow(child);

        let parent_timestamp_millis = parent_ts * 1000 + 500;
        let child_timestamp_millis = parent_ts * 1000 + 400;
        let result = consensus.validate_header_against_parent(&child_sealed, &parent_sealed);
        assert_eq!(
            result,
            Err(ConsensusError::TimestampIsInPast {
                parent_timestamp: parent_timestamp_millis,
                timestamp: child_timestamp_millis,
            })
        );
    }

    #[test]
    fn test_validate_body_against_header() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .build();
        let sealed = SealedHeader::seal_slow(header);
        let body = BlockBody {
            withdrawals: Some(Default::default()),
            ..Default::default()
        };

        assert!(
            consensus
                .validate_body_against_header(&body, &sealed)
                .is_ok()
        );
    }

    #[test]
    fn test_validate_block_pre_execution() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let chain_id = ANDANTINO.chain().id();

        let system_tx = create_system_tx(chain_id, SYSTEM_TX_ADDRESSES[0]);
        let user_tx = create_tx(chain_id);

        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .build();
        let block = create_valid_block(header, vec![user_tx, system_tx]);
        let sealed = reth_primitives_traits::SealedBlock::seal_slow(block);

        assert!(consensus.validate_block_pre_execution(&sealed).is_ok());
    }

    #[test]
    fn test_validate_block_pre_execution_invalid_system_tx() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let chain_id = ANDANTINO.chain().id();

        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Default::default(),
        };
        let signature = Signature::new(U256::ZERO, U256::ZERO, false);
        let invalid_system_tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, signature));
        let tx_hash = *invalid_system_tx.tx_hash();

        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .build();
        let block = create_valid_block(header, vec![invalid_system_tx]);
        let sealed = SealedBlock::seal_slow(block);

        let result = consensus.validate_block_pre_execution(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(format!(
                "Invalid system transaction: {tx_hash}"
            )))
        );
    }

    #[test]
    fn test_validate_block_pre_execution_no_system_tx() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let chain_id = ANDANTINO.chain().id();

        let user_tx = create_tx(chain_id);

        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .build();
        let block = create_valid_block(header, vec![user_tx]);
        let sealed = SealedBlock::seal_slow(block);

        let result = consensus.validate_block_pre_execution(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(
                "Block must contain end-of-block system txs".to_string()
            ))
        );
    }

    #[test]
    fn test_validate_block_pre_execution_system_tx_out_of_order() {
        let consensus = TempoConsensus::new(ANDANTINO.clone());
        let chain_id = ANDANTINO.chain().id();

        let wrong_addr = Address::repeat_byte(0xFF);
        let system_tx = create_system_tx(chain_id, wrong_addr);

        let header = TestHeaderBuilder::default()
            .gas_limit(30_000_000)
            .timestamp(current_timestamp())
            .build();
        let block = create_valid_block(header, vec![system_tx]);
        let sealed = SealedBlock::seal_slow(block);

        let result = consensus.validate_block_pre_execution(&sealed);
        assert_eq!(
            result,
            Err(ConsensusError::Other(
                "Invalid end-of-block system tx order".to_string()
            ))
        );
    }
}
