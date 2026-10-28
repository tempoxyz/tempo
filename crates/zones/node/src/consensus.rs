use alloy_primitives::B256;
use reth_chainspec::EthereumHardforks;
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;
use tempo_evm::consensus::TempoConsensus;
use tempo_primitives::{Block, BlockBody, TempoHeader, TempoPrimitives, TempoReceipt};
use zone_chainspec::ZoneChainSpec;

/// Consensus validation for Zone blocks.
///
/// In addition to Tempo's rules, this pins header inputs that the Zone stateless proving function
/// derives rather than receiving in its witness.
#[derive(Debug, Clone)]
pub struct ZoneConsensus {
    inner: TempoConsensus<ZoneChainSpec>,
    chain_spec: Arc<ZoneChainSpec>,
}

impl ZoneConsensus {
    /// Creates Zone consensus validation for the given chain specification.
    pub fn new(chain_spec: Arc<ZoneChainSpec>) -> Self {
        Self {
            inner: TempoConsensus::new(chain_spec.clone()).with_allow_equal_timestamps(true),
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

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<TempoHeader>,
        parent: &SealedHeader<TempoHeader>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_header_against_parent(header, parent)?;

        if header.inner.gas_limit != parent.inner.gas_limit {
            return Err(ConsensusError::other(Error::GasLimit {
                expected: parent.inner.gas_limit,
                actual: header.inner.gas_limit,
            }));
        }

        Ok(())
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

    fn is_transient_error(&self, error: &ConsensusError) -> bool {
        self.inner.is_transient_error(error)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<Block>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        self.inner
            .validate_block_pre_execution_with_tx_root(block, transaction_root)
    }
}

impl FullConsensus<TempoPrimitives> for ZoneConsensus {
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<Block>,
        result: &BlockExecutionResult<TempoReceipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_post_execution(
            block,
            result,
            receipt_root_bloom,
            block_access_list_hash,
        )
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
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
    #[error("zone header gas limit must equal its parent's {expected}, got {actual}")]
    GasLimit { expected: u64, actual: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{EMPTY_OMMER_ROOT_HASH, Header};
    use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
    use alloy_primitives::{Bytes, b256};
    use reth_chainspec::EthChainSpec as _;
    use reth_trie_common::EMPTY_ROOT_HASH;
    use tempo_primitives::{TempoConsensusContext, ed25519::PublicKey};
    use zone_primitives::constants::zone_chain_id;

    fn fixture() -> (ZoneConsensus, SealedHeader<TempoHeader>, TempoHeader) {
        let mut genesis = crate::genesis::genesis_template().unwrap();
        genesis.config.chain_id = zone_chain_id(1_337, 1).unwrap();
        let chain_spec = Arc::new(ZoneChainSpec::from_genesis(genesis).unwrap());
        let consensus = ZoneConsensus::new(chain_spec.clone());
        let parent = SealedHeader::seal_slow(chain_spec.genesis_header().clone());
        let header = TempoHeader {
            inner: Header {
                parent_hash: parent.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                transactions_root: EMPTY_ROOT_HASH,
                withdrawals_root: Some(EMPTY_ROOT_HASH),
                number: parent.inner.number + 1,
                gas_limit: parent.inner.gas_limit,
                timestamp: parent.inner.timestamp + 1,
                base_fee_per_gas: Some(0),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::ZERO),
                requests_hash: Some(EMPTY_REQUESTS_HASH),
                ..Default::default()
            },
            ..Default::default()
        };
        (consensus, parent, header)
    }

    fn assert_zone_header_error(consensus: &ZoneConsensus, header: TempoHeader, expected: Error) {
        let header = SealedHeader::seal_slow(header);
        consensus.inner.validate_header(&header).unwrap();
        let error = consensus.validate_header(&header).unwrap_err();
        assert_eq!(error.downcast_other_ref(), Some(&expected));
    }

    #[test]
    fn rejects_header_fields_the_spf_cannot_reproduce() {
        let (consensus, _, header) = fixture();
        consensus
            .validate_header(&SealedHeader::seal_slow(header.clone()))
            .unwrap();

        assert_zone_header_error(
            &consensus,
            TempoHeader {
                consensus_context: Some(TempoConsensusContext {
                    epoch: 7,
                    view: 9,
                    parent_view: 8,
                    proposer: PublicKey::try_from(b256!(
                        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    ))
                    .unwrap(),
                }),
                ..header.clone()
            },
            Error::ConsensusContext,
        );
        assert_zone_header_error(
            &consensus,
            TempoHeader {
                inner: Header {
                    extra_data: Bytes::from_static(b"malicious"),
                    ..header.inner.clone()
                },
                ..header
            },
            Error::ExtraData,
        );

        let mix_hash = B256::repeat_byte(0x11);
        assert_zone_header_error(
            &consensus,
            TempoHeader {
                inner: Header {
                    mix_hash,
                    ..header.inner.clone()
                },
                ..header
            },
            Error::MixHash { actual: mix_hash },
        );

        let parent_beacon_block_root = Some(B256::repeat_byte(0x22));
        assert_zone_header_error(
            &consensus,
            TempoHeader {
                inner: Header {
                    parent_beacon_block_root,
                    ..header.inner.clone()
                },
                ..header
            },
            Error::ParentBeaconBlockRoot {
                expected: Some(B256::ZERO),
                actual: parent_beacon_block_root,
            },
        );
    }

    #[test]
    fn rejects_gas_limit_that_differs_from_the_parent() {
        let (consensus, parent, mut header) = fixture();
        header.inner.gas_limit += 1;
        let header = SealedHeader::seal_slow(header);

        consensus
            .inner
            .validate_header_against_parent(&header, &parent)
            .unwrap();
        let error = consensus
            .validate_header_against_parent(&header, &parent)
            .unwrap_err();
        assert_eq!(
            error.downcast_other_ref(),
            Some(&Error::GasLimit {
                expected: parent.inner.gas_limit,
                actual: parent.inner.gas_limit + 1,
            })
        );
    }
}
