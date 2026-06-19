use crate::{TempoExecutionData, TempoPayloadTypes};
use reth_consensus::ConsensusError;
use reth_node_api::{InvalidPayloadAttributesError, NewPayloadError, PayloadValidator};
use reth_primitives_traits::{AlloyBlockHeader as _, RecoveredBlock, SealedBlock};
use reth_trie_common::HashedPostState;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_evm::consensus::TempoConsensusError;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{Block, TempoHeader};

/// Type encapsulating Tempo engine validation logic.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TempoEngineValidator {
    chain_spec: Arc<TempoChainSpec>,
}

impl TempoEngineValidator {
    /// Creates a new [`TempoEngineValidator`] with the given chain spec.
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl PayloadValidator<TempoPayloadTypes> for TempoEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: TempoExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        let TempoExecutionData {
            block,
            block_access_list: _,
            validator_set: _,
        } = payload;
        Ok(Arc::unwrap_or_clone(block))
    }

    fn validate_block_post_execution_with_hashed_state(
        &self,
        _state_updates: &HashedPostState,
        block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        let timestamp = block.header().timestamp();
        let provable_accounts = self.chain_spec.provable_accounts_at_timestamp(timestamp);
        if !provable_accounts.is_empty() {
            return Err(ConsensusError::msg(
                "non-empty provable account whitelist requires persisted proof-trie validation",
            ));
        }

        match self
            .chain_spec
            .proof_root_for_empty_provable_whitelist_at_timestamp(timestamp)
        {
            Some(expected) => match block.header().proof_root {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => {
                    Err(TempoConsensusError::ProofRootMismatch { expected, actual }.into())
                }
                None => Err(TempoConsensusError::MissingProofRoot.into()),
            },
            None if block.header().proof_root.is_some() => {
                Err(TempoConsensusError::ProofRootBeforeActivation.into())
            }
            None => Ok(()),
        }
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Ensure that payload attributes timestamp is not in the past
        if attr.timestamp < header.timestamp() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, constants::EMPTY_ROOT_HASH};
    use alloy_genesis::Genesis;
    use alloy_primitives::B256;
    use tempo_primitives::BlockBody;

    fn chainspec_with_t8_at(t8_time: u64) -> Arc<TempoChainSpec> {
        let genesis = serde_json::json!({
            "config": {
                "chainId": 99999,
                "homesteadBlock": 0,
                "daoForkSupport": false,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "mergeNetsplitBlock": 0,
                "shanghaiTime": 0,
                "cancunTime": 0,
                "pragueTime": 0,
                "osakaTime": 0,
                "terminalTotalDifficulty": 0,
                "terminalTotalDifficultyPassed": true,
                "t0Time": 0,
                "t8Time": t8_time
            },
            "alloc": {}
        });
        let genesis: Genesis = serde_json::from_value(genesis).unwrap();
        Arc::new(TempoChainSpec::from_genesis(genesis))
    }

    fn recovered_block(timestamp: u64, proof_root: Option<B256>) -> RecoveredBlock<Block> {
        let header = TempoHeader {
            inner: Header {
                timestamp,
                ..Default::default()
            },
            proof_root,
            ..Default::default()
        };
        let block = Block {
            header,
            body: BlockBody::default(),
        };
        RecoveredBlock::new_unhashed(block, vec![])
    }

    #[test]
    fn validates_proof_root_against_empty_provable_whitelist() {
        let validator = TempoEngineValidator::new(chainspec_with_t8_at(10));
        let state_updates = HashedPostState::default();

        validator
            .validate_block_post_execution_with_hashed_state(
                &state_updates,
                &recovered_block(9, None),
            )
            .expect("pre-activation proof_root omission is valid");

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &state_updates,
                    &recovered_block(9, Some(EMPTY_ROOT_HASH)),
                )
                .is_err(),
            "pre-activation proof_root must be rejected"
        );

        validator
            .validate_block_post_execution_with_hashed_state(
                &state_updates,
                &recovered_block(10, Some(EMPTY_ROOT_HASH)),
            )
            .expect("activation proof_root must match the empty trie root");

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &state_updates,
                    &recovered_block(10, None),
                )
                .is_err(),
            "post-activation proof_root must be required"
        );

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &state_updates,
                    &recovered_block(10, Some(B256::repeat_byte(0x42))),
                )
                .is_err(),
            "post-activation proof_root must match the expected root"
        );
    }
}
