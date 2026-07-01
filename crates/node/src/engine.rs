use crate::{TempoExecutionData, TempoPayloadTypes};
use alloy_consensus::constants::EMPTY_ROOT_HASH;
use alloy_primitives::B256;
use reth_consensus::ConsensusError;
use reth_node_api::{
    AuxiliaryStateRoot, InvalidPayloadAttributesError, NewPayloadError, PayloadValidator,
};
use reth_primitives_traits::{AlloyBlockHeader as _, RecoveredBlock, SealedBlock};
use reth_revm::db::states::BundleState;
use reth_trie_common::HashedPostState;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_evm::{consensus::TempoConsensusError, proof_trie::proof_hashed_state_from_bundle_state};
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
        Ok(block.into_sealed_block())
    }

    fn validate_block_post_execution_with_hashed_state<'a>(
        &self,
        _state_updates: &dyn FnOnce() -> &'a HashedPostState,
        block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        let timestamp = block.header().timestamp();
        if self.chain_spec.is_proof_root_active_at_timestamp(timestamp) {
            block
                .header()
                .proof_root
                .ok_or_else(|| TempoConsensusError::MissingProofRoot.into())
                .map(|_| ())
        } else if block.header().proof_root.is_some() {
            Err(TempoConsensusError::ProofRootBeforeActivation.into())
        } else {
            Ok(())
        }
    }

    fn auxiliary_state_root(
        &self,
        parent_header: &TempoHeader,
        block: &RecoveredBlock<Self::Block>,
        bundle_state: &BundleState,
    ) -> Result<Option<AuxiliaryStateRoot>, ConsensusError> {
        let timestamp = block.header().timestamp();
        if !self.chain_spec.is_proof_root_active_at_timestamp(timestamp) {
            if block.header().proof_root.is_some() {
                return Err(TempoConsensusError::ProofRootBeforeActivation.into());
            }
            return Ok(None);
        }

        let expected_root = block
            .header()
            .proof_root
            .ok_or(TempoConsensusError::MissingProofRoot)?;
        let provable_accounts = self.chain_spec.provable_accounts_at_timestamp(timestamp);
        let state_updates = proof_hashed_state_from_bundle_state(bundle_state, provable_accounts);
        let parent_root = parent_header.proof_root.unwrap_or(EMPTY_ROOT_HASH);

        Ok(Some(AuxiliaryStateRoot {
            parent_root,
            expected_root,
            state_updates,
            full_state_accounts: Some(provable_accounts.to_vec()),
            retain_trie_data: true,
        }))
    }

    fn validate_auxiliary_state_root(
        &self,
        actual: B256,
        expected: B256,
        _block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        if actual == expected {
            Ok(())
        } else {
            Err(TempoConsensusError::ProofRootMismatch { expected, actual }.into())
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
    use alloy_consensus::Header;
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
    fn validates_proof_root_against_empty_provable_state_updates() {
        let validator = TempoEngineValidator::new(chainspec_with_t8_at(10));
        let state_updates = HashedPostState::default();

        validator
            .validate_block_post_execution_with_hashed_state(
                &|| &state_updates,
                &recovered_block(9, None),
            )
            .expect("pre-activation proof_root omission is valid");

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &|| &state_updates,
                    &recovered_block(9, Some(EMPTY_ROOT_HASH)),
                )
                .is_err(),
            "pre-activation proof_root must be rejected"
        );

        validator
            .validate_block_post_execution_with_hashed_state(
                &|| &state_updates,
                &recovered_block(10, Some(EMPTY_ROOT_HASH)),
            )
            .expect("activation proof_root must be present");

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &|| &state_updates,
                    &recovered_block(10, None),
                )
                .is_err(),
            "post-activation proof_root must be required"
        );

        let parent = recovered_block(9, None);
        let block = recovered_block(10, Some(EMPTY_ROOT_HASH));
        let auxiliary = validator
            .auxiliary_state_root(parent.header(), &block, &BundleState::default())
            .expect("auxiliary proof root input is valid")
            .expect("proof root is active");
        assert_eq!(auxiliary.parent_root, EMPTY_ROOT_HASH);
        assert_eq!(auxiliary.expected_root, EMPTY_ROOT_HASH);
        assert!(auxiliary.state_updates.is_empty());
        assert!(auxiliary.retain_trie_data);

        assert!(
            validator
                .validate_auxiliary_state_root(B256::repeat_byte(0x42), EMPTY_ROOT_HASH, &block,)
                .is_err(),
            "post-activation proof_root must match the computed proof root"
        );
    }
}
