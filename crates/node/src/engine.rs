use crate::{TempoExecutionData, TempoPayloadTypes};
use reth_consensus::ConsensusError;
use reth_node_api::{
    InvalidPayloadAttributesError, LazyHashedPostState, NewPayloadError, PayloadValidator,
};
use reth_primitives_traits::{AlloyBlockHeader as _, RecoveredBlock, SealedBlock};
use reth_storage_api::StateProviderFactory;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_evm::{
    consensus::TempoConsensusError,
    proof_trie::{EMPTY_PROOF_ROOT_HASH, proof_root_from_hashed_post_state},
};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{Block, TempoHeader};

/// Type encapsulating Tempo engine validation logic.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TempoEngineValidator<Provider> {
    chain_spec: Arc<TempoChainSpec>,
    provider: Provider,
}

impl<Provider> TempoEngineValidator<Provider> {
    /// Creates a new [`TempoEngineValidator`] with the given chain spec.
    pub fn new(chain_spec: Arc<TempoChainSpec>, provider: Provider) -> Self {
        Self {
            chain_spec,
            provider,
        }
    }
}

impl<Provider> PayloadValidator<TempoPayloadTypes> for TempoEngineValidator<Provider>
where
    Provider: StateProviderFactory + Clone + Send + Sync + Unpin + 'static,
{
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
        state_updates: &LazyHashedPostState,
        block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        let timestamp = block.header().timestamp();
        if self.chain_spec.is_proof_root_active_at_timestamp(timestamp) {
            let actual = block
                .header()
                .proof_root
                .ok_or_else(|| ConsensusError::from(TempoConsensusError::MissingProofRoot))?;
            let provable_accounts = self.chain_spec.provable_accounts_at_timestamp(timestamp);
            let expected = if provable_accounts.is_empty() {
                EMPTY_PROOF_ROOT_HASH
            } else {
                let state_provider = self
                    .provider
                    .state_by_block_hash(block.header().parent_hash())
                    .map_err(ConsensusError::other)?;
                proof_root_from_hashed_post_state(
                    &*state_provider,
                    state_updates.get(),
                    provable_accounts,
                )
                .map_err(ConsensusError::other)?
            };

            if actual != expected {
                return Err(TempoConsensusError::ProofRootMismatch { expected, actual }.into());
            }

            Ok(())
        } else if block.header().proof_root.is_some() {
            Err(TempoConsensusError::ProofRootBeforeActivation.into())
        } else {
            Ok(())
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
    use alloy_primitives::{B256, U256, keccak256};
    use reth_primitives_traits::Account;
    use reth_storage_api::noop::NoopProvider;
    use reth_trie_common::HashedPostState;
    use tempo_chainspec::spec::INITIAL_PROVABLE_ACCOUNTS;
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

    fn validator_with_t8_at(t8_time: u64) -> TempoEngineValidator<NoopProvider<TempoChainSpec>> {
        let chain_spec = chainspec_with_t8_at(t8_time);
        let provider = NoopProvider::new(chain_spec.clone());
        TempoEngineValidator::new(chain_spec, provider)
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

    fn lazy_hashed_state(state_updates: HashedPostState) -> LazyHashedPostState {
        LazyHashedPostState::ready(Arc::new(state_updates))
    }

    #[test]
    fn validates_proof_root_against_empty_provable_state_updates() {
        let validator = validator_with_t8_at(10);
        let state_updates = lazy_hashed_state(HashedPostState::default());

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
                    &recovered_block(9, Some(EMPTY_PROOF_ROOT_HASH)),
                )
                .is_err(),
            "pre-activation proof_root must be rejected"
        );

        validator
            .validate_block_post_execution_with_hashed_state(
                &state_updates,
                &recovered_block(10, Some(EMPTY_PROOF_ROOT_HASH)),
            )
            .expect("activation proof_root must be present");

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &state_updates,
                    &recovered_block(10, None),
                )
                .is_err(),
            "post-activation proof_root must be required"
        );
    }

    #[test]
    fn validates_proof_root_against_hashed_state_updates() {
        let chain_spec = chainspec_with_t8_at(10);
        let provider: NoopProvider<TempoChainSpec> = NoopProvider::new(chain_spec.clone());
        let validator = TempoEngineValidator::new(chain_spec, provider.clone());
        let address = INITIAL_PROVABLE_ACCOUNTS[0];
        let account = Account {
            nonce: 1,
            balance: U256::from(2),
            bytecode_hash: None,
        };
        let state_updates =
            HashedPostState::default().with_accounts([(keccak256(address), Some(account))]);
        let expected =
            proof_root_from_hashed_post_state(&provider, &state_updates, &[address]).unwrap();
        let state_updates = lazy_hashed_state(state_updates);

        validator
            .validate_block_post_execution_with_hashed_state(
                &state_updates,
                &recovered_block(10, Some(expected)),
            )
            .expect("matching proof_root is valid");

        assert!(
            validator
                .validate_block_post_execution_with_hashed_state(
                    &state_updates,
                    &recovered_block(10, Some(EMPTY_PROOF_ROOT_HASH)),
                )
                .is_err(),
            "post-activation proof_root must match the hashed-state proof root"
        );
    }
}
