use crate::{
    TempoEvmConfig, TempoEvmFactory, block::TempoReceiptBuilder, context::TempoBlockExecutionCtx,
};
use alloy_evm::{block::BlockExecutionError, eth::EthBlockExecutorFactory};
use reth_evm::execute::{BlockAssembler, BlockAssemblerInput};
use reth_evm_ethereum::EthBlockAssembler;
use reth_primitives_traits::SealedHeader;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_primitives::TempoHeader;

/// Assembler for Tempo blocks.
#[derive(Debug, Clone)]
pub struct TempoBlockAssembler {
    pub(crate) inner: EthBlockAssembler<TempoChainSpec>,
}

impl TempoBlockAssembler {
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            inner: EthBlockAssembler::new(chain_spec),
        }
    }
}

impl BlockAssembler<TempoEvmConfig> for TempoBlockAssembler {
    type Block = tempo_primitives::Block;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, TempoEvmConfig, TempoHeader>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx:
                TempoBlockExecutionCtx {
                    inner,
                    general_gas_limit,
                    shared_gas_limit,
                    validator_set: _,
                    subblock_fee_recipients: _,
                },
            parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
            ..
        } = input;

        let parent = SealedHeader::new_unhashed(parent.clone().into_header().inner);

        let timestamp_millis_part = evm_env.block_env.timestamp_millis_part;

        // Delegate block building to the inner assembler
        let block = self.inner.assemble_block(BlockAssemblerInput::<
            EthBlockExecutorFactory<TempoReceiptBuilder, TempoChainSpec, TempoEvmFactory>,
        >::new(
            evm_env,
            inner,
            &parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
        ))?;

        Ok(block.map_header(|inner| TempoHeader {
            inner,
            general_gas_limit,
            timestamp_millis_part,
            shared_gas_limit,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_evm::{EvmEnv, block::BlockExecutionResult, eth::EthBlockExecutionCtx};
    use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
    use reth_chainspec::EthChainSpec;
    use reth_evm::execute::BlockAssembler;
    use reth_primitives_traits::SealedHeader;
    use reth_storage_api::noop::NoopProvider;
    use revm::{context::BlockEnv, database::BundleState};
    use std::collections::HashMap;
    use tempo_chainspec::spec::ANDANTINO;
    use tempo_primitives::{
        TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope, TempoTxType,
    };
    use tempo_revm::TempoBlockEnv;

    fn create_legacy_tx() -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn create_test_receipt(gas_used: u64) -> TempoReceipt {
        TempoReceipt {
            tx_type: TempoTxType::Legacy,
            success: true,
            cumulative_gas_used: gas_used,
            logs: vec![],
        }
    }

    #[test]
    fn test_assemble_block() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(ANDANTINO.genesis().clone()));
        let assembler = TempoBlockAssembler::new(chainspec.clone());

        let block_number = 1u64;
        let timestamp = 1000u64;
        let timestamp_millis_part = 500u64;
        let gas_limit = 30_000_000u64;
        let general_gas_limit = 10_000_000u64;
        let shared_gas_limit = 10_000_000u64;

        let evm_env = EvmEnv {
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    number: U256::from(block_number),
                    timestamp: U256::from(timestamp),
                    beneficiary: Address::repeat_byte(0x01),
                    basefee: 1,
                    gas_limit,
                    ..Default::default()
                },
                timestamp_millis_part,
            },
            ..Default::default()
        };

        let parent_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 0,
                timestamp: 0,
                gas_limit,
                ..Default::default()
            },
            general_gas_limit,
            timestamp_millis_part: 0,
            shared_gas_limit,
        };
        let parent = SealedHeader::seal_slow(parent_header);

        let execution_ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: Some(B256::ZERO),
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
            },
            general_gas_limit,
            shared_gas_limit,
            validator_set: None,
            subblock_fee_recipients: HashMap::new(),
        };

        let tx = create_legacy_tx();
        let transactions = vec![tx];

        let receipt = create_test_receipt(21000);
        let output = BlockExecutionResult {
            receipts: vec![receipt],
            requests: Default::default(),
            gas_used: 21000,
            blob_gas_used: 0,
        };

        let bundle_state = BundleState::default();
        let state_provider = NoopProvider::<TempoChainSpec, TempoPrimitives>::new(chainspec);
        let state_root = B256::ZERO;

        let input = BlockAssemblerInput::<TempoEvmConfig, TempoHeader>::new(
            evm_env,
            execution_ctx,
            &parent,
            transactions,
            &output,
            &bundle_state,
            &state_provider,
            state_root,
        );

        let block = assembler
            .assemble_block(input)
            .expect("should assemble block");

        // Verify block header fields
        assert_eq!(block.header.inner.number, block_number);
        assert_eq!(block.header.inner.timestamp, timestamp);
        assert_eq!(block.header.inner.gas_used, 21000);
        assert_eq!(block.header.inner.gas_limit, gas_limit);
        assert_eq!(block.header.inner.parent_hash, parent.hash());
        assert_eq!(block.header.inner.beneficiary, Address::repeat_byte(0x01));
        assert_eq!(block.header.inner.state_root, state_root);

        // Verify Tempo-specific header fields
        assert_eq!(block.header.general_gas_limit, general_gas_limit);
        assert_eq!(block.header.shared_gas_limit, shared_gas_limit);
        assert_eq!(block.header.timestamp_millis_part, timestamp_millis_part);

        // Verify body
        assert_eq!(block.body.transactions.len(), 1);
    }
}
