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
        Self { inner: EthBlockAssembler::new(chain_spec) }
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
                    extra_data,
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

        // Set extra_data on the inner assembler before building
        let mut assembler = self.inner.clone();
        assembler.extra_data = extra_data;

        // Delegate block building to the inner assembler
        let block = assembler.assemble_block(BlockAssemblerInput::<
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
