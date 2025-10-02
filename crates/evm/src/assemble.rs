use crate::{
    TempoEvmConfig, TempoEvmFactory, block::TempoReceiptBuilder, context::TempoBlockExecutionCtx,
};
use alloy_consensus::constants::MAXIMUM_EXTRA_DATA_SIZE;
use reth_evm::{
    block::BlockExecutionError,
    eth::EthBlockExecutorFactory,
    execute::{BlockAssembler, BlockAssemblerInput},
};
use reth_evm_ethereum::EthBlockAssembler;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_consensus::{TEMPO_EXTRA_DATA_SUFFIX_LENGTH, TempoExtraData};

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
        input: BlockAssemblerInput<'_, '_, TempoEvmConfig>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx:
                TempoBlockExecutionCtx {
                    inner,
                    general_gas_limit,
                },
            parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
            ..
        } = input;

        // Delegate block building to the inner assembler
        let mut block = self.inner.assemble_block(BlockAssemblerInput::<
            EthBlockExecutorFactory<TempoReceiptBuilder, TempoChainSpec, TempoEvmFactory>,
        >::new(
            evm_env,
            inner,
            parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
        ))?;

        let suffix = TempoExtraData { general_gas_limit }.encode();

        // respect extra data produced by inner assembler and only keep its prefix that
        // fits within the maximum extra data size
        let prefix = if block.header.extra_data.len()
            <= MAXIMUM_EXTRA_DATA_SIZE - TEMPO_EXTRA_DATA_SUFFIX_LENGTH
        {
            block.header.extra_data
        } else {
            block
                .header
                .extra_data
                .slice(..MAXIMUM_EXTRA_DATA_SIZE - TEMPO_EXTRA_DATA_SUFFIX_LENGTH)
        };

        // set correct extra data
        block.header.extra_data = [prefix, suffix.into()].concat().into();

        Ok(block)
    }
}
