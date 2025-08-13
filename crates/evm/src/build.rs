use std::sync::Arc;

use alloy_consensus::Block;
use reth_chainspec::EthereumHardforks;
use reth_evm::{
    block::{BlockExecutionError, BlockExecutorFactory},
    execute::{BlockAssembler, BlockAssemblerInput},
};
use reth_primitives_traits::{Receipt, SignedTransaction};

use crate::executor::TempoBlockExecutionCtx;

/// Block builder for Tempo
#[derive(Debug)]
pub struct TempoBlockAssembler<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
    // TODO: inner eth block assembler
}

impl<ChainSpec> TempoBlockAssembler<ChainSpec> {
    /// Creates a new [`OpBlockAssembler`].
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl<ChainSpec: EthereumHardforks> TempoBlockAssembler<ChainSpec> {
    /// Builds a block for `input` without any bounds on header `H`.
    pub fn assemble_block<
        F: for<'a> BlockExecutorFactory<
                ExecutionCtx<'a> = TempoBlockExecutionCtx,
                Transaction: SignedTransaction,
                Receipt: Receipt,
            >,
        H,
    >(
        &self,
        input: BlockAssemblerInput<'_, '_, F, H>,
    ) -> Result<Block<F::Transaction>, BlockExecutionError> {
        todo!()
    }
}

impl<ChainSpec> Clone for TempoBlockAssembler<ChainSpec> {
    fn clone(&self) -> Self {
        Self {
            chain_spec: self.chain_spec.clone(),
        }
    }
}

impl<F, ChainSpec> BlockAssembler<F> for TempoBlockAssembler<ChainSpec>
where
    ChainSpec: EthereumHardforks,
    F: for<'a> BlockExecutorFactory<
            ExecutionCtx<'a> = TempoBlockExecutionCtx,
            Transaction: SignedTransaction,
            Receipt: Receipt,
        >,
{
    type Block = Block<F::Transaction>;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F>,
    ) -> Result<Self::Block, BlockExecutionError> {
        self.assemble_block(input)
    }
}
