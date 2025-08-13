use std::sync::Arc;

use alloy_consensus::{
    Block, BlockBody, BlockHeader, EMPTY_OMMER_ROOT_HASH, Header, Transaction, TxReceipt, proofs,
};
use alloy_eips::merge::BEACON_NONCE;
use alloy_primitives::Bytes;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::{
    block::{BlockExecutionError, BlockExecutorFactory},
    execute::{BlockAssembler, BlockAssemblerInput},
};
use reth_primitives::{Receipt, TransactionSigned, logs_bloom};
use reth_primitives_traits::SignedTransaction;
use reth_provider::BlockExecutionResult;

use crate::executor::TempoBlockExecutionCtx;

/// Block builder for Tempo
#[derive(Debug, Clone)]
pub struct TempoBlockAssembler<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
    pub extra_data: Bytes,
}

impl<ChainSpec> TempoBlockAssembler<ChainSpec> {
    /// Creates a new [`OpBlockAssembler`].
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            chain_spec,
            extra_data: Default::default(),
        }
    }
}

impl<ChainSpec: EthereumHardforks> TempoBlockAssembler<ChainSpec> {
    /// Builds a block for `input` without any bounds on header `H`.
    pub fn assemble_block<
        F: for<'a> BlockExecutorFactory<
                ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>,
                Transaction: SignedTransaction,
                Receipt: reth_primitives_traits::Receipt,
            >,
        H,
    >(
        &self,
        input: BlockAssemblerInput<'_, '_, F, H>,
    ) -> Result<Block<F::Transaction>, BlockExecutionError> {
        todo!()
    }
}

impl<F, ChainSpec> BlockAssembler<F> for TempoBlockAssembler<ChainSpec>
where
    ChainSpec: EthereumHardforks,
    F: for<'a> BlockExecutorFactory<
            ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>,
            Transaction: SignedTransaction,
            Receipt: reth_primitives_traits::Receipt,
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
