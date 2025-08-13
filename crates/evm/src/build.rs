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
        let BlockAssemblerInput {
            evm_env,
            execution_ctx: ctx,
            parent,
            transactions,
            output:
                BlockExecutionResult {
                    receipts,
                    requests,
                    gas_used,
                },
            state_root,
            ..
        } = input;

        let timestamp = evm_env.block_env.timestamp.saturating_to();
        let transactions_root = proofs::calculate_transaction_root(&transactions);

        // TODO: receipts root

        let logs_bloom = logs_bloom(receipts.iter().flat_map(|r| r.logs()));
        let withdrawals = self
            .chain_spec
            .is_shanghai_active_at_timestamp(timestamp)
            .then(|| ctx.withdrawals.map(|w| w.into_owned()).unwrap_or_default());

        let withdrawals_root = withdrawals
            .as_deref()
            .map(|w| proofs::calculate_withdrawals_root(w));
        let requests_hash = self
            .chain_spec
            .is_prague_active_at_timestamp(timestamp)
            .then(|| requests.requests_hash());

        // let mut excess_blob_gas = None;
        // let mut blob_gas_used = None;

        // // only determine cancun fields when active
        // if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
        //     blob_gas_used = Some(
        //         transactions
        //             .iter()
        //             .map(|tx| tx.blob_gas_used().unwrap_or_default())
        //             .sum(),
        //     );
        //     excess_blob_gas = if self
        //         .chain_spec
        //         .is_cancun_active_at_timestamp(parent.timestamp)
        //     {
        //         parent.maybe_next_block_excess_blob_gas(
        //             self.chain_spec.blob_params_at_timestamp(timestamp),
        //         )
        //     } else {
        //         // for the first post-fork block, both parent.blob_gas_used and
        //         // parent.excess_blob_gas are evaluated as 0
        //         Some(alloy_eips::eip7840::BlobParams::cancun().next_block_excess_blob_gas(0, 0))
        //     };
        // }

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
