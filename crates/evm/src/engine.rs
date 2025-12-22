use crate::TempoEvmConfig;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::Address;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    FromRecoveredTx, RecoveredTx, ToTxEnv,
};
use reth_primitives_traits::{SealedBlock, SignedTransaction};
use std::sync::Arc;
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoTxEnvelope};
use tempo_revm::TempoTxEnv;

impl ConfigureEngineEvm<TempoExecutionData> for TempoEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.evm_env(&payload.block)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let TempoExecutionData {
            block,
            validator_set,
        } = payload;
        let mut context = self.context_for_block(block)?;

        context.validator_set = validator_set.clone();

        Ok(context)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let block = payload.block.clone();
        let transactions = (0..payload.block.body().transactions.len())
            .into_par_iter()
            .map(move |i| (block.clone(), i));

        Ok((transactions, RecoveredInBlock::new))
    }
}

/// A [`reth_evm::execute::ExecutableTxFor`] implementation that contains a pointer to the
/// block and the transaction index, allowing to prepare a [`TempoTxEnv`] without having to
/// clone block or transaction.
#[derive(Clone)]
struct RecoveredInBlock {
    block: Arc<SealedBlock<Block>>,
    index: usize,
    sender: Address,
}

impl RecoveredInBlock {
    fn new((block, index): (Arc<SealedBlock<Block>>, usize)) -> Result<Self, RecoveryError> {
        let sender = block.body().transactions[index].try_recover()?;
        Ok(Self {
            block,
            index,
            sender,
        })
    }
}

impl RecoveredTx<TempoTxEnvelope> for RecoveredInBlock {
    fn tx(&self) -> &TempoTxEnvelope {
        &self.block.body().transactions[self.index]
    }

    fn signer(&self) -> &alloy_primitives::Address {
        &self.sender
    }
}

impl ToTxEnv<TempoTxEnv> for RecoveredInBlock {
    fn to_tx_env(&self) -> TempoTxEnv {
        TempoTxEnv::from_recovered_tx(self.tx(), *self.signer())
    }
}
