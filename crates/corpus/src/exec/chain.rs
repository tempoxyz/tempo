//! The chains the corpus captures and replays. Tempo L1 is implemented here; a zone implements
//! these traits where its EVM lives.

use crate::types::L1Reads;
use alloy_primitives::Address;
use evm2::evm::Database;
use reth_chainspec::EthChainSpec;
use reth_evm::{ConfigureEvm, execute::BlockExecutor};
use reth_primitives_traits::RecoveredBlock;
use serde::{Serialize, de::DeserializeOwned};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_evm::{ExecutorState, TempoBlockExecutor, TempoEvm, TempoEvmConfig};
use tempo_primitives::{Block, TempoReceipt, TempoTxEnvelope};

/// Block execution the corpus drives, one transaction at a time.
pub trait Evm: Send + Sync {
    /// The executor of one block.
    type Executor<'a>: BlockExecutor<Transaction = TempoTxEnvelope, Receipt = TempoReceipt, Evm = TempoEvm<'a>>
    where
        Self: 'a;

    /// The executor's block-level state between transactions, stored as each transaction's
    /// boundary.
    type Boundary: Serialize + DeserializeOwned;

    /// An executor of `block` over `db`, the state before it.
    fn executor<'a, DB: Database + 'a>(
        &'a self,
        db: DB,
        block: &'a RecoveredBlock<Block>,
    ) -> eyre::Result<Self::Executor<'a>>;

    /// The block-level state after the transactions `executor` has committed.
    fn boundary(executor: &Self::Executor<'_>) -> Self::Boundary;

    /// Restores `boundary` into a fresh executor over the matching state, to execute one
    /// transaction alone.
    fn restore(executor: &mut Self::Executor<'_>, boundary: Self::Boundary);
}

/// A chain whose blocks the corpus replays from their records alone.
pub trait Chain: Send + Sync {
    /// Executes the chain's blocks.
    type Evm: Evm;

    /// The chain's specification.
    type Spec: EthChainSpec;

    /// The chain's specification, whose chain ID, genesis and forks a corpus is pinned to.
    fn chain_spec(&self) -> &Self::Spec;

    /// The zone portal on Tempo L1 whose zone this chain is, or `None` for Tempo L1 itself.
    fn portal(&self) -> Option<Address>;

    /// Executes a block from its record, serving L1 reads only from `reads`, the ones it
    /// recorded. A read outside them fails the block. Fails if the chain reads no L1 state but
    /// `reads` is not empty.
    fn replaying(&self, reads: &L1Reads) -> eyre::Result<Self::Evm>;
}

/// A chain the corpus captures blocks of from an archive, reading L1 state from the source.
pub trait Source: Chain {
    /// Executes a block during capture.
    type Capture: Evm;

    /// Executes one block, recording the L1 reads it makes for [`Self::recorded`].
    fn capturing(&self) -> Self::Capture;

    /// Takes the L1 reads `evm` has recorded since [`Self::capturing`] created it.
    fn recorded(evm: &Self::Capture) -> L1Reads;
}

impl Evm for TempoEvmConfig {
    type Executor<'a> = TempoBlockExecutor<'a>;
    type Boundary = ExecutorState;

    fn executor<'a, DB: Database + 'a>(
        &'a self,
        db: DB,
        block: &'a RecoveredBlock<Block>,
    ) -> eyre::Result<TempoBlockExecutor<'a>> {
        Ok(self.executor_for_block(db, block.sealed_block())?)
    }

    fn boundary(executor: &TempoBlockExecutor<'_>) -> ExecutorState {
        executor.executor_state()
    }

    fn restore(executor: &mut TempoBlockExecutor<'_>, boundary: ExecutorState) {
        executor.with_executor_state(boundary);
    }
}

impl Chain for TempoEvmConfig {
    type Evm = Self;
    type Spec = TempoChainSpec;

    fn chain_spec(&self) -> &TempoChainSpec {
        Self::chain_spec(self)
    }

    fn portal(&self) -> Option<Address> {
        None
    }

    fn replaying(&self, reads: &L1Reads) -> eyre::Result<Self> {
        eyre::ensure!(reads.0.is_empty(), "Tempo L1 block records L1 reads");
        Ok(self.clone())
    }
}

impl Source for TempoEvmConfig {
    type Capture = Self;

    fn capturing(&self) -> Self {
        self.clone()
    }

    fn recorded(_: &Self) -> L1Reads {
        L1Reads::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::L1Read;
    use tempo_chainspec::spec::DEV;

    #[test]
    fn tempo_replay_rejects_l1_reads() {
        let config = TempoEvmConfig::new(DEV.clone());
        assert!(config.replaying(&L1Reads::default()).is_ok());
        let read = L1Read {
            block: 1,
            account: [1; 20],
            slot: None,
        };
        let reads = L1Reads([(read, [2; 32])].into_iter().collect());
        let err = config.replaying(&reads).unwrap_err();
        assert_eq!(err.to_string(), "Tempo L1 block records L1 reads");
    }
}
