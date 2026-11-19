//! What a harness executes blocks with: Tempo L1's EVM and consensus, or those of a chain built on
//! Tempo's EVM, such as a zone. [`execute::run`](crate::run) takes any [`Engine`], so a harness
//! for such a chain shares the input and outcome types, the execution loop and the invariants.

use std::sync::{Arc, LazyLock};

use alloy_consensus::transaction::Recovered;
use alloy_primitives::Address;
use evm2::evm::Cache;
use reth_consensus::{Consensus, HeaderValidator};
use reth_evm::{BlockExecutionError, BlockExecutorFactory, ConfigureEvm};
use tempo_chainspec::{TempoChainSpec, spec::TempoConsensusSpec};
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv, consensus::TempoConsensus};
use tempo_fuzz_types::{ChainSpecInput, ErrorClass};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope};

use crate::{chain, state};

/// An EVM configuration whose blocks execute on Tempo's EVM, as Tempo L1's and a zone's do.
pub trait EvmConfig:
    ConfigureEvm<Primitives = TempoPrimitives, BlockExecutorFactory = Self>
    + for<'a> BlockExecutorFactory<
        Evm<'a> = TempoEvm<'a>,
        EvmEnv = TempoEvmEnv,
        Transaction = TempoTxEnvelope,
        Receipt = TempoReceipt,
    >
{
}

impl<T> EvmConfig for T where
    T: ConfigureEvm<Primitives = TempoPrimitives, BlockExecutorFactory = Self>
        + for<'a> BlockExecutorFactory<
            Evm<'a> = TempoEvm<'a>,
            EvmEnv = TempoEvmEnv,
            Transaction = TempoTxEnvelope,
            Receipt = TempoReceipt,
        >
{
}

/// The rules a chain's blocks are validated by before they execute.
pub trait BlockConsensus: HeaderValidator<TempoHeader> + Consensus<Block> {}

impl<T: HeaderValidator<TempoHeader> + Consensus<Block>> BlockConsensus for T {}

/// A chain an input describes, ready to execute blocks.
pub struct Chain<S, C, K> {
    /// The chain spec headers are built from: a context header takes its hardfork activations and
    /// gas limits from it.
    pub spec: Arc<S>,
    /// The EVM configuration blocks execute with.
    pub evm_config: C,
    /// The consensus rules blocks are validated by.
    pub consensus: K,
}

/// The chain `E` executes.
pub type ChainOf<E> =
    Chain<<E as Engine>::ChainSpec, <E as Engine>::EvmConfig, <E as Engine>::Consensus>;

/// A chain built on Tempo's EVM, as the harness executes it.
pub trait Engine {
    /// The chain's spec.
    type ChainSpec: TempoConsensusSpec;
    /// The chain's EVM configuration.
    type EvmConfig: EvmConfig;
    /// The chain's consensus rules.
    type Consensus: BlockConsensus;

    /// The chain `input` describes, or the [`ErrorClass`] it is not executable for.
    fn chain(&self, input: &ChainSpecInput) -> Result<ChainOf<Self>, ErrorClass>;

    /// The state a [`tempo_fuzz_types::PreState::Genesis`] pre-state starts from.
    fn genesis(&self) -> &Cache;

    /// Whether the chain runs the protocol contract at `contract`, so its invariants apply. Every
    /// one by default; a zone runs no stablecoin DEX.
    fn runs(&self, _contract: &Address) -> bool {
        true
    }

    /// Transactions that open each block before the input's, built against the state after the
    /// block's pre-execution changes: a zone's `advanceTempo`. None by default.
    ///
    /// They execute like the input's, with receipts and invariant checks, but are not part of the
    /// block's body: a header the harness builds commits only to the input's transactions.
    fn open_block(
        &self,
        _evm: &mut TempoEvm<'_>,
        _header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        Ok(Vec::new())
    }

    /// Transactions that close each block after the input's, built against the state they leave:
    /// a zone's `finalizeWithdrawalBatch`. None by default, and like [`Self::open_block`]'s, not
    /// part of the block's body.
    fn close_block(
        &self,
        _evm: &mut TempoEvm<'_>,
        _header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        Ok(Vec::new())
    }
}

/// Tempo L1: the dev chain spec with the input's chain ID and hardforks, Tempo's EVM and consensus.
#[derive(Debug, Clone, Copy, Default)]
pub struct Tempo;

/// The dev genesis allocation, seeded once per process: seeding analyses and hashes every genesis
/// contract, which costs more than executing a transfer.
static GENESIS: LazyLock<Cache> =
    LazyLock::new(|| state::genesis(&tempo_chainspec::spec::DEV.inner.genesis));

impl Engine for Tempo {
    type ChainSpec = TempoChainSpec;
    type EvmConfig = TempoEvmConfig;
    type Consensus = TempoConsensus;

    fn chain(
        &self,
        input: &ChainSpecInput,
    ) -> Result<Chain<TempoChainSpec, TempoEvmConfig, TempoConsensus>, ErrorClass> {
        let spec = Arc::new(chain::chain_spec(input)?);
        Ok(Chain {
            evm_config: TempoEvmConfig::new(Arc::clone(&spec)),
            consensus: TempoConsensus::new(Arc::clone(&spec)),
            spec,
        })
    }

    fn genesis(&self) -> &Cache {
        &GENESIS
    }
}
