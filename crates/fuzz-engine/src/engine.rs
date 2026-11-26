//! What a harness executes blocks with: Tempo L1's EVM and consensus, or those of a chain built on
//! Tempo's EVM, such as a zone. [`run`](crate::run) takes any [`Engine`], so a harness for such a
//! chain shares the input and outcome types, the execution loop and the invariants.

use std::sync::{Arc, LazyLock};

use alloy_consensus::transaction::Recovered;
use alloy_primitives::Address;
use evm2::evm::Cache;
use reth_consensus::{Consensus, HeaderValidator};
use reth_evm::{BlockExecutionError, BlockExecutorFactory, ConfigureEvm};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork, spec::TempoConsensusSpec};
use tempo_contracts::precompiles::{STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv, consensus::TempoConsensus};
use tempo_fuzz_types::{ChainSpecInput, HarnessInputKind};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope};

use crate::{Rejection, chain, state};

/// The dev genesis allocation, seeded once per process.
static GENESIS: LazyLock<Cache> =
    LazyLock::new(|| state::genesis_cache(&tempo_chainspec::spec::DEV.inner.genesis));

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
pub struct Chain<E: Engine + ?Sized> {
    /// The chain spec headers are built from.
    pub spec: Arc<E::ChainSpec>,
    /// The EVM configuration blocks execute with.
    pub evm_config: E::EvmConfig,
    /// The consensus rules blocks are validated by.
    pub consensus: E::Consensus,
}

/// A chain built on Tempo's EVM, as the harness executes it.
pub trait Engine {
    /// The chain's spec.
    type ChainSpec: TempoConsensusSpec;
    /// The chain's EVM configuration.
    type EvmConfig: EvmConfig;
    /// The chain's consensus rules.
    type Consensus: BlockConsensus;

    /// The implementation the harness's capabilities name.
    const IMPLEMENTATION: &'static str;
    /// The hardforks the chain's blocks execute at, in order.
    const HARDFORKS: &'static [TempoHardfork];
    /// The input modes the harness executes.
    const INPUTS: &'static [HarnessInputKind];
    /// The fee manager whose fee AMM is checked, if the chain runs one.
    const FEE_AMM: Option<Address>;
    /// The stablecoin DEX, if the chain runs one.
    const DEX: Option<Address>;

    /// The chain `input` describes, or why it is not executable.
    fn chain(&self, input: &ChainSpecInput) -> Result<Chain<Self>, Rejection>;

    /// The state a [`tempo_fuzz_types::PreState::Genesis`] pre-state starts from.
    fn genesis(&self) -> &Cache;

    /// The account the view call `input` to `target` runs as: on a chain that answers an
    /// account-scoped view only to the account it reads, that account. `Address::ZERO` by default.
    fn view_caller(&self, _target: Address, _input: &[u8]) -> Address {
        Address::ZERO
    }

    /// Transactions that open a block (header built by the harness) before the input's, built
    /// against the state after pre-execution changes: None by default, `advanceTempo` on zones.
    fn open_block(
        &self,
        _evm: &mut TempoEvm<'_>,
        _header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        Ok(Vec::new())
    }

    /// Transactions that close a block (header built by the harness) after the input's, built
    /// against the state they leave: None by default, `finalizeWithdrawalBatch` on zones.
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

impl Engine for Tempo {
    type ChainSpec = TempoChainSpec;
    type EvmConfig = TempoEvmConfig;
    type Consensus = TempoConsensus;

    const IMPLEMENTATION: &'static str = "tempo";
    const HARDFORKS: &'static [TempoHardfork] = TempoHardfork::VARIANTS;
    const INPUTS: &'static [HarnessInputKind] = &[
        HarnessInputKind::Transaction,
        HarnessInputKind::State,
        HarnessInputKind::Blockchain,
    ];
    const FEE_AMM: Option<Address> = Some(TIP_FEE_MANAGER_ADDRESS);
    const DEX: Option<Address> = Some(STABLECOIN_DEX_ADDRESS);

    fn chain(&self, input: &ChainSpecInput) -> Result<Chain<Self>, Rejection> {
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
