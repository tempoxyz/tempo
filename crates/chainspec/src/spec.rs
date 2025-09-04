use alloy_consensus::Header;
use alloy_eips::eip7840::BlobParams;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{
    BaseFeeParams, Chain, ChainHardforks, ChainSpec, DepositContract, EthChainSpec,
    EthereumHardfork, EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks,
    Head,
};
use reth_cli::chainspec::{ChainSpecParser, parse_genesis};
use reth_ethereum::evm::primitives::eth::spec::EthExecutorSpec;
use reth_network_peers::NodeRecord;
use std::sync::{Arc, LazyLock};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;

pub const TEMPO_BASE_FEE: u64 = 44;

/// Tempo chain specification parser.
#[derive(Debug, Clone, Default)]
pub struct TempoChainSpecParser;

/// Chains supported by Tempo. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["adagio"];

/// Clap value parser for [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<TempoChainSpec>> {
    Ok(match s {
        "adagio" => ADAGIO.clone(),
        "dev" => DEV.clone(),
        _ => {
            let spec: ChainSpec = parse_genesis(s)?.into();
            TempoChainSpec { inner: spec }.into()
        }
    })
}

impl ChainSpecParser for TempoChainSpecParser {
    type ChainSpec = TempoChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        chain_value_parser(s)
    }
}

pub static ADAGIO: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let _genesis: Genesis = serde_json::from_str(include_str!("./genesis/adagio.json"))
        .expect("`../res/genesis/adagio.json` must be present and deserializable");
    let hardforks: ChainHardforks = EthereumHardfork::mainnet().into();
    let mut spec = ChainSpec {
        chain: Chain::from(1234),
        hardforks,
        // TODO: update spec for testnet
        ..Default::default()
    };
    spec.genesis.config.dao_fork_support = true;
    TempoChainSpec { inner: spec }.into()
});

pub static DEV: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let mut spec = (**reth_chainspec::DEV).clone();
    let adagio = ADAGIO.clone();
    let default_7702_alloc = adagio
        .genesis()
        .alloc
        .get(&DEFAULT_7702_DELEGATE_ADDRESS)
        .expect("Could not get 7702 delegate address");

    spec.genesis
        .alloc
        .insert(DEFAULT_7702_DELEGATE_ADDRESS, default_7702_alloc.clone());

    TempoChainSpec { inner: spec }.into()
});

/// Tempo chain spec type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempoChainSpec {
    /// [`ChainSpec`].
    pub inner: ChainSpec,
}

impl TempoChainSpec {
    /// Converts the given [`Genesis`] into a [`TempoChainSpec`].
    pub fn from_genesis(genesis: Genesis) -> Self {
        let inner: ChainSpec = genesis.into();
        Self { inner }
    }
}

impl Hardforks for TempoChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        self.inner.fork_id(head)
    }

    fn latest_fork_id(&self) -> ForkId {
        self.inner.latest_fork_id()
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        self.inner.fork_filter(head)
    }
}

impl EthChainSpec for TempoChainSpec {
    type Header = Header;

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        self.inner.bootnodes()
    }

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.inner.deposit_contract()
    }

    fn display_hardforks(&self) -> Box<dyn std::fmt::Display> {
        EthChainSpec::display_hardforks(&self.inner)
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis_hash()
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.inner.get_final_paris_total_difficulty()
    }

    fn next_block_base_fee(&self, _parent: &Header, _target_timestamp: u64) -> Option<u64> {
        Some(TEMPO_BASE_FEE)
    }
}

impl EthereumHardforks for TempoChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }
}

impl EthExecutorSpec for TempoChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.inner.deposit_contract_address()
    }
}
