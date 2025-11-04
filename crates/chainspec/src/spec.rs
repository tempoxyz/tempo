use crate::{
    bootnodes::andantino_nodes,
    hardfork::{TempoHardfork, TempoHardforks},
};
use alloy_eips::eip7840::BlobParams;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{
    BaseFeeParams, Chain, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork,
    EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_cli::chainspec::{ChainSpecParser, parse_genesis};
use reth_ethereum::evm::primitives::eth::spec::EthExecutorSpec;
use reth_network_peers::NodeRecord;
use std::sync::{Arc, LazyLock};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
use tempo_primitives::TempoHeader;

pub const TEMPO_BASE_FEE: u64 = 44;

/// Tempo genesis info extracted from genesis extra_fields
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TempoGenesisInfo {
    /// Timestamp of Adagio hardfork activation
    #[serde(skip_serializing_if = "Option::is_none")]
    adagio_time: Option<u64>,
}

impl TempoGenesisInfo {
    /// Extract Tempo genesis info from genesis extra_fields
    fn extract_from(genesis: &Genesis) -> Self {
        genesis
            .config
            .extra_fields
            .deserialize_as::<Self>()
            .unwrap_or_default()
    }
}

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
        _ => TempoChainSpec::from_genesis(parse_genesis(s)?).into(),
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
    let genesis: Genesis = serde_json::from_str(include_str!("./genesis/adagio.json"))
        .expect("`./genesis/adagio.json` must be present and deserializable");
    TempoChainSpec::from_genesis(genesis).into()
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

    TempoChainSpec {
        inner: spec.map_header(|inner| TempoHeader {
            general_gas_limit: 0,
            timestamp_millis_part: 0,
            shared_gas_limit: 0,
            inner,
        }),
    }
    .into()
});

/// Tempo chain spec type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempoChainSpec {
    /// [`ChainSpec`].
    pub inner: ChainSpec<TempoHeader>,
}

impl TempoChainSpec {
    /// Converts the given [`Genesis`] into a [`TempoChainSpec`].
    pub fn from_genesis(genesis: Genesis) -> Self {
        // Extract Tempo genesis info from extra_fields
        let tempo_genesis_info = TempoGenesisInfo::extract_from(&genesis);

        // Create base chainspec from genesis (already has ordered Ethereum hardforks)
        let mut base_spec = ChainSpec::from_genesis(genesis);

        // Collect Tempo hardforks to insert
        let tempo_forks: Vec<_> = [tempo_genesis_info
            .adagio_time
            .map(|time| (TempoHardfork::Adagio, ForkCondition::Timestamp(time)))]
        .into_iter()
        .flatten()
        .collect();

        base_spec.hardforks.extend(tempo_forks);

        Self {
            inner: base_spec.map_header(|inner| TempoHeader {
                general_gas_limit: 0,
                timestamp_millis_part: inner.timestamp * 1000,
                shared_gas_limit: 0,
                inner,
            }),
        }
    }
}

// Required by reth's e2e-test-utils for integration tests.
// The test utilities need to convert from standard ChainSpec to custom chain specs.
impl From<ChainSpec> for TempoChainSpec {
    fn from(spec: ChainSpec) -> Self {
        Self {
            inner: spec.map_header(|inner| TempoHeader {
                general_gas_limit: 0,
                timestamp_millis_part: inner.timestamp * 1000,
                inner,
                shared_gas_limit: 0,
            }),
        }
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
    type Header = TempoHeader;

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        match self.inner.chain_id() {
            42429 => Some(andantino_nodes()),
            _ => self.inner.bootnodes(),
        }
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

    fn next_block_base_fee(&self, _parent: &TempoHeader, _target_timestamp: u64) -> Option<u64> {
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

impl TempoHardforks for TempoChainSpec {
    fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition {
        self.fork(fork)
    }
}

#[cfg(test)]
mod tests {
    use crate::hardfork::{TempoHardfork, TempoHardforks};
    use reth_chainspec::{EthereumHardfork, ForkCondition, Hardforks};
    use reth_cli::chainspec::ChainSpecParser as _;
    use serde_json::json;

    #[test]
    fn can_load_adagio() {
        let _ = super::TempoChainSpecParser::parse("adagio")
            .expect("the adagio chainspec must always be well formed");
    }

    #[test]
    fn can_load_dev() {
        let _ = super::TempoChainSpecParser::parse("dev")
            .expect("the dev chainspec must always be well formed");
    }

    #[test]
    fn test_tempo_chainspec_has_tempo_hardforks() {
        let chainspec = super::TempoChainSpecParser::parse("adagio")
            .expect("the adagio chainspec must always be well formed");

        // Adagio should be active at genesis (timestamp 0)
        assert!(chainspec.is_adagio_active_at_timestamp(0));
    }

    #[test]
    fn test_tempo_chainspec_implements_tempo_hardforks_trait() {
        let chainspec = super::TempoChainSpecParser::parse("adagio")
            .expect("the adagio chainspec must always be well formed");

        // Should be able to query Tempo hardfork activation through trait
        let activation = chainspec.tempo_fork_activation(TempoHardfork::Adagio);
        assert_eq!(activation, ForkCondition::Timestamp(0));

        // Should be able to use convenience method through trait
        assert!(chainspec.is_adagio_active_at_timestamp(0));
        assert!(chainspec.is_adagio_active_at_timestamp(1000));
    }

    #[test]
    fn test_tempo_hardforks_in_inner_hardforks() {
        let chainspec = super::TempoChainSpecParser::parse("adagio")
            .expect("the adagio chainspec must always be well formed");

        // Tempo hardforks should be queryable from inner.hardforks via Hardforks trait
        let activation = chainspec.fork(TempoHardfork::Adagio);
        assert_eq!(activation, ForkCondition::Timestamp(0));

        // Verify Adagio appears in forks iterator
        let has_adagio = chainspec
            .forks_iter()
            .any(|(fork, _)| fork.name() == "Adagio");
        assert!(has_adagio, "Adagio hardfork should be in inner.hardforks");
    }

    #[test]
    fn test_parse_tempo_hardforks_from_genesis_extra_fields() {
        // Create a genesis with Tempo hardfork timestamps as extra fields in config
        // (non-standard fields automatically go into extra_fields)
        let genesis_json = json!({
            "config": {
                "chainId": 1337,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "mergeNetsplitBlock": 0,
                "terminalTotalDifficulty": 0,
                "terminalTotalDifficultyPassed": true,
                "shanghaiTime": 0,
                "cancunTime": 0,
                "adagioTime": 1000
            },
            "alloc": {}
        });

        let genesis: alloy_genesis::Genesis =
            serde_json::from_value(genesis_json).expect("genesis should be valid");

        let chainspec = super::TempoChainSpec::from_genesis(genesis);

        // Adagio should be activated at timestamp 1000, not 0
        let activation = chainspec.fork(TempoHardfork::Adagio);
        assert_eq!(
            activation,
            ForkCondition::Timestamp(1000),
            "Adagio should be activated at the parsed timestamp from extra_fields"
        );

        // Should not be active at timestamp 0
        assert!(
            !chainspec.is_adagio_active_at_timestamp(0),
            "Adagio should not be active before its activation timestamp"
        );

        // Should be active at timestamp 1000
        assert!(
            chainspec.is_adagio_active_at_timestamp(1000),
            "Adagio should be active at its activation timestamp"
        );

        // Should be active after timestamp 1000
        assert!(
            chainspec.is_adagio_active_at_timestamp(2000),
            "Adagio should be active after its activation timestamp"
        );
    }

    #[test]
    fn test_tempo_hardforks_are_ordered_correctly() {
        // Create a genesis where Adagio should appear between Shanghai (time 0) and Cancun (time 2000)
        let genesis_json = json!({
            "config": {
                "chainId": 1337,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "mergeNetsplitBlock": 0,
                "terminalTotalDifficulty": 0,
                "terminalTotalDifficultyPassed": true,
                "shanghaiTime": 0,
                "cancunTime": 2000,
                "adagioTime": 1000
            },
            "alloc": {}
        });

        let genesis: alloy_genesis::Genesis =
            serde_json::from_value(genesis_json).expect("genesis should be valid");

        let chainspec = super::TempoChainSpec::from_genesis(genesis);

        // Collect forks in order
        let forks: Vec<_> = chainspec.inner.hardforks.forks_iter().collect();

        // Find positions of Shanghai, Adagio, and Cancun
        let shanghai_pos = forks
            .iter()
            .position(|(f, _)| f.name() == EthereumHardfork::Shanghai.name());
        let adagio_pos = forks
            .iter()
            .position(|(f, _)| f.name() == TempoHardfork::Adagio.name());
        let cancun_pos = forks
            .iter()
            .position(|(f, _)| f.name() == EthereumHardfork::Cancun.name());

        assert!(shanghai_pos.is_some(), "Shanghai should be present");
        assert!(adagio_pos.is_some(), "Adagio should be present");
        assert!(cancun_pos.is_some(), "Cancun should be present");

        // Verify ordering: Shanghai (0) < Adagio (1000) < Cancun (2000)
        assert!(
            shanghai_pos.unwrap() < adagio_pos.unwrap(),
            "Shanghai (time 0) should come before Adagio (time 1000), but got positions {} and {}",
            shanghai_pos.unwrap(),
            adagio_pos.unwrap()
        );
        assert!(
            adagio_pos.unwrap() < cancun_pos.unwrap(),
            "Adagio (time 1000) should come before Cancun (time 2000), but got positions {} and {}",
            adagio_pos.unwrap(),
            cancun_pos.unwrap()
        );
    }
}
