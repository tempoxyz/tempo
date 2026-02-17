use crate::{
    bootnodes::{andantino_nodes, moderato_nodes, presto_nodes},
    hardfork::{TempoHardfork, TempoHardforks},
};
use alloy_eips::eip7840::BlobParams;
use alloy_evm::{
    eth::spec::EthExecutorSpec,
    revm::interpreter::gas::{
        COLD_SLOAD_COST as COLD_SLOAD, SSTORE_SET, WARM_SSTORE_RESET,
        WARM_STORAGE_READ_COST as WARM_SLOAD,
    },
};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{
    BaseFeeParams, Chain, ChainSpec, DepositContract, DisplayHardforks, EthChainSpec,
    EthereumHardfork, EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks,
    Head,
};
use reth_network_peers::NodeRecord;
use std::sync::{Arc, LazyLock};
use tempo_primitives::TempoHeader;

/// T0 base fee: 10 billion attodollars (1×10^10)
///
/// Attodollars are the atomic gas accounting units at 10^-18 USD precision.
/// Basefee is denominated in attodollars.
pub const TEMPO_T0_BASE_FEE: u64 = 10_000_000_000;

/// T1 base fee: 20 billion attodollars (2×10^10)
///
/// Attodollars are the atomic gas accounting units at 10^-18 USD precision.
/// Basefee is denominated in attodollars.
///
/// At this basefee, a standard TIP-20 transfer (~50,000 gas) costs:
/// - Gas: 50,000 × 20 billion attodollars/gas = 1 quadrillion attodollars
/// - Tokens: 1 quadrillion attodollars / 10^12 = 1,000 microdollars
/// - Economic: 1,000 microdollars = 0.001 USD = 0.1 cents
pub const TEMPO_T1_BASE_FEE: u64 = 20_000_000_000;

/// TIP-1010 general (non-payment) gas limit: 30 million gas per block.
/// Cap for non-payment transactions.
pub const TEMPO_T1_GENERAL_GAS_LIMIT: u64 = 30_000_000;

/// TIP-1010 per-transaction gas limit cap: 30 million gas.
/// Allows maximum-sized contract deployments under TIP-1000 state creation costs.
pub const TEMPO_T1_TX_GAS_LIMIT_CAP: u64 = 30_000_000;

// End-of-block system transactions
pub const SYSTEM_TX_COUNT: usize = 1;
pub const SYSTEM_TX_ADDRESSES: [Address; SYSTEM_TX_COUNT] = [Address::ZERO];

/// Gas cost for using an existing 2D nonce key (cold SLOAD + warm SSTORE reset)
pub const TEMPO_T1_EXISTING_NONCE_KEY_GAS: u64 = COLD_SLOAD + WARM_SSTORE_RESET;
/// T2 adds 2 warm SLOADs for the extended nonce key lookup
pub const TEMPO_T2_EXISTING_NONCE_KEY_GAS: u64 = TEMPO_T1_EXISTING_NONCE_KEY_GAS + 2 * WARM_SLOAD;

/// Gas cost for using a new 2D nonce key (cold SLOAD + SSTORE set for 0 -> non-zero)
pub const TEMPO_T1_NEW_NONCE_KEY_GAS: u64 = COLD_SLOAD + SSTORE_SET;
/// T2 adds 2 warm SLOADs for the extended nonce key lookup
pub const TEMPO_T2_NEW_NONCE_KEY_GAS: u64 = TEMPO_T1_NEW_NONCE_KEY_GAS + 2 * WARM_SLOAD;

/// Tempo genesis info extracted from genesis extra_fields
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoGenesisInfo {
    /// The epoch length used by consensus.
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_length: Option<u64>,
    /// Activation timestamp for T0 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t0_time: Option<u64>,
    /// Activation timestamp for T1 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t1_time: Option<u64>,
    /// Activation timestamp for T1.A hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t1a_time: Option<u64>,
    /// Activation timestamp for T1.B hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t1b_time: Option<u64>,
    /// Activation timestamp for T2 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t2_time: Option<u64>,
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

    pub fn epoch_length(&self) -> Option<u64> {
        self.epoch_length
    }

    pub fn t0_time(&self) -> Option<u64> {
        self.t0_time
    }

    pub fn t1_time(&self) -> Option<u64> {
        self.t1_time
    }

    pub fn t1a_time(&self) -> Option<u64> {
        self.t1a_time
    }

    pub fn t1b_time(&self) -> Option<u64> {
        self.t1b_time
    }

    pub fn t2_time(&self) -> Option<u64> {
        self.t2_time
    }
}

/// Tempo chain specification parser.
#[derive(Debug, Clone, Default)]
pub struct TempoChainSpecParser;

/// Chains supported by Tempo. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["mainnet", "moderato", "testnet"];

/// Clap value parser for [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
#[cfg(feature = "cli")]
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<TempoChainSpec>> {
    Ok(match s {
        "mainnet" => PRESTO.clone(),
        "testnet" => ANDANTINO.clone(),
        "moderato" => MODERATO.clone(),
        "dev" => DEV.clone(),
        _ => TempoChainSpec::from_genesis(reth_cli::chainspec::parse_genesis(s)?).into(),
    })
}

#[cfg(feature = "cli")]
impl reth_cli::chainspec::ChainSpecParser for TempoChainSpecParser {
    type ChainSpec = TempoChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        chain_value_parser(s)
    }
}

pub static ANDANTINO: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let genesis: Genesis = serde_json::from_str(include_str!("./genesis/andantino.json"))
        .expect("`./genesis/andantino.json` must be present and deserializable");
    TempoChainSpec::from_genesis(genesis)
        .with_default_follow_url("wss://rpc.testnet.tempo.xyz")
        .into()
});

pub static MODERATO: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let genesis: Genesis = serde_json::from_str(include_str!("./genesis/moderato.json"))
        .expect("`./genesis/moderato.json` must be present and deserializable");
    TempoChainSpec::from_genesis(genesis)
        .with_default_follow_url("wss://rpc.moderato.tempo.xyz")
        .into()
});

pub static PRESTO: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let genesis: Genesis = serde_json::from_str(include_str!("./genesis/presto.json"))
        .expect("`./genesis/presto.json` must be present and deserializable");
    TempoChainSpec::from_genesis(genesis)
        .with_default_follow_url("wss://rpc.presto.tempo.xyz")
        .into()
});

/// Development chainspec with funded dev accounts and activated tempo hardforks
///
/// `cargo x generate-genesis -o dev.json --accounts 10`
pub static DEV: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let genesis: Genesis = serde_json::from_str(include_str!("./genesis/dev.json"))
        .expect("`./genesis/dev.json` must be present and deserializable");
    TempoChainSpec::from_genesis(genesis).into()
});

/// Tempo chain spec type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempoChainSpec {
    /// [`ChainSpec`].
    pub inner: ChainSpec<TempoHeader>,
    pub info: TempoGenesisInfo,
    /// Default RPC URL for following this chain.
    pub default_follow_url: Option<&'static str>,
}

impl TempoChainSpec {
    /// Returns the default RPC URL for following this chain.
    pub fn default_follow_url(&self) -> Option<&'static str> {
        self.default_follow_url
    }

    /// Converts the given [`Genesis`] into a [`TempoChainSpec`].
    pub fn from_genesis(genesis: Genesis) -> Self {
        // Extract Tempo genesis info from extra_fields
        let info @ TempoGenesisInfo {
            t0_time,
            t1_time,
            t1a_time,
            t1b_time,
            t2_time,
            ..
        } = TempoGenesisInfo::extract_from(&genesis);

        // Create base chainspec from genesis (already has ordered Ethereum hardforks)
        let mut base_spec = ChainSpec::from_genesis(genesis);

        let tempo_forks = vec![
            (TempoHardfork::Genesis, Some(0)),
            (TempoHardfork::T0, t0_time),
            (TempoHardfork::T1, t1_time),
            (TempoHardfork::T1A, t1a_time),
            (TempoHardfork::T1B, t1b_time),
            (TempoHardfork::T2, t2_time),
        ]
        .into_iter()
        .filter_map(|(fork, time)| time.map(|time| (fork, ForkCondition::Timestamp(time))));
        base_spec.hardforks.extend(tempo_forks);

        Self {
            inner: base_spec.map_header(|inner| TempoHeader {
                general_gas_limit: 0,
                timestamp_millis_part: inner.timestamp % 1000,
                shared_gas_limit: 0,
                inner,
            }),
            info,
            default_follow_url: None,
        }
    }

    /// Sets the default follow URL for this chain spec.
    pub fn with_default_follow_url(mut self, url: &'static str) -> Self {
        self.default_follow_url = Some(url);
        self
    }

    /// Returns the mainnet chainspec.
    pub fn mainnet() -> Self {
        PRESTO.as_ref().clone()
    }
}

// Required by reth's e2e-test-utils for integration tests.
// The test utilities need to convert from standard ChainSpec to custom chain specs.
impl From<ChainSpec> for TempoChainSpec {
    fn from(spec: ChainSpec) -> Self {
        Self {
            inner: spec.map_header(|inner| TempoHeader {
                general_gas_limit: 0,
                timestamp_millis_part: inner.timestamp % 1000,
                inner,
                shared_gas_limit: 0,
            }),
            info: TempoGenesisInfo::default(),
            default_follow_url: None,
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

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.inner.deposit_contract()
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn display_hardforks(&self) -> Box<dyn std::fmt::Display> {
        // filter only tempo hardforks
        let tempo_forks = self.inner.hardforks.forks_iter().filter(|(fork, _)| {
            !EthereumHardfork::VARIANTS
                .iter()
                .any(|h| h.name() == (*fork).name())
        });

        Box::new(DisplayHardforks::new(tempo_forks))
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        match self.inner.chain_id() {
            4217 => Some(presto_nodes()),
            42429 => Some(andantino_nodes()),
            42431 => Some(moderato_nodes()),
            _ => self.inner.bootnodes(),
        }
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.inner.get_final_paris_total_difficulty()
    }

    fn next_block_base_fee(&self, _parent: &TempoHeader, target_timestamp: u64) -> Option<u64> {
        Some(self.tempo_hardfork_at(target_timestamp).base_fee())
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
    use reth_chainspec::{ForkCondition, Hardforks};
    use reth_cli::chainspec::ChainSpecParser as _;

    #[test]
    fn can_load_testnet() {
        let _ = super::TempoChainSpecParser::parse("testnet")
            .expect("the testnet chainspec must always be well formed");
    }

    #[test]
    fn can_load_dev() {
        let _ = super::TempoChainSpecParser::parse("dev")
            .expect("the dev chainspec must always be well formed");
    }

    #[test]
    fn test_tempo_chainspec_has_tempo_hardforks() {
        let chainspec = super::TempoChainSpecParser::parse("mainnet")
            .expect("the mainnet chainspec must always be well formed");

        // Genesis should be active at timestamp 0
        let activation = chainspec.tempo_fork_activation(TempoHardfork::Genesis);
        assert_eq!(activation, ForkCondition::Timestamp(0));

        // T0 should be active at timestamp 0
        let activation = chainspec.tempo_fork_activation(TempoHardfork::T0);
        assert_eq!(activation, ForkCondition::Timestamp(0));
    }

    #[test]
    fn test_tempo_chainspec_implements_tempo_hardforks_trait() {
        let chainspec = super::TempoChainSpecParser::parse("mainnet")
            .expect("the mainnet chainspec must always be well formed");

        // Should be able to query Tempo hardfork activation through trait
        let activation = chainspec.tempo_fork_activation(TempoHardfork::T0);
        assert_eq!(activation, ForkCondition::Timestamp(0));
    }

    #[test]
    fn test_tempo_hardforks_in_inner_hardforks() {
        let chainspec = super::TempoChainSpecParser::parse("mainnet")
            .expect("the mainnet chainspec must always be well formed");

        // Tempo hardforks should be queryable from inner.hardforks via Hardforks trait
        let activation = chainspec.fork(TempoHardfork::T0);
        assert_eq!(activation, ForkCondition::Timestamp(0));

        // Verify Genesis appears in forks iterator
        let has_genesis = chainspec
            .forks_iter()
            .any(|(fork, _)| fork.name() == "Genesis");
        assert!(has_genesis, "Genesis hardfork should be in inner.hardforks");
    }

    #[test]
    fn test_tempo_hardfork_at() {
        let mainnet_chainspec = super::TempoChainSpecParser::parse("mainnet")
            .expect("the mainnet chainspec must always be well formed");

        // Before T1 activation (1770908400 = Feb 12th 2026 16:00 CET)
        assert_eq!(mainnet_chainspec.tempo_hardfork_at(0), TempoHardfork::T0);
        assert_eq!(mainnet_chainspec.tempo_hardfork_at(1000), TempoHardfork::T0);
        assert_eq!(
            mainnet_chainspec.tempo_hardfork_at(1770908399),
            TempoHardfork::T0
        );

        // At and after T1/T1A activation (both activate at 1770908400)
        assert!(mainnet_chainspec.is_t1_active_at_timestamp(1770908400));
        assert!(mainnet_chainspec.is_t1a_active_at_timestamp(1770908400));
        assert_eq!(
            mainnet_chainspec.tempo_hardfork_at(1770908400),
            TempoHardfork::T1A
        );
        assert_eq!(
            mainnet_chainspec.tempo_hardfork_at(1770908401),
            TempoHardfork::T1A
        );

        // T2 not yet scheduled on mainnet
        assert!(!mainnet_chainspec.is_t2_active_at_timestamp(u64::MAX));
        assert_eq!(
            mainnet_chainspec.tempo_hardfork_at(u64::MAX),
            TempoHardfork::T1A
        );

        let moderato_genesis = super::TempoChainSpecParser::parse("moderato")
            .expect("the moderato chainspec must always be well formed");

        // Before T0/T1 activation (1770303600 = Feb 5th 2026 16:00 CET)
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(0),
            TempoHardfork::Genesis
        );
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(1770303599),
            TempoHardfork::Genesis
        );

        // At and after T0/T1 activation (before T1A)
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(1770303600),
            TempoHardfork::T1
        );
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(1770303601),
            TempoHardfork::T1
        );

        // Before T1A activation (1771513200 = Feb 19th 2026 16:00 CET)
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(1771513199),
            TempoHardfork::T1
        );

        // At and after T1A activation (1771513200 = Feb 19th 2026 16:00 CET)
        assert!(moderato_genesis.is_t1a_active_at_timestamp(1771513200));
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(1771513200),
            TempoHardfork::T1A
        );

        // T2 not yet scheduled on moderato
        assert!(!moderato_genesis.is_t2_active_at_timestamp(u64::MAX));
        assert_eq!(
            moderato_genesis.tempo_hardfork_at(u64::MAX),
            TempoHardfork::T1A
        );

        let testnet_chainspec = super::TempoChainSpecParser::parse("testnet")
            .expect("the mainnet chainspec must always be well formed");

        // Should always return Genesis (no T1A on testnet)
        assert_eq!(
            testnet_chainspec.tempo_hardfork_at(0),
            TempoHardfork::Genesis
        );
        assert_eq!(
            testnet_chainspec.tempo_hardfork_at(1000),
            TempoHardfork::Genesis
        );
        assert_eq!(
            testnet_chainspec.tempo_hardfork_at(u64::MAX),
            TempoHardfork::Genesis
        );

        // Dev chainspec should return T2 (all hardforks active at 0)
        let dev_chainspec = super::TempoChainSpecParser::parse("dev")
            .expect("the dev chainspec must always be well formed");
        assert_eq!(dev_chainspec.tempo_hardfork_at(0), TempoHardfork::T2);
        assert_eq!(dev_chainspec.tempo_hardfork_at(1000), TempoHardfork::T2);
    }

    #[test]
    fn test_from_genesis_with_hardforks_at_zero() {
        use alloy_genesis::Genesis;

        let genesis: Genesis = serde_json::from_str(
            r#"{
                "config": {
                    "chainId": 1234,
                    "t0Time": 0,
                    "t1Time": 0,
                    "t1aTime": 0,
                    "t1bTime": 0,
                    "t2Time": 0
                },
                "alloc": {}
            }"#,
        )
        .unwrap();

        let chainspec = super::TempoChainSpec::from_genesis(genesis);

        assert!(chainspec.is_t0_active_at_timestamp(0));
        assert!(chainspec.is_t0_active_at_timestamp(1000));
        assert!(chainspec.is_t1_active_at_timestamp(0));
        assert!(chainspec.is_t1_active_at_timestamp(1000));
        assert!(chainspec.is_t1a_active_at_timestamp(0));
        assert!(chainspec.is_t1a_active_at_timestamp(1000));
        assert!(chainspec.is_t1b_active_at_timestamp(0));
        assert!(chainspec.is_t1b_active_at_timestamp(1000));
        assert!(chainspec.is_t2_active_at_timestamp(0));
        assert!(chainspec.is_t2_active_at_timestamp(1000));

        assert_eq!(chainspec.tempo_hardfork_at(0), TempoHardfork::T2);
        assert_eq!(chainspec.tempo_hardfork_at(1000), TempoHardfork::T2);
        assert_eq!(chainspec.tempo_hardfork_at(u64::MAX), TempoHardfork::T2);
    }
}
