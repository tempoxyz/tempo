pub use crate::constants::gas::*;

use crate::{
    bootnodes::{moderato_nodes, presto_nodes},
    hardfork::{TempoHardfork, TempoHardforks},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_eips::eip7840::BlobParams;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use once_cell as _;
#[cfg(not(feature = "std"))]
use once_cell::sync::Lazy as LazyLock;
use reth_chainspec::{
    BaseFeeParams, Chain, ChainSpec, DepositContract, DisplayHardforks, EthChainSpec,
    EthereumHardfork, EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks,
    Head,
};
use reth_network_peers::NodeRecord;
#[cfg(feature = "std")]
use std::sync::LazyLock;
use tempo_primitives::TempoHeader;

// End-of-block system transactions
pub const SYSTEM_TX_COUNT: usize = 1;
pub const SYSTEM_TX_ADDRESSES: [Address; SYSTEM_TX_COUNT] = [Address::ZERO];

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
    /// Activation timestamp for T1.C hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t1c_time: Option<u64>,
    /// Activation timestamp for T2 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t2_time: Option<u64>,
    /// Activation timestamp for T3 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t3_time: Option<u64>,
    /// Activation timestamp for T4 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t4_time: Option<u64>,
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

    /// Returns the activation timestamp for a given hardfork, or `None` if not scheduled.
    pub fn fork_time(&self, fork: TempoHardfork) -> Option<u64> {
        match fork {
            TempoHardfork::Genesis => Some(0),
            TempoHardfork::T0 => self.t0_time,
            TempoHardfork::T1 => self.t1_time,
            TempoHardfork::T1A => self.t1a_time,
            TempoHardfork::T1B => self.t1b_time,
            TempoHardfork::T1C => self.t1c_time,
            TempoHardfork::T2 => self.t2_time,
            TempoHardfork::T3 => self.t3_time,
            TempoHardfork::T4 => self.t4_time,
        }
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
        "testnet" | "moderato" => MODERATO.clone(),
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

/// Resolve a [`TempoChainSpec`] from a chain id.
///
/// Returns `None` for unknown chain ids.
pub fn chainspec_from_chain_id(chain_id: u64) -> Option<Arc<TempoChainSpec>> {
    match chain_id {
        4217 => Some(PRESTO.clone()),
        42431 => Some(MODERATO.clone()),
        _ => None,
    }
}

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
/// `cargo x generate-genesis -o dev.json --accounts 10 --no-dkg-in-genesis`
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
        let info = TempoGenesisInfo::extract_from(&genesis);

        // Create base chainspec from genesis (already has ordered Ethereum hardforks)
        let mut base_spec = ChainSpec::from_genesis(genesis);

        let tempo_forks = TempoHardfork::VARIANTS.iter().filter_map(|&fork| {
            info.fork_time(fork)
                .map(|time| (fork, ForkCondition::Timestamp(time)))
        });
        base_spec.hardforks.extend(tempo_forks);

        Self {
            inner: base_spec.map_header(|inner| TempoHeader {
                general_gas_limit: 0,
                timestamp_millis_part: inner.timestamp % 1000,
                shared_gas_limit: 0,
                consensus_context: None,
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

    /// Returns the moderato chainspec.
    pub fn moderato() -> Self {
        MODERATO.as_ref().clone()
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
                shared_gas_limit: 0,
                consensus_context: None,
                inner,
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

    fn display_hardforks(&self) -> Box<dyn core::fmt::Display> {
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
    fn test_from_genesis_with_hardforks_at_zero() {
        use alloy_genesis::Genesis;

        // Build genesis config with every post-Genesis fork at timestamp 0
        let mut config = serde_json::Map::new();
        config.insert("chainId".into(), 1234.into());
        for &fork in TempoHardfork::VARIANTS {
            if fork != TempoHardfork::Genesis {
                let key = format!("{}Time", fork.name().to_lowercase());
                config.insert(key, 0.into());
            }
        }
        let json = serde_json::json!({ "config": config, "alloc": {} });
        let genesis: Genesis = serde_json::from_value(json).unwrap();
        let chainspec = super::TempoChainSpec::from_genesis(genesis);

        // Every fork should be active at any timestamp
        for &fork in TempoHardfork::VARIANTS {
            assert!(
                chainspec.tempo_fork_activation(fork).active_at_timestamp(0),
                "{fork:?} should be active at timestamp 0"
            );
            assert!(
                chainspec
                    .tempo_fork_activation(fork)
                    .active_at_timestamp(1000),
                "{fork:?} should be active at timestamp 1000"
            );
        }

        // tempo_hardfork_at should return the latest fork
        let latest = *TempoHardfork::VARIANTS.last().unwrap();
        assert_eq!(chainspec.tempo_hardfork_at(0), latest);
        assert_eq!(chainspec.tempo_hardfork_at(1000), latest);
        assert_eq!(chainspec.tempo_hardfork_at(u64::MAX), latest);
    }

    mod tempo_hardfork_at {
        use super::*;

        #[test]
        fn mainnet() {
            let cs = super::super::TempoChainSpecParser::parse("mainnet")
                .expect("the mainnet chainspec must always be well formed");

            // Before T1 activation (1770908400 = Feb 12th 2026 16:00 CET)
            assert_eq!(cs.tempo_hardfork_at(0), TempoHardfork::T0);
            assert_eq!(cs.tempo_hardfork_at(1000), TempoHardfork::T0);
            assert_eq!(cs.tempo_hardfork_at(1770908399), TempoHardfork::T0);

            // At and after T1/T1A activation (both activate at 1770908400)
            assert!(cs.is_t1_active_at_timestamp(1770908400));
            assert!(cs.is_t1a_active_at_timestamp(1770908400));
            assert_eq!(cs.tempo_hardfork_at(1770908400), TempoHardfork::T1A);
            assert_eq!(cs.tempo_hardfork_at(1770908401), TempoHardfork::T1A);

            // Before T1B activation (1771858800 = Feb 23rd 2026 16:00 CET)
            assert!(!cs.is_t1b_active_at_timestamp(1771858799));
            assert_eq!(cs.tempo_hardfork_at(1771858799), TempoHardfork::T1A);

            // At and after T1B activation
            assert!(cs.is_t1b_active_at_timestamp(1771858800));
            assert_eq!(cs.tempo_hardfork_at(1771858800), TempoHardfork::T1B);

            // Before T1C activation (1773327600 = Mar 12th 2026 16:00 CET)
            assert!(!cs.is_t1c_active_at_timestamp(1773327599));
            assert_eq!(cs.tempo_hardfork_at(1773327599), TempoHardfork::T1B);

            // At and after T1C activation
            assert!(cs.is_t1c_active_at_timestamp(1773327600));
            assert_eq!(cs.tempo_hardfork_at(1773327600), TempoHardfork::T1C);

            // Before T2 activation (1774965600 = Mar 31st 2026 16:00 CEST)
            assert!(!cs.is_t2_active_at_timestamp(1774965599));
            assert_eq!(cs.tempo_hardfork_at(1774965599), TempoHardfork::T1C);

            // At and after T2 activation
            assert!(cs.is_t2_active_at_timestamp(1774965600));
            assert_eq!(cs.tempo_hardfork_at(1774965600), TempoHardfork::T2);

            // Before T3 activation (1777298400 = Apr 27th 2026 16:00 CEST)
            assert!(!cs.is_t3_active_at_timestamp(1777298399));
            assert_eq!(cs.tempo_hardfork_at(1777298399), TempoHardfork::T2);

            // At and after T3 activation
            assert!(cs.is_t3_active_at_timestamp(1777298400));
            assert_eq!(cs.tempo_hardfork_at(1777298400), TempoHardfork::T3);
            assert_eq!(cs.tempo_hardfork_at(u64::MAX), TempoHardfork::T3);
        }

        #[test]
        fn moderato() {
            let cs = super::super::TempoChainSpecParser::parse("moderato")
                .expect("the moderato chainspec must always be well formed");

            // Before T0/T1 activation (1770303600 = Feb 5th 2026 16:00 CET)
            assert_eq!(cs.tempo_hardfork_at(0), TempoHardfork::Genesis);
            assert_eq!(cs.tempo_hardfork_at(1770303599), TempoHardfork::Genesis);

            // At and after T0/T1 activation
            assert_eq!(cs.tempo_hardfork_at(1770303600), TempoHardfork::T1);
            assert_eq!(cs.tempo_hardfork_at(1770303601), TempoHardfork::T1);

            // Before T1A/T1B activation (1771858800 = Feb 23rd 2026 16:00 CET)
            assert_eq!(cs.tempo_hardfork_at(1771858799), TempoHardfork::T1);

            // At and after T1A/T1B activation (both activate at 1771858800)
            assert!(cs.is_t1a_active_at_timestamp(1771858800));
            assert!(cs.is_t1b_active_at_timestamp(1771858800));
            assert_eq!(cs.tempo_hardfork_at(1771858800), TempoHardfork::T1B);

            // Before T1C activation (1773068400 = Mar 9th 2026 16:00 CET)
            assert!(!cs.is_t1c_active_at_timestamp(1773068399));
            assert_eq!(cs.tempo_hardfork_at(1773068399), TempoHardfork::T1B);

            // At and after T1C activation
            assert!(cs.is_t1c_active_at_timestamp(1773068400));
            assert_eq!(cs.tempo_hardfork_at(1773068400), TempoHardfork::T1C);

            // Before T2 activation (1774537200 = Mar 26th 2026 16:00 CET)
            assert!(!cs.is_t2_active_at_timestamp(1774537199));
            assert_eq!(cs.tempo_hardfork_at(1774537199), TempoHardfork::T1C);

            // At and after T2 activation
            assert!(cs.is_t2_active_at_timestamp(1774537200));
            assert_eq!(cs.tempo_hardfork_at(1774537200), TempoHardfork::T2);

            // Before T3 activation (1776780000 = Apr 21st 2026 16:00 CEST)
            assert!(!cs.is_t3_active_at_timestamp(1776779999));
            assert_eq!(cs.tempo_hardfork_at(1776779999), TempoHardfork::T2);

            // At and after T3 activation
            assert!(cs.is_t3_active_at_timestamp(1776780000));
            assert_eq!(cs.tempo_hardfork_at(1776780000), TempoHardfork::T3);
            assert_eq!(cs.tempo_hardfork_at(u64::MAX), TempoHardfork::T3);
        }

        #[test]
        fn testnet() {
            let cs = super::super::TempoChainSpecParser::parse("testnet")
                .expect("the testnet chainspec must always be well formed");

            // "testnet" is an alias for moderato
            let moderato = super::super::TempoChainSpecParser::parse("moderato")
                .expect("the moderato chainspec must always be well formed");
            assert_eq!(cs.inner.chain(), moderato.inner.chain());
        }
    }

    #[test]
    #[allow(clippy::expect_fun_call)]
    fn chainspec_from_chain_id_roundtrips_supported_chains() {
        use reth_chainspec::EthChainSpec;

        for &name in super::SUPPORTED_CHAINS {
            let spec =
                super::chain_value_parser(name).expect(&format!("failed to parse chain `{name}`"));

            let resolved = super::chainspec_from_chain_id(spec.chain().id())
                .expect(&format!("failed to parse chain `{name}`"));

            assert_eq!(spec.chain(), resolved.chain(), "chain mismatch for {name}");
        }
    }
}
