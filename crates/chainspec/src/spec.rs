pub use tempo_hardfork::constants::gas::*;

use crate::{
    bootnodes::{moderato_nodes, presto_nodes},
    network_identity::NetworkIdentity,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_eips::eip7840::BlobParams;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use core::num::NonZeroU64;
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
use tempo_hardfork::TempoHardfork;
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
    epoch_length: Option<NonZeroU64>,
    /// Optional override for the general (non-payment) gas limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    general_gas_limit: Option<u64>,
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
    /// Activation timestamp for T5 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t5_time: Option<u64>,
    /// Activation timestamp for T6 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t6_time: Option<u64>,
    /// Activation timestamp for T7 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t7_time: Option<u64>,
    /// Activation timestamp for T8 hardfork.
    #[serde(skip_serializing_if = "Option::is_none")]
    t8_time: Option<u64>,
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

    pub fn epoch_length(&self) -> Option<NonZeroU64> {
        self.epoch_length
    }

    pub fn general_gas_limit(&self) -> Option<u64> {
        self.general_gas_limit
    }

    /// Returns the activation timestamp for a given hardfork, or `None` if not scheduled.
    pub fn fork_time(&self, fork: TempoHardfork) -> Option<u64> {
        macro_rules! fork_time_match {
            ($($variant:ident),* $(,)?) => {
                paste::paste! {
                    match fork {
                        TempoHardfork::Genesis => Some(0),
                        $(TempoHardfork::$variant => self.[<$variant:lower _time>],)*
                        // Required because `TempoHardfork` is non-exhaustive across crates.
                        // Missing `TempoGenesisInfo` fields fail via generated `self.<fork>_time`.
                        _ => None,
                    }
                }
            };
        }

        tempo_hardfork::tempo_post_genesis_hardforks!(fork_time_match)
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
        .with_network_identity(NetworkIdentity::testnet())
        .with_default_follow_url("wss://rpc.moderato.tempo.xyz")
        .into()
});

pub static PRESTO: LazyLock<Arc<TempoChainSpec>> = LazyLock::new(|| {
    let genesis: Genesis = serde_json::from_str(include_str!("./genesis/presto.json"))
        .expect("`./genesis/presto.json` must be present and deserializable");

    TempoChainSpec::from_genesis(genesis)
        .with_network_identity(NetworkIdentity::mainnet())
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
    /// Consensus network identity derived from genesis
    pub network_identity: Option<NetworkIdentity>,
    /// Default RPC URL for following this chain.
    pub default_follow_url: Option<&'static str>,
}

impl TempoChainSpec {
    /// Returns the default RPC URL for following this chain.
    pub fn default_follow_url(&self) -> Option<&'static str> {
        self.default_follow_url
    }

    /// Returns the general (non-payment) gas limit for the given timestamp and block.
    /// - Genesis override: fixed at the configured value
    /// - T1+: fixed at 30M gas
    /// - Pre-T1: calculated as (gas_limit - shared_gas_limit) / 2
    pub fn general_gas_limit_at(
        &self,
        timestamp: u64,
        gas_limit: u64,
        shared_gas_limit: u64,
    ) -> u64 {
        self.info
            .general_gas_limit()
            .or_else(|| self.tempo_hardfork_at(timestamp).general_gas_limit())
            .unwrap_or_else(|| (gas_limit - shared_gas_limit) / 2)
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

        let inner = base_spec.map_header(|inner| TempoHeader {
            general_gas_limit: 0,
            timestamp_millis_part: inner.timestamp % 1000,
            shared_gas_limit: 0,
            consensus_context: None,
            inner,
        });

        // TODO(hamdi): Dev networks are allowed to have a non-dkg outcome in extra data. Update such
        // that we always require a valid dkg outcome, thus network identity for all networks
        let network_identity =
            NetworkIdentity::from_extra_data(inner.genesis_header().inner.extra_data.as_ref()).ok();

        Self {
            inner,
            info,
            network_identity,
            default_follow_url: None,
        }
    }

    /// Sets the compiled consensus network identity for this chain.
    pub fn with_network_identity(mut self, identity: NetworkIdentity) -> Self {
        self.network_identity = Some(identity);
        self
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
        let inner = spec.map_header(|inner| TempoHeader {
            general_gas_limit: 0,
            timestamp_millis_part: inner.timestamp % 1000,
            shared_gas_limit: 0,
            consensus_context: None,
            inner,
        });

        let network_identity =
            NetworkIdentity::from_extra_data(inner.genesis_header().inner.extra_data.as_ref()).ok();

        Self {
            inner,
            info: TempoGenesisInfo::default(),
            network_identity,
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

    fn next_block_base_fee(&self, parent: &TempoHeader, target_timestamp: u64) -> Option<u64> {
        let target_fork = self.tempo_hardfork_at(target_timestamp);

        if target_fork.is_t7() {
            let parent_base_fee = parent
                .inner
                .base_fee_per_gas
                .expect("tempo blocks are expected to have a base fee");
            Some(tempo_t7_next_block_base_fee(
                parent_base_fee,
                parent.inner.gas_used,
            ))
        } else if target_fork.is_t1() {
            Some(TEMPO_T1_BASE_FEE)
        } else {
            Some(TEMPO_T0_BASE_FEE)
        }
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

/// Generates the Tempo hardfork query trait for all post-Genesis hardforks.
macro_rules! tempo_hardforks_trait {
    ($($variant:ident),* $(,)?) => {
        /// Trait for querying Tempo-specific hardfork activations.
        pub trait TempoHardforks: EthereumHardforks {
            /// Retrieves activation condition for a Tempo-specific hardfork.
            fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition;

            /// Retrieves the Tempo hardfork active at a given timestamp.
            fn tempo_hardfork_at(&self, timestamp: u64) -> TempoHardfork {
                for &fork in TempoHardfork::VARIANTS.iter().rev() {
                    if self
                        .tempo_fork_activation(fork)
                        .active_at_timestamp(timestamp)
                    {
                        return fork;
                    }
                }
                TempoHardfork::Genesis
            }

            paste::paste! {
                $(
                    #[doc = concat!("Returns true if ", stringify!($variant), " is active at the given timestamp.")]
                    fn [<is_ $variant:lower _active_at_timestamp>](&self, timestamp: u64) -> bool {
                        self.tempo_fork_activation(TempoHardfork::$variant)
                            .active_at_timestamp(timestamp)
                    }
                )*
            }

            /// Returns the shared gas limit for the given timestamp and block.
            /// - T4+: 0 gas
            /// - Pre-T4: block_gas_limit / 10
            fn shared_gas_limit_at(&self, timestamp: u64, gas_limit: u64) -> u64 {
                self.tempo_hardfork_at(timestamp)
                    .shared_gas_limit(gas_limit)
            }
        }
    };
}

tempo_hardfork::tempo_post_genesis_hardforks!(tempo_hardforks_trait);

impl TempoHardforks for TempoChainSpec {
    fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition {
        self.fork(fork)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        TempoHardfork,
        spec::{TEMPO_T1_BASE_FEE, TEMPO_T7_BASE_FEE_CAP, TEMPO_T7_BASE_FEE_FLOOR, TempoHardforks},
    };
    use alloy_primitives::hex;
    use commonware_codec::Encode as _;
    use reth_chainspec::EthChainSpec;
    #[cfg(feature = "cli")]
    use reth_chainspec::{ForkCondition, Hardforks};
    #[cfg(feature = "cli")]
    use reth_cli::chainspec::ChainSpecParser as _;
    use tempo_primitives::Header;

    #[test]
    #[cfg(feature = "cli")]
    fn can_load_testnet() {
        let _ = super::TempoChainSpecParser::parse("testnet")
            .expect("the testnet chainspec must always be well formed");
    }

    #[test]
    #[cfg(feature = "cli")]
    fn can_load_dev() {
        let _ = super::TempoChainSpecParser::parse("dev")
            .expect("the dev chainspec must always be well formed");
    }

    #[test]
    #[cfg(feature = "cli")]
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
    #[cfg(feature = "cli")]
    fn test_tempo_chainspec_implements_tempo_hardforks_trait() {
        let chainspec = super::TempoChainSpecParser::parse("mainnet")
            .expect("the mainnet chainspec must always be well formed");

        // Should be able to query Tempo hardfork activation through trait
        let activation = chainspec.tempo_fork_activation(TempoHardfork::T0);
        assert_eq!(activation, ForkCondition::Timestamp(0));
    }

    #[test]
    fn network_identity_defaults_to_genesis_extra_data() {
        let genesis: alloy_genesis::Genesis =
            serde_json::from_str(include_str!("./genesis/presto.json"))
                .expect("the mainnet genesis must always be well formed");

        let chainspec = super::TempoChainSpec::from_genesis(genesis);
        let identity = chainspec
            .network_identity
            .expect("presto genesis contains a DKG outcome");

        assert_eq!(identity.from_epoch, 0);
        assert_eq!(
            identity.identity.encode().as_ref(),
            &hex!(
                "0xa217bb85001d4dcf8e5c50136f77af88cb2cab1857279b91c6240f41cca95c4f"
                "43f6dcab3e0dfb87dafb3ecbeb6251e90a5df2e6c47432482821cd8b84665ee4"
                "642589d2d9628a92b03e2bbfb00e006d038cd98def76d2a41b7c228c05f5a193"
            )
        );
    }

    #[test]
    #[cfg(feature = "cli")]
    fn named_network_identities_use_compiled_identities() {
        let moderato = super::TempoChainSpecParser::parse("testnet")
            .expect("the moderato chainspec must always be well formed");
        assert_eq!(
            moderato.network_identity,
            Some(super::NetworkIdentity::testnet())
        );

        assert_eq!(
            moderato.network_identity,
            Some(super::NetworkIdentity::testnet())
        );

        let presto = super::TempoChainSpecParser::parse("mainnet")
            .expect("the mainnet chainspec must always be well formed");
        assert_eq!(
            presto.network_identity,
            Some(super::NetworkIdentity::mainnet())
        );
    }

    #[test]
    fn network_identity_is_absent_without_genesis_dkg_outcome() {
        let genesis: alloy_genesis::Genesis = serde_json::from_value(serde_json::json!({
            "config": { "chainId": 1234 },
            "alloc": {}
        }))
        .unwrap();

        let chainspec = super::TempoChainSpec::from_genesis(genesis);
        assert!(chainspec.network_identity.is_none());
    }

    #[test]
    #[cfg(feature = "cli")]
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

    #[test]
    fn test_general_gas_limit_at_uses_genesis_override() {
        let genesis: alloy_genesis::Genesis = serde_json::from_value(serde_json::json!({
            "config": {
                "chainId": 1234,
                "t1Time": 0,
                "generalGasLimit": 123456789
            },
            "alloc": {}
        }))
        .unwrap();

        let chainspec = super::TempoChainSpec::from_genesis(genesis);

        assert_eq!(chainspec.info.general_gas_limit(), Some(123456789));
        assert_eq!(chainspec.general_gas_limit_at(0, 500_000_000, 0), 123456789);
    }

    fn header(timestamp: u64, base_fee: u64, gas_used: u64) -> super::TempoHeader {
        super::TempoHeader {
            inner: Header {
                timestamp,
                base_fee_per_gas: Some(base_fee),
                gas_used,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn chainspec_with_t7_at(t7_time: u64) -> super::TempoChainSpec {
        let genesis = serde_json::json!({
            "config": {
                "chainId": 99999,
                "homesteadBlock": 0,
                "daoForkSupport": false,
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
                "shanghaiTime": 0,
                "cancunTime": 0,
                "pragueTime": 0,
                "osakaTime": 0,
                "terminalTotalDifficulty": 0,
                "terminalTotalDifficultyPassed": true,
                "t0Time": 0,
                "t1Time": 0,
                "t7Time": t7_time
            },
            "nonce": "0x42",
            "timestamp": "0x0",
            "extraData": "0x",
            "gasLimit": "0x1dcd6500",
            "difficulty": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "alloc": {}
        });
        let genesis: alloy_genesis::Genesis = serde_json::from_value(genesis).unwrap();
        super::TempoChainSpec::from_genesis(genesis)
    }

    #[test]
    fn next_block_base_fee_fixed_before_t7() {
        let chainspec = chainspec_with_t7_at(10);
        let parent = header(8, TEMPO_T1_BASE_FEE / 2, 0);

        assert_eq!(
            chainspec.next_block_base_fee(&parent, 9),
            Some(TEMPO_T1_BASE_FEE)
        );
    }

    #[test]
    fn next_block_base_fee_seeds_cap_on_t7_activation() {
        let chainspec = chainspec_with_t7_at(10);
        let parent = header(9, TEMPO_T1_BASE_FEE, 0);

        assert_eq!(
            chainspec.next_block_base_fee(&parent, 10),
            Some(TEMPO_T7_BASE_FEE_CAP)
        );
    }

    #[test]
    fn next_block_base_fee_adjusts_after_t7_activation() {
        let chainspec = chainspec_with_t7_at(10);
        let parent = header(10, TEMPO_T7_BASE_FEE_CAP, 0);

        assert_eq!(
            chainspec.next_block_base_fee(&parent, 11),
            Some(TEMPO_T7_BASE_FEE_CAP * 7 / 8)
        );
    }

    #[test]
    fn next_block_base_fee_uses_parent_gas_used_after_t7_activation() {
        let chainspec = chainspec_with_t7_at(10);
        let parent = header(10, TEMPO_T7_BASE_FEE_FLOOR, 30_000_000);

        assert_eq!(
            chainspec.next_block_base_fee(&parent, 11),
            Some(750_000_000)
        );
    }

    #[cfg(feature = "cli")]
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

            // Before T4 activation (1779112800 = May 18th 2026 16:00 CEST)
            assert!(!cs.is_t4_active_at_timestamp(1779112799));
            assert_eq!(cs.tempo_hardfork_at(1779112799), TempoHardfork::T3);

            // At and after T4 activation
            assert!(cs.is_t4_active_at_timestamp(1779112800));
            assert_eq!(cs.tempo_hardfork_at(1779112800), TempoHardfork::T4);

            // Before T5 activation (1781013600 = Jun 9th 2026 16:00 CEST)
            assert!(!cs.is_t5_active_at_timestamp(1781013599));
            assert_eq!(cs.tempo_hardfork_at(1781013599), TempoHardfork::T4);

            // At and after T5 activation
            assert!(cs.is_t5_active_at_timestamp(1781013600));
            assert_eq!(cs.tempo_hardfork_at(1781013600), TempoHardfork::T5);
            assert!(!cs.is_t6_active_at_timestamp(1781013600));

            // Before T6 activation (1782223200 = Jun 23rd 2026 16:00 CEST)
            assert!(!cs.is_t6_active_at_timestamp(1782223199));
            assert_eq!(cs.tempo_hardfork_at(1782223199), TempoHardfork::T5);

            // At and after T6 activation
            assert!(cs.is_t6_active_at_timestamp(1782223200));
            assert_eq!(cs.tempo_hardfork_at(1782223200), TempoHardfork::T6);

            // Before T7 activation (1783605600 = Jul 9th 2026 16:00 CEST)
            assert!(!cs.is_t7_active_at_timestamp(1783605599));
            assert_eq!(cs.tempo_hardfork_at(1783605599), TempoHardfork::T6);

            // At and after T7 activation
            assert!(cs.is_t7_active_at_timestamp(1783605600));
            assert_eq!(cs.tempo_hardfork_at(1783605600), TempoHardfork::T7);
            assert_eq!(cs.tempo_hardfork_at(u64::MAX), TempoHardfork::T7);
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

            // Before T4 activation (1778767200 = May 14th 2026 16:00 CEST)
            assert!(!cs.is_t4_active_at_timestamp(1778767199));
            assert_eq!(cs.tempo_hardfork_at(1778767199), TempoHardfork::T3);

            // At and after T4 activation
            assert!(cs.is_t4_active_at_timestamp(1778767200));
            assert_eq!(cs.tempo_hardfork_at(1778767200), TempoHardfork::T4);

            // Before T5 activation (1780495200 = Jun 3rd 2026 16:00 CEST)
            assert!(!cs.is_t5_active_at_timestamp(1780495199));
            assert_eq!(cs.tempo_hardfork_at(1780495199), TempoHardfork::T4);

            // At and after T5 activation
            assert!(cs.is_t5_active_at_timestamp(1780495200));
            assert_eq!(cs.tempo_hardfork_at(1780495200), TempoHardfork::T5);
            assert!(!cs.is_t6_active_at_timestamp(1780495200));

            // Before T6 activation (1781791200 = Jun 18th 2026 16:00 CEST)
            assert!(!cs.is_t6_active_at_timestamp(1781791199));
            assert_eq!(cs.tempo_hardfork_at(1781791199), TempoHardfork::T5);

            // At and after T6 activation
            assert!(cs.is_t6_active_at_timestamp(1781791200));
            assert_eq!(cs.tempo_hardfork_at(1781791200), TempoHardfork::T6);

            // Before T7 activation (1783000800 = Jul 2nd 2026 16:00 CEST)
            assert!(!cs.is_t7_active_at_timestamp(1783000799));
            assert_eq!(cs.tempo_hardfork_at(1783000799), TempoHardfork::T6);

            // At and after T7 activation
            assert!(cs.is_t7_active_at_timestamp(1783000800));
            assert_eq!(cs.tempo_hardfork_at(1783000800), TempoHardfork::T7);
            assert_eq!(cs.tempo_hardfork_at(u64::MAX), TempoHardfork::T7);
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
    #[cfg(feature = "cli")]
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
