//! Zone chain specification.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy_eips::{eip1559::BaseFeeParams, eip7840::BlobParams};
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{
    Chain, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition,
    ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_network_peers::NodeRecord;
use std::{fmt::Display, sync::Arc};
use tempo_chainspec::{
    TempoChainSpec, TempoConsensusSpec,
    hardfork::TempoHardfork,
    spec::{DEV, TempoHardforks, chainspec_from_chain_id},
};
use tempo_primitives::TempoHeader;
use zone_primitives::constants::{ZoneChainIdError, decode_l1_chain_id, decode_zone_chain_id};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// Chain specification for a Tempo Zone.
///
/// Zones use the underlying Tempo and Ethereum hardfork schedule, inheriting missing
/// activations when their parent Tempo chain is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneChainSpec {
    /// Underlying Tempo chain specification.
    pub inner: Arc<TempoChainSpec>,
}

impl ZoneChainSpec {
    /// Converts a genesis configuration into a Zone chain specification.
    ///
    /// Known public and local development chains inherit their parent schedule. Custom chains
    /// use only the supplied genesis, so dependency updates cannot activate omitted forks; use
    /// [`Self::from_genesis_with_l1_rpc`] to follow their L1 schedule instead.
    pub fn from_genesis(genesis: Genesis) -> Result<Self, ZoneChainSpecError> {
        let parent_chain_id = decode_l1_chain_id(genesis.config.chain_id)?;
        if let Some(parent) = tempo_chain_spec_for_l1(parent_chain_id) {
            return Self::from_genesis_with_l1(genesis, parent.as_ref());
        }
        Ok(Self::from_explicit_genesis(genesis))
    }

    /// Converts a genesis configuration using an already-resolved L1 chain specification.
    ///
    /// This supports custom L1 chains whose hardfork schedule is not globally registered.
    pub fn from_genesis_with_l1(
        mut genesis: Genesis,
        l1: &TempoChainSpec,
    ) -> Result<Self, ZoneChainSpecError> {
        decode_l1_chain_id(genesis.config.chain_id)?;
        inherit_parent_fork_activations(&mut genesis, l1)?;
        Ok(Self::from_explicit_genesis(genesis))
    }

    /// Converts a genesis configuration, reading a custom parent's Tempo fork schedule from L1.
    ///
    /// Known parents behave as in [`Self::from_genesis`] without querying `l1`. For any other
    /// parent, the schedule `l1` reports through `tempo_forkSchedule` replaces every Tempo
    /// activation in the genesis: scheduled forks use the L1 timestamps and all others are
    /// disabled, so the Zone follows its L1 even where its genesis differs. Ethereum activations
    /// keep their genesis values.
    ///
    /// Fails if `l1` belongs to another chain or schedules a fork this binary does not know.
    #[cfg(feature = "l1-rpc")]
    pub async fn from_genesis_with_l1_rpc<TProvider>(
        mut genesis: Genesis,
        l1: &TProvider,
    ) -> Result<Self, ZoneChainSpecError>
    where
        TProvider: alloy_provider::Provider<tempo_alloy::TempoNetwork>,
    {
        let parent_chain_id = decode_l1_chain_id(genesis.config.chain_id)?;
        if tempo_chain_spec_for_l1(parent_chain_id).is_some() {
            return Self::from_genesis(genesis);
        }

        let l1_chain_id = l1.get_chain_id().await?;
        if l1_chain_id != parent_chain_id {
            return Err(ZoneChainSpecError::L1ChainIdMismatch {
                l1: l1_chain_id,
                parent: parent_chain_id,
            });
        }
        let schedule = tempo_alloy::provider::TempoProviderExt::get_fork_schedule(l1).await?;

        let mut activations = std::collections::BTreeMap::new();
        for fork in schedule.schedule {
            let Ok(hardfork) = fork.name.parse::<TempoHardfork>() else {
                return Err(ZoneChainSpecError::UnsupportedL1Fork(fork.name));
            };
            if activations.insert(hardfork, fork.activation_time).is_some() {
                return Err(ZoneChainSpecError::DuplicateL1Fork(hardfork));
            }
        }
        for fork in TempoHardfork::VARIANTS {
            if let Some(key) = fork.genesis_key() {
                let activation = activations
                    .get(fork)
                    .map_or(serde_json::Value::Null, |&time| time.into());
                genesis
                    .config
                    .extra_fields
                    .insert(key.to_owned(), activation);
            }
        }
        Ok(Self::from_explicit_genesis(genesis))
    }

    /// Zone identifier encoded in the genesis chain ID.
    pub fn zone_id(&self) -> u32 {
        decode_zone_chain_id(self.inner.genesis().config.chain_id)
            .expect("ZoneChainSpec validates its chain ID during construction")
            .1
    }

    fn from_explicit_genesis(genesis: Genesis) -> Self {
        let zone = TempoChainSpec::from_genesis(genesis);
        Self {
            inner: Arc::new(zone),
        }
    }
}

/// Fills missing fork activation fields in the Zone genesis from its parent.
///
/// Chain config serializes Ethereum and Tempo activations as camelCase `*Block` and `*Time`
/// fields. Composing them before constructing the chain spec ensures that its cached genesis
/// header is built with the inherited activations. Explicit Zone activations take precedence.
fn inherit_parent_fork_activations(
    zone_genesis: &mut Genesis,
    l1: &TempoChainSpec,
) -> Result<(), serde_json::Error> {
    let mut zone_config = serde_json::to_value(&zone_genesis.config)?;
    let l1_config = serde_json::to_value(&l1.genesis().config)?;
    let zone_fields = zone_config
        .as_object_mut()
        .expect("ChainConfig must serialize as a JSON object");
    let l1_fields = l1_config
        .as_object()
        .expect("ChainConfig must serialize as a JSON object");

    for (name, value) in l1_fields {
        if name.ends_with("Block") || name.ends_with("Time") {
            zone_fields
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }

    zone_genesis.config = serde_json::from_value(zone_config)?;
    Ok(())
}

impl Hardforks for ZoneChainSpec {
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

impl EthChainSpec for ZoneChainSpec {
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

    fn display_hardforks(&self) -> Box<dyn Display> {
        self.inner.display_hardforks()
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        self.inner.bootnodes()
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.inner.final_paris_total_difficulty()
    }

    fn next_block_base_fee(&self, _parent: &TempoHeader, _target_timestamp: u64) -> Option<u64> {
        Some(0)
    }
}

impl EthereumHardforks for ZoneChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }
}

impl TempoHardforks for ZoneChainSpec {
    fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition {
        self.inner.tempo_fork_activation(fork)
    }
}

impl TempoConsensusSpec for ZoneChainSpec {
    fn shared_gas_limit_at(&self, _timestamp: u64, _gas_limit: u64) -> u64 {
        0
    }

    fn general_gas_limit_at(
        &self,
        _timestamp: u64,
        _gas_limit: u64,
        _shared_gas_limit: u64,
    ) -> u64 {
        0
    }
}

impl EthExecutorSpec for ZoneChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.inner.deposit_contract_address()
    }
}

/// Zone chain specification parser.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Default)]
pub struct ZoneChainSpecParser;

#[cfg(feature = "cli")]
impl reth_cli::chainspec::ChainSpecParser for ZoneChainSpecParser {
    type ChainSpec = ZoneChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &[];

    fn parse(s: &str) -> eyre::Result<std::sync::Arc<Self::ChainSpec>> {
        let genesis = reth_cli::chainspec::parse_genesis(s)?;
        Ok(Arc::new(ZoneChainSpec::from_genesis(genesis)?))
    }
}

/// Failure to resolve the canonical chain specification for a zone.
#[derive(Debug, thiserror::Error)]
pub enum ZoneChainSpecError {
    /// The zone chain ID is not a valid encoding of its parent and zone IDs.
    #[error(transparent)]
    InvalidChainId(#[from] ZoneChainIdError),
    /// The inherited parent fork activations could not be applied to the Zone genesis.
    #[error("failed to compose Zone genesis config: {0}")]
    InvalidGenesisConfig(#[from] serde_json::Error),
    /// Reading the parent fork schedule from the L1 RPC failed.
    #[cfg(feature = "l1-rpc")]
    #[error("failed reading the L1 fork schedule: {0}")]
    L1Rpc(#[from] alloy_transport::TransportError),
    /// The L1 RPC belongs to another chain than the Zone's parent.
    #[error("L1 RPC chain ID {l1} does not match zone parent chain ID {parent}")]
    L1ChainIdMismatch {
        /// Chain ID the L1 RPC reports.
        l1: u64,
        /// Parent chain ID encoded in the Zone chain ID.
        parent: u64,
    },
    /// The L1 schedules a Tempo fork this binary does not know.
    #[error("L1 schedules unsupported Tempo fork {0}; update the zone binary")]
    UnsupportedL1Fork(String),
    /// The L1 schedule lists a Tempo fork more than once.
    #[error("L1 schedules Tempo fork {0} twice")]
    DuplicateL1Fork(TempoHardfork),
}

/// Returns the Tempo chain specification whose hardfork schedule a parent uses.
///
/// Local development chains 1337 and 31337 use the Tempo DEV schedule. Custom chains
/// have no implicit parent schedule; `ZONE_L1_DEV_CHAIN_IDS` is no longer used.
pub fn tempo_chain_spec_for_l1(chain_id: u64) -> Option<Arc<TempoChainSpec>> {
    chainspec_from_chain_id(chain_id).or_else(|| match chain_id {
        1_337 | 31_337 => Some(DEV.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "cli")]
    use reth_cli::chainspec::ChainSpecParser;
    use tempo_chainspec::spec::{DEV, MODERATO};
    use zone_primitives::constants::zone_chain_id;

    fn dev_zone_spec(zone_id: u32) -> ZoneChainSpec {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(DEV.chain_id(), zone_id).unwrap();
        ZoneChainSpec::from_genesis(genesis).unwrap()
    }

    #[test]
    fn delegates_tempo_chain_behavior() {
        let zone = dev_zone_spec(1);

        assert_eq!(zone.chain_id(), zone_chain_id(DEV.chain_id(), 1).unwrap());
        for &hardfork in TempoHardfork::VARIANTS {
            assert_eq!(
                zone.tempo_fork_activation(hardfork),
                DEV.tempo_fork_activation(hardfork)
            );
        }
    }

    #[test]
    fn hardfork_schedule_matches_tempo() {
        let zone = dev_zone_spec(4);
        let zone_forks: Vec<_> = zone
            .forks_iter()
            .map(|(fork, condition)| (fork.name(), condition))
            .collect();
        let tempo_forks: Vec<_> = DEV
            .forks_iter()
            .map(|(fork, condition)| (fork.name(), condition))
            .collect();
        assert_eq!(zone_forks, tempo_forks);
        assert_eq!(zone.latest_fork_id(), DEV.latest_fork_id());
    }

    #[test]
    fn tempo_hardfork_activates_at_boundary() {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 5).unwrap();
        test_utils::set_tempo_fork(&mut genesis, TempoHardfork::T13, 100);
        let zone = ZoneChainSpec::from_genesis(genesis).unwrap();

        assert_eq!(zone.tempo_hardfork_at(99), TempoHardfork::T12);
        assert_eq!(zone.tempo_hardfork_at(100), TempoHardfork::T13);
    }

    #[test]
    fn genesis_inherits_missing_parent_hardforks_everywhere() {
        let mut genesis = MODERATO.genesis().clone();
        genesis.config.chain_id = zone_chain_id(MODERATO.chain_id(), 7).unwrap();
        genesis.config.london_block = None;
        genesis.config.shanghai_time = None;
        genesis.config.cancun_time = None;
        genesis.config.prague_time = None;
        let raw = TempoChainSpec::from_genesis(genesis.clone());
        let zone = ZoneChainSpec::from_genesis(genesis).unwrap();

        assert_eq!(zone.chain_id(), raw.chain_id());
        assert_ne!(zone.genesis_hash(), raw.genesis_hash());
        assert!(raw.genesis_header().inner.base_fee_per_gas.is_none());
        assert!(raw.genesis_header().inner.withdrawals_root.is_none());
        assert!(
            raw.genesis_header()
                .inner
                .parent_beacon_block_root
                .is_none()
        );
        assert!(raw.genesis_header().inner.requests_hash.is_none());
        assert!(zone.genesis_header().inner.base_fee_per_gas.is_some());
        assert!(zone.genesis_header().inner.withdrawals_root.is_some());
        assert!(
            zone.genesis_header()
                .inner
                .parent_beacon_block_root
                .is_some()
        );
        assert!(zone.genesis_header().inner.requests_hash.is_some());
        for &hardfork in EthereumHardfork::VARIANTS {
            assert_eq!(
                zone.ethereum_fork_activation(hardfork),
                MODERATO.ethereum_fork_activation(hardfork)
            );
        }
        for &hardfork in TempoHardfork::VARIANTS {
            assert_eq!(
                zone.tempo_fork_activation(hardfork),
                MODERATO.tempo_fork_activation(hardfork)
            );
        }
    }

    #[test]
    fn genesis_accepts_an_already_resolved_custom_l1_spec() {
        const CUSTOM_L1_CHAIN_ID: u64 = 31_318;

        let mut l1_genesis = DEV.genesis().clone();
        l1_genesis.config.chain_id = CUSTOM_L1_CHAIN_ID;
        l1_genesis.config.osaka_time = Some(456);
        let l1 = TempoChainSpec::from_genesis(l1_genesis);

        let mut zone_genesis = DEV.genesis().clone();
        zone_genesis.config.chain_id = zone_chain_id(CUSTOM_L1_CHAIN_ID, 8).unwrap();
        zone_genesis.config.osaka_time = Some(123);
        zone_genesis
            .config
            .extra_fields
            .insert_value("t11Time".to_string(), 789)
            .unwrap();
        let zone = ZoneChainSpec::from_genesis_with_l1(zone_genesis, &l1).unwrap();

        assert_eq!(
            zone.ethereum_fork_activation(EthereumHardfork::Osaka),
            ForkCondition::Timestamp(123)
        );
        assert_eq!(
            zone.tempo_fork_activation(TempoHardfork::T11),
            ForkCondition::Timestamp(789)
        );
    }

    #[cfg(feature = "l1-rpc")]
    fn mocked_l1(
        responses: &[serde_json::Value],
    ) -> impl alloy_provider::Provider<tempo_alloy::TempoNetwork> + use<> {
        let asserter = alloy_provider::mock::Asserter::new();
        for response in responses {
            asserter.push_success(response);
        }
        alloy_provider::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter)
    }

    #[cfg(feature = "l1-rpc")]
    fn custom_zone_genesis() -> Genesis {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(31_318, 9).unwrap();
        test_utils::set_tempo_fork(&mut genesis, TempoHardfork::T13, 100);
        genesis
    }

    #[cfg(feature = "l1-rpc")]
    #[tokio::test]
    async fn l1_rpc_schedule_replaces_the_genesis_schedule() {
        let from_genesis = ZoneChainSpec::from_genesis(custom_zone_genesis()).unwrap();
        let l1 = mocked_l1(&[
            serde_json::json!("0x7a56"),
            serde_json::json!({ "active": "T12", "schedule": [
                { "name": "T0", "activationTime": 0, "active": true },
                { "name": "T12", "activationTime": 0, "active": true },
                { "name": "T13", "activationTime": 500, "active": false }
            ] }),
        ]);
        let zone = ZoneChainSpec::from_genesis_with_l1_rpc(custom_zone_genesis(), &l1)
            .await
            .unwrap();

        assert_eq!(zone.genesis_hash(), from_genesis.genesis_hash());
        assert_eq!(
            zone.ethereum_fork_activation(EthereumHardfork::Osaka),
            from_genesis.ethereum_fork_activation(EthereumHardfork::Osaka)
        );
        assert_eq!(
            zone.tempo_fork_activation(TempoHardfork::T13),
            ForkCondition::Timestamp(500)
        );
        assert_eq!(
            zone.tempo_fork_activation(TempoHardfork::T11),
            ForkCondition::Never
        );
        assert_eq!(zone.tempo_hardfork_at(499), TempoHardfork::T12);
        assert_eq!(zone.tempo_hardfork_at(500), TempoHardfork::T13);
    }

    #[cfg(feature = "l1-rpc")]
    #[tokio::test]
    async fn l1_rpc_schedule_is_validated() {
        let schedule =
            |forks: serde_json::Value| serde_json::json!({ "active": "T0", "schedule": forks });
        let cases = [
            (
                vec![serde_json::json!("0x1079")],
                "L1 RPC chain ID 4217 does not match zone parent chain ID 31318",
            ),
            (
                vec![
                    serde_json::json!("0x7a56"),
                    schedule(serde_json::json!([
                        { "name": "T999", "activationTime": 500, "active": false }
                    ])),
                ],
                "L1 schedules unsupported Tempo fork T999; update the zone binary",
            ),
            (
                vec![
                    serde_json::json!("0x7a56"),
                    schedule(serde_json::json!([
                        { "name": "T0", "activationTime": 0, "active": true },
                        { "name": "T0", "activationTime": 0, "active": true }
                    ])),
                ],
                "L1 schedules Tempo fork T0 twice",
            ),
        ];
        for (responses, expected) in cases {
            let error = ZoneChainSpec::from_genesis_with_l1_rpc(
                custom_zone_genesis(),
                &mocked_l1(&responses),
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
        }
    }

    #[cfg(feature = "l1-rpc")]
    #[tokio::test]
    async fn known_l1_does_not_query_rpc() {
        let mut genesis = MODERATO.genesis().clone();
        genesis.config.chain_id = zone_chain_id(MODERATO.chain_id(), 7).unwrap();
        let zone = ZoneChainSpec::from_genesis_with_l1_rpc(genesis.clone(), &mocked_l1(&[]))
            .await
            .unwrap();

        assert_eq!(zone, ZoneChainSpec::from_genesis(genesis).unwrap());
    }

    #[test]
    fn next_block_base_fee_is_zero() {
        let zone = dev_zone_spec(2);
        let parent = zone.genesis_header();
        let timestamp = parent.inner.timestamp;

        assert_ne!(DEV.next_block_base_fee(parent, timestamp), Some(0));
        assert_eq!(zone.next_block_base_fee(parent, timestamp), Some(0));
    }

    #[test]
    fn consensus_gas_limits_disable_tempo_gas_sections() {
        let zone = dev_zone_spec(3);

        assert_eq!(zone.shared_gas_limit_at(0, 30_000_000), 0);
        assert_eq!(zone.general_gas_limit_at(0, 30_000_000, 0), 0);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn parser_parses_zone_genesis_json() {
        let mut genesis = DEV.genesis().clone();
        let chain_id = zone_chain_id(DEV.chain_id(), 9).unwrap();
        genesis.config.chain_id = chain_id;
        let json = serde_json::to_string(&genesis).unwrap();
        let zone = ZoneChainSpecParser::parse(&json).expect("valid Zone genesis JSON");

        assert_eq!(zone.chain_id(), chain_id);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn parser_rejects_named_tempo_chain() {
        assert!(ZoneChainSpecParser::parse("dev").is_err());
    }

    #[test]
    fn custom_genesis_preserves_historical_schedule() {
        let genesis = historical_custom_genesis();
        let expected = TempoChainSpec::from_genesis(genesis.clone());
        let zone = ZoneChainSpec::from_genesis(genesis.clone()).unwrap();

        assert_eq!(zone.genesis(), &genesis);
        assert_eq!(zone.genesis_hash(), expected.genesis_hash());
        assert_eq!(zone.tempo_hardfork_at(u64::MAX), TempoHardfork::T11);
        assert_eq!(
            zone.tempo_fork_activation(TempoHardfork::T14),
            ForkCondition::Never
        );
        assert_eq!(zone.zone_id(), 11);
        assert!(tempo_chain_spec_for_l1(31_318).is_none());
    }

    #[test]
    fn custom_genesis_preserves_future_activation() {
        let mut genesis = historical_custom_genesis();
        genesis
            .config
            .extra_fields
            .insert("t12Time".into(), serde_json::json!(1_000));
        let zone = ZoneChainSpec::from_genesis(genesis).unwrap();

        assert_eq!(zone.tempo_hardfork_at(999), TempoHardfork::T11);
        assert_eq!(zone.tempo_hardfork_at(1_000), TempoHardfork::T12);
        assert_eq!(zone.tempo_hardfork_at(u64::MAX), TempoHardfork::T12);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn parser_preserves_custom_genesis_schedule() {
        let genesis = historical_custom_genesis();
        let zone = ZoneChainSpecParser::parse(&serde_json::to_string(&genesis).unwrap()).unwrap();

        assert_eq!(zone.genesis(), &genesis);
        assert_eq!(zone.tempo_hardfork_at(u64::MAX), TempoHardfork::T11);
    }

    #[test]
    fn custom_genesis_still_rejects_invalid_chain_ids() {
        let mut genesis = historical_custom_genesis();
        genesis.config.chain_id = 0;
        assert!(matches!(
            ZoneChainSpec::from_genesis(genesis),
            Err(ZoneChainSpecError::InvalidChainId(_))
        ));
    }

    fn historical_custom_genesis() -> Genesis {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(31_318, 11).unwrap();
        // The existing devnet explicitly disabled T12/T13 before T14 was introduced.
        for &fork in TempoHardfork::VARIANTS {
            if fork > TempoHardfork::T13 {
                genesis
                    .config
                    .extra_fields
                    .remove(&format!("{}Time", fork.to_string().to_lowercase()));
            }
        }
        genesis
            .config
            .extra_fields
            .insert("t12Time".into(), serde_json::Value::Null);
        genesis
            .config
            .extra_fields
            .insert("t13Time".into(), serde_json::Value::Null);
        genesis
    }
}
