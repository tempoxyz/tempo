//! Zone chain specification.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy_eips::{eip1559::BaseFeeParams, eip7840::BlobParams};
use alloy_genesis::Genesis;
use alloy_primitives::{B256, U256};
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
    /// use only the supplied genesis, so dependency updates cannot activate omitted forks.
    /// On mainnet and testnet, a Zone whose Tempo fork activations differ from the parent's
    /// compiled schedule is rejected, including when malformed Tempo genesis fields leave the
    /// forks unscheduled.
    pub fn from_genesis(genesis: Genesis) -> Result<Self, ZoneChainSpecError> {
        let parent_chain_id = decode_l1_chain_id(genesis.config.chain_id)?;
        if let Some(parent) = chainspec_from_chain_id(parent_chain_id) {
            let zone = Self::from_genesis_with_l1(genesis, parent.as_ref())?;
            ensure_parent_fork_schedule(&zone, |fork| parent.tempo_fork_activation(fork))?;
            return Ok(zone);
        }
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

    /// Returns this chain specification following the given Tempo fork schedule of its L1.
    ///
    /// Tempo fork fields the Zone genesis omits take the reported activations; forks the L1 has
    /// not scheduled stay disabled. An explicit field, `null` included, must already agree with
    /// the schedule: adopting the L1 value would retroactively change how blocks past that time
    /// execute. Ethereum activations are kept. Also fails if other Tempo genesis fields are
    /// malformed, since that leaves the composed spec without the schedule.
    pub fn with_l1_fork_schedule(
        &self,
        schedule: impl IntoIterator<Item = (TempoHardfork, u64)>,
    ) -> Result<Self, ZoneChainSpecError> {
        let mut genesis = self.inner.genesis().clone();
        let schedule: std::collections::HashMap<_, _> = schedule.into_iter().collect();
        for (fork, &time) in &schedule {
            if let Some(key) = fork.genesis_key() {
                genesis
                    .config
                    .extra_fields
                    .entry(key.to_owned())
                    .or_insert_with(|| time.into());
            }
        }
        let zone = Self::from_explicit_genesis(genesis);
        ensure_parent_fork_schedule(&zone, |fork| {
            schedule
                .get(&fork)
                .map_or(ForkCondition::Never, |&time| ForkCondition::Timestamp(time))
        })?;
        Ok(zone)
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

/// Rejects a Zone whose Tempo fork activations differ from its parent's schedule.
///
/// The prover enclave replays Zone batches under the parent's schedule, so a node following
/// different activations would build blocks the enclave cannot prove. Inheriting the parent's
/// value instead would silently change how blocks already past that time execute. The check
/// runs on the composed spec, so it also catches Tempo genesis metadata that fails to parse and
/// leaves every Tempo fork unscheduled.
fn ensure_parent_fork_schedule(
    zone: &ZoneChainSpec,
    parent: impl Fn(TempoHardfork) -> ForkCondition,
) -> Result<(), ZoneChainSpecError> {
    for &fork in TempoHardfork::VARIANTS {
        if fork.genesis_key().is_none() {
            continue;
        }
        let zone_activation = zone.inner.tempo_fork_activation(fork);
        let parent_activation = parent(fork);
        if zone_activation != parent_activation {
            return Err(ZoneChainSpecError::ParentForkMismatch {
                fork,
                zone: zone_activation.as_timestamp(),
                parent: parent_activation.as_timestamp(),
            });
        }
    }
    Ok(())
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
    /// A Zone's Tempo fork activation disagrees with its parent's schedule.
    #[error(
        "Zone genesis activates {fork:?} at {}, but its parent schedules it at {}; remove the \
         fork field or match the parent, and check that the Tempo genesis fields are valid",
        .zone.map_or_else(|| "never".to_owned(), |time| time.to_string()),
        .parent.map_or_else(|| "never".to_owned(), |time| time.to_string())
    )]
    ParentForkMismatch {
        /// The fork whose activation differs.
        fork: TempoHardfork,
        /// The Zone's activation timestamp, if scheduled.
        zone: Option<u64>,
        /// The parent's activation timestamp, if scheduled.
        parent: Option<u64>,
    },
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
    use serde_json::{Value, json};
    use tempo_chainspec::{
        constants::moderato::{MODERATO_T0_TIMESTAMP, MODERATO_T14_TIMESTAMP},
        spec::{DEV, MODERATO},
    };
    use test_case::test_case;
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

    type Mismatch = (TempoHardfork, Option<u64>, Option<u64>);

    fn fork_mismatch(error: ZoneChainSpecError) -> Mismatch {
        match error {
            ZoneChainSpecError::ParentForkMismatch { fork, zone, parent } => (fork, zone, parent),
            error => panic!("unexpected error: {error}"),
        }
    }

    /// Applies a custom L1 schedule (T0 to T11 at zero, T12 at 300) to a Zone genesis without
    /// Tempo fork fields except `field`. Returns the forks active at 299 and 300.
    #[test_case("t12Time", None => Ok((TempoHardfork::T11, TempoHardfork::T12)))]
    #[test_case("t12Time", Some(json!(300)) => Ok((TempoHardfork::T11, TempoHardfork::T12)))]
    #[test_case("t13Time", Some(Value::Null) => Ok((TempoHardfork::T11, TempoHardfork::T12)))]
    #[test_case("t12Time", Some(json!(500)) => Err((TempoHardfork::T12, Some(500), Some(300))))]
    #[test_case("t12Time", Some(Value::Null) => Err((TempoHardfork::T12, None, Some(300))))]
    #[test_case("t13Time", Some(json!(0)) => Err((TempoHardfork::T13, Some(0), None)))]
    // An invalid Tempo field fails the whole Tempo record, leaving every fork unscheduled.
    #[test_case("epochLength", Some(json!(0)) => Err((TempoHardfork::T0, None, Some(0))))]
    fn custom_parent_follows_l1_schedule(
        field: &str,
        value: Option<Value>,
    ) -> Result<(TempoHardfork, TempoHardfork), Mismatch> {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(31_318, 4).unwrap();
        for key in TempoHardfork::VARIANTS
            .iter()
            .filter_map(|fork| fork.genesis_key())
        {
            genesis.config.extra_fields.remove(key);
        }
        if let Some(value) = value {
            genesis.config.extra_fields.insert(field.into(), value);
        }
        let schedule = TempoHardfork::VARIANTS
            .iter()
            .copied()
            .filter(|&fork| fork != TempoHardfork::Genesis && fork <= TempoHardfork::T12)
            .map(|fork| (fork, if fork == TempoHardfork::T12 { 300 } else { 0 }));
        ZoneChainSpec::from_genesis(genesis)
            .unwrap()
            .with_l1_fork_schedule(schedule)
            .map(|zone| (zone.tempo_hardfork_at(299), zone.tempo_hardfork_at(300)))
            .map_err(fork_mismatch)
    }

    /// Builds a Moderato Zone whose genesis sets `field` to `value`, or omits it. Returns the
    /// forks active just before and at Moderato's T14.
    #[test_case("t14Time", Some(json!(MODERATO_T14_TIMESTAMP)) => Ok((TempoHardfork::T13, TempoHardfork::T14)))]
    #[test_case("t14Time", None => Ok((TempoHardfork::T13, TempoHardfork::T14)))]
    #[test_case("t15Time", Some(Value::Null) => Ok((TempoHardfork::T13, TempoHardfork::T14)))]
    #[test_case("t14Time", Some(Value::Null) => Err((TempoHardfork::T14, None, Some(MODERATO_T14_TIMESTAMP))))]
    #[test_case("t14Time", Some(json!(MODERATO_T14_TIMESTAMP + 1)) => Err((TempoHardfork::T14, Some(MODERATO_T14_TIMESTAMP + 1), Some(MODERATO_T14_TIMESTAMP))))]
    #[test_case("t15Time", Some(json!(0)) => Err((TempoHardfork::T15, Some(0), None)))]
    // An invalid Tempo field fails the whole Tempo record, leaving every fork unscheduled even
    // though the fork fields match the parent.
    #[test_case("epochLength", Some(json!(0)) => Err((TempoHardfork::T0, None, Some(MODERATO_T0_TIMESTAMP))))]
    fn public_parent_rejects_disagreeing_schedule(
        field: &str,
        value: Option<Value>,
    ) -> Result<(TempoHardfork, TempoHardfork), Mismatch> {
        let mut genesis = MODERATO.genesis().clone();
        genesis.config.chain_id = zone_chain_id(MODERATO.chain_id(), 7).unwrap();
        match value {
            Some(value) => genesis.config.extra_fields.insert(field.into(), value),
            None => genesis.config.extra_fields.remove(field),
        };
        ZoneChainSpec::from_genesis(genesis)
            .map(|zone| {
                (
                    zone.tempo_hardfork_at(MODERATO_T14_TIMESTAMP - 1),
                    zone.tempo_hardfork_at(MODERATO_T14_TIMESTAMP),
                )
            })
            .map_err(fork_mismatch)
    }
}
