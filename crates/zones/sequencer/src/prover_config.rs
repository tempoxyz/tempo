//! Remote prover routing by the hardfork active on the settlement chain.

use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::BlockHeader as _;
use alloy_provider::{DynProvider, Provider as _};
use alloy_rpc_types_eth::BlockNumberOrTag;
use eyre::{Context as _, Result, ensure};
use reth_metrics::metrics::Gauge;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{TempoHardforks, hardfork::TempoHardfork};
use zone_chainspec::ZoneChainSpec;
use zone_prover::attested_transport::RemoteProverConfig;

/// Readiness monitors endpoints for forks activating within 72 hours, inclusive.
const PROVER_UPGRADE_LOOKAHEAD_SECS: u64 = 72 * 60 * 60;
const PROVER_UPGRADE_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// One explicit hardfork-to-prover assignment, written as `T13=HOST:PORT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardforkProverAddress {
    /// L1 hardfork for which this prover is approved.
    pub hardfork: TempoHardfork,
    /// TCP endpoint of the immutable prover release.
    pub address: String,
}

impl FromStr for HardforkProverAddress {
    type Err = eyre::Report;

    fn from_str(value: &str) -> Result<Self> {
        let (fork, address) = value.split_once('=').ok_or_else(|| {
            eyre::eyre!("expected prover assignment HARDFORK=HOST:PORT, got {value:?}")
        })?;
        ensure!(
            !address.trim().is_empty(),
            "prover address must not be empty"
        );
        Ok(Self {
            hardfork: fork
                .parse()
                .map_err(|_| eyre::eyre!("unknown Tempo hardfork {fork:?}"))?,
            address: address.to_owned(),
        })
    }
}

/// Remote prover configuration. Fork routing requires an exact assignment, with no fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverAddresses(BTreeMap<TempoHardfork, RemoteProverConfig>);

impl ProverAddresses {
    /// Build authenticated endpoints, requiring an explicit policy for nonempty assignments and
    /// rejecting duplicate assignments.
    pub fn new(
        assignments: Vec<HardforkProverAddress>,
        policy: Option<&[u8]>,
    ) -> Result<Option<Self>> {
        if assignments.is_empty() {
            return Ok(None);
        }
        let policy = policy.ok_or_else(|| {
            eyre::eyre!(
                "remote proving requires --sequencer.prover-attestation-policy; this Tempo release does not expose the verifier's PCR policy"
            )
        })?;
        let mut addresses = BTreeMap::new();
        for assignment in assignments {
            let HardforkProverAddress { hardfork, address } = assignment;
            ensure!(
                !address.trim().is_empty(),
                "prover address must not be empty"
            );
            let prev = addresses.insert(
                hardfork,
                RemoteProverConfig::from_policy_json(address, policy)?,
            );
            ensure!(prev.is_none(), "duplicate prover address for {hardfork}");
        }
        Ok(Some(Self(addresses)))
    }

    /// Observe the schedule every minute, including while the node is idle or a standby.
    /// Run for the node's lifetime, independently of individual prover workers.
    pub async fn monitor_upgrade_readiness(&self, chain_spec: Arc<ZoneChainSpec>) {
        self.monitor_upgrade_readiness_with_gauge(
            chain_spec,
            crate::metrics::ProverMetrics::default().missing_hardfork_prover,
        )
        .await;
    }

    pub(crate) async fn resolve(
        &self,
        provider: &DynProvider<TempoNetwork>,
        chain_spec: &impl TempoHardforks,
    ) -> Result<(&RemoteProverConfig, TempoHardfork)> {
        let hardfork = active_l1_hardfork(provider, chain_spec).await?;
        Ok((self.config_for(hardfork)?, hardfork))
    }

    fn config_for(&self, hardfork: TempoHardfork) -> Result<&RemoteProverConfig> {
        self.0
            .get(&hardfork)
            .ok_or_else(|| eyre::eyre!("no prover configured for active L1 hardfork {hardfork}"))
    }

    fn missing_upcoming_hardfork(
        &self,
        chain_spec: &impl TempoHardforks,
        active: TempoHardfork,
        now: u64,
    ) -> Option<(TempoHardfork, u64)> {
        let deadline = now.saturating_add(PROVER_UPGRADE_LOOKAHEAD_SECS);
        TempoHardfork::VARIANTS.iter().copied().find_map(|fork| {
            let activation = chain_spec.tempo_fork_activation(fork).as_timestamp()?;
            (fork > active && activation <= deadline && !self.0.contains_key(&fork))
                .then_some((fork, activation))
        })
    }

    async fn monitor_upgrade_readiness_with_gauge(
        &self,
        chain_spec: Arc<ZoneChainSpec>,
        gauge: Gauge,
    ) {
        let mut interval = tokio::time::interval(PROVER_UPGRADE_CHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(now) => {
                    self.record_upgrade_readiness(chain_spec.as_ref(), now.as_secs(), &gauge)
                }
                Err(error) => {
                    tracing::warn!(%error, "Cannot check upcoming prover hardforks: system clock precedes Unix epoch")
                }
            }
        }
    }

    fn record_upgrade_readiness(&self, chain_spec: &impl TempoHardforks, now: u64, gauge: &Gauge) {
        let active = chain_spec.tempo_hardfork_at(now);
        let missing = !self.0.contains_key(&active)
            || self
                .missing_upcoming_hardfork(chain_spec, active, now)
                .is_some();
        gauge.set(if missing { 1.0 } else { 0.0 });
    }
}

/// Resolve the active L1 fork from its latest block timestamp and the Zone chainspec.
///
/// The local clock can pass an activation while L1 is stalled, so it cannot select a prover.
pub(crate) async fn active_l1_hardfork(
    provider: &DynProvider<TempoNetwork>,
    chain_spec: &impl TempoHardforks,
) -> Result<TempoHardfork> {
    let header = provider
        .get_header_by_number(BlockNumberOrTag::Latest)
        .await
        .wrap_err("failed reading the latest Tempo L1 header")?
        .ok_or_else(|| eyre::eyre!("latest Tempo L1 header is unavailable"))?;
    Ok(chain_spec.tempo_hardfork_at(header.timestamp()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header as ConsensusHeader;
    use alloy_provider::ProviderBuilder;
    use alloy_rpc_types_eth::Header as RpcHeader;
    use alloy_transport::mock::Asserter;
    use tempo_alloy::rpc::TempoHeaderResponse;
    use tempo_primitives::TempoHeader;
    use zone_chainspec::test_utils::set_tempo_fork;

    const TRANSITIONS: [(TempoHardfork, TempoHardfork); 2] = [
        (TempoHardfork::T12, TempoHardfork::T13),
        (TempoHardfork::T13, TempoHardfork::T14),
    ];

    fn policy() -> Vec<u8> {
        let pcr = "11".repeat(48);
        serde_json::to_vec(&serde_json::json!({"pcrs":{"0":[&pcr],"1":[&pcr],"2":[&pcr]}})).unwrap()
    }

    fn mock_l1_header(timestamp: u64) -> serde_json::Value {
        let header = TempoHeaderResponse {
            inner: RpcHeader {
                hash: Default::default(),
                inner: TempoHeader {
                    inner: ConsensusHeader {
                        timestamp,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                total_difficulty: None,
                size: None,
            },
            timestamp_millis: 0,
        };
        serde_json::to_value(header).unwrap()
    }

    #[tokio::test]
    async fn active_fork_uses_latest_l1_block_timestamp() {
        for (before, after) in TRANSITIONS {
            let asserter = Asserter::new();
            asserter.push_success(&mock_l1_header(999));
            asserter.push_success(&mock_l1_header(1_000));
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(asserter)
                .erased();
            assert_eq!(
                active_l1_hardfork(&provider, &scheduled(after, 1_000))
                    .await
                    .unwrap(),
                before
            );
            assert_eq!(
                active_l1_hardfork(&provider, &scheduled(after, 1_000))
                    .await
                    .unwrap(),
                after
            );
        }
    }

    #[derive(Default)]
    struct RecordedGauge(std::sync::Mutex<Vec<f64>>);

    impl reth_metrics::metrics::GaugeFn for RecordedGauge {
        fn increment(&self, _: f64) {
            panic!("readiness must set the gauge, not increment it");
        }

        fn decrement(&self, _: f64) {
            panic!("readiness must set the gauge, not decrement it");
        }

        fn set(&self, value: f64) {
            self.0.lock().unwrap().push(value);
        }
    }

    #[test]
    fn metric_detects_entry_into_the_window_and_remains_set_after_activation() {
        for (before, after) in TRANSITIONS {
            let activation = 400_000;
            let spec = scheduled(after, activation);
            let addresses = ProverAddresses::new(
                vec![format!("{before}=old:5000").parse().unwrap()],
                Some(&policy()),
            )
            .unwrap()
            .unwrap();
            let recorded = Arc::new(RecordedGauge::default());
            let gauge = Gauge::from_arc(recorded.clone());
            for now in [
                activation - PROVER_UPGRADE_LOOKAHEAD_SECS - 1,
                activation - PROVER_UPGRADE_LOOKAHEAD_SECS,
                activation - 1,
                activation,
            ] {
                addresses.record_upgrade_readiness(&spec, now, &gauge);
            }
            routed(before, after).record_upgrade_readiness(&spec, activation, &gauge);
            assert_eq!(*recorded.0.lock().unwrap(), vec![0.0, 1.0, 1.0, 1.0, 0.0]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_is_refreshed_every_minute_without_prover_jobs() {
        for (before, after) in TRANSITIONS {
            let addresses = routed(before, after);
            let chain_spec = Arc::new(ZoneChainSpec {
                inner: Arc::new(scheduled(after, u64::MAX)),
            });
            let recorded = Arc::new(RecordedGauge::default());
            let gauge = Gauge::from_arc(recorded.clone());
            let task = tokio::spawn(async move {
                addresses
                    .monitor_upgrade_readiness_with_gauge(chain_spec, gauge)
                    .await;
            });
            tokio::task::yield_now().await;
            assert_eq!(*recorded.0.lock().unwrap(), vec![0.0]);
            tokio::time::advance(Duration::from_secs(59)).await;
            tokio::task::yield_now().await;
            assert_eq!(recorded.0.lock().unwrap().len(), 1);
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(*recorded.0.lock().unwrap(), vec![0.0, 0.0]);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    }

    fn scheduled(fork: TempoHardfork, timestamp: u64) -> tempo_chainspec::TempoChainSpec {
        let mut genesis = tempo_chainspec::spec::DEV.inner.genesis.clone();
        set_tempo_fork(&mut genesis, fork, timestamp);
        tempo_chainspec::TempoChainSpec::from_genesis(genesis)
    }

    fn routed(before: TempoHardfork, after: TempoHardfork) -> ProverAddresses {
        ProverAddresses::new(
            vec![
                format!("{before}=old:5000").parse().unwrap(),
                format!("{after}=new:5000").parse().unwrap(),
            ],
            Some(&policy()),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn remote_assignments_require_an_attestation_policy() {
        assert!(ProverAddresses::new(Vec::new(), None).unwrap().is_none());
        for &hardfork in TempoHardfork::VARIANTS {
            let error = ProverAddresses::new(
                vec![HardforkProverAddress {
                    hardfork,
                    address: "prover:5000".to_owned(),
                }],
                None,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("--sequencer.prover-attestation-policy")
            );
        }
    }

    #[test]
    fn assignments_are_exact_and_unambiguous() {
        for (before, after) in TRANSITIONS {
            let config = routed(before, after);
            assert_eq!(config.config_for(before).unwrap().address(), "old:5000");
            assert_eq!(config.config_for(after).unwrap().address(), "new:5000");
            assert!(config.config_for(TempoHardfork::T11).is_err());
            assert!(
                ProverAddresses::new(
                    vec![format!("{before}=old:5000").parse().unwrap()],
                    Some(b"{}"),
                )
                .is_err()
            );
            assert!(
                ProverAddresses::new(
                    vec![
                        format!("{after}=a:1").parse().unwrap(),
                        format!("{after}=b:2").parse().unwrap()
                    ],
                    Some(&policy()),
                )
                .is_err()
            );
            for invalid in [
                after.to_string(),
                format!("{after}="),
                format!("{after}= "),
                "unknown=a:1".to_owned(),
            ] {
                assert!(invalid.parse::<HardforkProverAddress>().is_err());
            }
        }
    }

    #[tokio::test]
    async fn missing_fork_and_rpc_failure_never_fall_back() {
        for (before, after) in TRANSITIONS {
            let asserter = Asserter::new();
            asserter.push_success(&mock_l1_header(100_001));
            asserter.push_failure_msg("L1 unavailable");
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(asserter.clone())
                .erased();
            let config = ProverAddresses::new(
                vec![format!("{before}=old:5000").parse().unwrap()],
                Some(&policy()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                config
                    .resolve(&provider, &scheduled(after, 100_001))
                    .await
                    .unwrap_err()
                    .to_string(),
                format!("no prover configured for active L1 hardfork {after}")
            );
            assert!(
                config
                    .resolve(&provider, &scheduled(after, 100_001))
                    .await
                    .is_err()
            );
            assert!(asserter.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn routing_follows_activation_and_reorg_without_caching() {
        for (before, after) in TRANSITIONS {
            let asserter = Asserter::new();
            for timestamp in [999, 1_000, 999] {
                asserter.push_success(&mock_l1_header(timestamp));
            }
            asserter.push_failure_msg("L1 unavailable");
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(asserter)
                .erased();
            let config = routed(before, after);
            let spec = scheduled(after, 1_000);
            for (address, fork) in [
                ("old:5000", before),
                ("new:5000", after),
                ("old:5000", before),
            ] {
                let (config, selected_fork) = config.resolve(&provider, &spec).await.unwrap();
                assert_eq!((config.address(), selected_fork), (address, fork));
            }
            assert!(config.resolve(&provider, &spec).await.is_err());
        }
    }
}
