//! Resolve and persist the parent L1 fork schedule for Zone genesis.

use alloy::{consensus::BlockHeader as _, genesis::ChainConfig, providers::Provider};
use alloy_eips::BlockNumberOrTag;
use eyre::{WrapErr as _, ensure, eyre};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use tempo_alloy::{TempoNetwork, rpc::ForkSchedule};
use tempo_chainspec::{cli::TempoHardforkArgs, hardfork::TempoHardfork};
use tokio::time::timeout;
use zone_primitives::constants::decode_l1_chain_id;

#[derive(Debug)]
pub(crate) struct ResolvedForks {
    parent_chain_id: Option<u64>,
    activations: BTreeMap<TempoHardfork, u64>,
}

impl ResolvedForks {
    fn from_schedule(
        parent_chain_id: u64,
        timestamp: u64,
        schedule: ForkSchedule,
    ) -> eyre::Result<Self> {
        let active = schedule
            .active
            .parse::<TempoHardfork>()
            .wrap_err("L1 reports an unsupported active Tempo fork; update the zone binary")?;
        let mut activations = BTreeMap::new();
        for entry in schedule.schedule {
            let fork = entry.name.parse::<TempoHardfork>().wrap_err_with(|| {
                format!(
                    "L1 schedules unsupported Tempo fork {}; update the zone binary",
                    entry.name
                )
            })?;
            ensure!(
                fork != TempoHardfork::Genesis,
                "L1 fork schedule must exclude Genesis"
            );
            ensure!(
                entry.active == (entry.activation_time <= timestamp),
                "L1 fork activation flags do not match the sampled head; retry genesis generation"
            );
            ensure!(
                activations.insert(fork, entry.activation_time).is_none(),
                "duplicate Tempo fork {} in L1 schedule",
                entry.name
            );
        }
        ensure!(
            activations.values().is_sorted(),
            "L1 fork activation times are out of order"
        );
        let forks = Self {
            parent_chain_id: Some(parent_chain_id),
            activations,
        };
        ensure!(
            forks.hardfork_at(timestamp).ok() == Some(active),
            "L1 fork schedule does not match the sampled head; retry genesis generation"
        );
        Ok(forks)
    }

    pub(crate) fn offline(args: &TempoHardforkArgs) -> eyre::Result<Self> {
        ensure!(
            args.hardfork.is_some(),
            "offline genesis generation requires an explicit --hardfork"
        );
        let activations = TempoHardfork::VARIANTS
            .iter()
            .copied()
            .filter(|&fork| fork != TempoHardfork::Genesis)
            .filter_map(|fork| args.fork_time(fork).map(|time| (fork, time)))
            .collect::<BTreeMap<_, _>>();
        let forks = Self {
            parent_chain_id: None,
            activations,
        };
        forks
            .hardfork_at(0)
            .wrap_err("offline genesis must enable at least T0 at timestamp zero")?;
        Ok(forks)
    }

    pub(crate) fn hardfork_at(&self, timestamp: u64) -> eyre::Result<TempoHardfork> {
        self.activations
            .iter()
            .rev()
            .find_map(|(&fork, &time)| (time <= timestamp).then_some(fork))
            .ok_or_else(|| eyre!("no Tempo fork is active at genesis anchor timestamp {timestamp}"))
    }

    pub(crate) fn validate_chain_id(&self, chain_id: u64) -> eyre::Result<()> {
        if let Some(parent_chain_id) = self.parent_chain_id {
            let expected = decode_l1_chain_id(chain_id)?;
            ensure!(
                parent_chain_id == expected,
                "L1 RPC chain ID {parent_chain_id} does not match zone parent chain ID {expected}"
            );
        }
        Ok(())
    }

    pub(crate) fn write_to(&self, config: &mut ChainConfig) {
        for &fork in TempoHardfork::VARIANTS {
            if let Some(key) = fork.genesis_key() {
                let value = self
                    .activations
                    .get(&fork)
                    .map_or(Value::Null, |&time| Value::from(time));
                config.extra_fields.insert(key.to_owned(), value);
            }
        }
    }
}

pub(crate) async fn resolve_l1_forks(
    provider: &impl Provider<TempoNetwork>,
    args: &TempoHardforkArgs,
) -> eyre::Result<ResolvedForks> {
    ensure!(
        *args == TempoHardforkArgs::default(),
        "RPC-derived fork schedules cannot be combined with --hardfork or --t*-time overrides; use explicit offline generation instead"
    );
    timeout(Duration::from_secs(30), async {
        let parent_chain_id = provider
            .get_chain_id()
            .await
            .wrap_err("failed reading L1 chain ID")?;
        let schedule = provider
            .raw_request("tempo_forkSchedule".into(), ())
            .await
            .wrap_err("failed reading tempo_forkSchedule; no implicit fork defaults are allowed")?;
        let header = provider
            .get_header_by_number(BlockNumberOrTag::Latest)
            .await
            .wrap_err("failed reading L1 head timestamp")?
            .ok_or_else(|| eyre!("L1 head header not found"))?;
        ResolvedForks::from_schedule(parent_chain_id, header.timestamp(), schedule)
    })
    .await
    .wrap_err("timed out resolving L1 fork schedule")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{providers::ProviderBuilder, transports::mock::Asserter};
    use serde_json::json;
    use tempo_alloy::rpc::ForkInfo;

    fn schedule() -> ForkSchedule {
        serde_json::from_value(json!({ "active": "T11", "schedule": [
            { "name": "T0", "activationTime": 10, "active": true },
            { "name": "T11", "activationTime": 20, "active": true },
            { "name": "T12", "activationTime": 200, "active": false }
        ] }))
        .unwrap()
    }

    #[tokio::test]
    async fn rpc_fork_resolution_fails_closed() {
        let mut unknown_active = schedule();
        unknown_active.active = "T999".to_owned();
        assert!(ResolvedForks::from_schedule(4217, 100, unknown_active).is_err());
        let mut unknown_future = schedule();
        unknown_future.schedule.push(ForkInfo {
            name: "T999".to_owned(),
            activation_time: 300,
            active: false,
            fork_id: None,
        });
        assert!(ResolvedForks::from_schedule(4217, 100, unknown_future).is_err());
        let mut duplicate = schedule();
        duplicate.schedule.push(duplicate.schedule[1].clone());
        assert!(ResolvedForks::from_schedule(4217, 100, duplicate).is_err());
        let mut out_of_order = schedule();
        out_of_order.schedule[2].activation_time = 15;
        out_of_order.schedule[2].active = true;
        assert!(ResolvedForks::from_schedule(4217, 100, out_of_order).is_err());
        assert!(ResolvedForks::from_schedule(4217, 9, schedule()).is_err());
        assert!(ResolvedForks::from_schedule(4217, 200, schedule()).is_err());
        let empty = ForkSchedule {
            active: "T0".to_owned(),
            schedule: Vec::new(),
        };
        assert!(ResolvedForks::from_schedule(4217, 100, empty).is_err());

        let asserter = Asserter::new();
        asserter.push_success(&"0x1079");
        asserter.push_failure_msg("tempo_forkSchedule unavailable");
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter);
        assert!(
            resolve_l1_forks(&provider, &TempoHardforkArgs::default())
                .await
                .is_err()
        );
        let args = TempoHardforkArgs {
            hardfork: Some(TempoHardfork::T11),
            ..Default::default()
        };
        assert!(resolve_l1_forks(&provider, &args).await.is_err());
    }
}
