use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_consensus::types::{Epocher, FixedEpocher, Height};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;

use crate::{
    CONSENSUS_NODE_PREFIX, Setup, setup_validators,
    tests::dkg::common::wait_for_validators_to_reach_epoch,
};

#[test_traced]
fn single_node_transitions_once() {
    AssertTransition {
        how_many_signers: 1,
        epoch_length: 10,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn single_node_transitions_twice() {
    AssertTransition {
        how_many_signers: 1,
        epoch_length: 10,
        how_many_epochs: 2,
    }
    .run()
}

#[test_traced]
fn two_nodes_transition_once() {
    AssertTransition {
        how_many_signers: 2,
        epoch_length: 10,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn two_nodes_transition_twice() {
    AssertTransition {
        how_many_signers: 2,
        epoch_length: 10,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn four_nodes_transition_once() {
    AssertTransition {
        how_many_signers: 4,
        epoch_length: 20,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn four_nodes_transition_twice() {
    AssertTransition {
        how_many_signers: 4,
        epoch_length: 20,
        how_many_epochs: 2,
    }
    .run()
}

struct AssertTransition {
    how_many_signers: u32,
    epoch_length: u64,
    how_many_epochs: u64,
}

impl AssertTransition {
    fn run(self) {
        let Self {
            how_many_signers,
            epoch_length,
            how_many_epochs,
        } = self;
        let _ = tempo_eyre::install();
        let setup = Setup::new()
            .how_many_signers(how_many_signers)
            .epoch_length(epoch_length);

        let executor = Runner::from(Config::default().with_seed(setup.seed));

        executor.start(|mut context| async move {
            // HACK: Sleep 1 second to ensure the deterministic runtime returns
            // .current().epoch_millis() > 1000.
            context.sleep(Duration::from_secs(1)).await;

            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            let http_url = validators[0]
                .execution()
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse::<Url>()
                .unwrap();

            for i in 0..how_many_signers {
                tracing::debug!(
                    block.number = execution_runtime
                        .migrate_validator(http_url.clone(), i as u64)
                        .await
                        .unwrap()
                        .block_number,
                    "migrateValidator returned receipt",
                );
            }
            let initialization_height = execution_runtime
                .initialize_if_migrated(http_url.clone())
                .await
                .unwrap()
                .block_number
                .unwrap();

            let epoch_strat = FixedEpocher::new(NZU64!(epoch_length));
            let info = epoch_strat
                .containing(Height::new(initialization_height))
                .unwrap();
            let initialization_epoch = info.epoch();
            tracing::debug!(
                initialization_height,
                %initialization_epoch,
                "initializeIfMigrated completed",
            );

            // The epoch at which we start checking nodes for transitions.
            //
            // If the migration completed in epoch 0, we need to wait for
            // all nodes to enter epoch 1 before their metrics make sense.
            let start_epoch = if info.last().get() == initialization_height {
                initialization_epoch.next().next()
            } else {
                initialization_epoch.next()
            }
            .get();
            let mut epoch_count = 0;
            while epoch_count < how_many_epochs {
                tracing::error!("waiting for epoch {}", start_epoch + epoch_count);
                wait_for_validators_to_reach_epoch(
                    &context,
                    start_epoch + epoch_count,
                    how_many_signers,
                )
                .await;

                for line in context.encode().lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();
                    if metric.ends_with("_dkg_manager_read_players_from_v1_contract_total") {
                        assert_eq!(
                            initialization_epoch.get(),
                            value.parse::<u64>().unwrap(),
                            "v1 contract must only have been read for however \
                            many epochs it took to initialize the v2 contract"
                        );
                    }
                    if metric.ends_with("_dkg_manager_read_players_from_v2_contract_total") {
                        assert!(value.parse::<u64>().unwrap() > 0);
                    }
                    if metric.ends_with("_dkg_manager_read_re_dkg_epoch_from_v1_contract_total") {
                        assert_eq!(
                            initialization_epoch.get(),
                            value.parse::<u64>().unwrap(),
                            "v1 contract must only have been read for however \
                            many epochs it took to initialize the v2 contract"
                        );
                    }
                    if metric.ends_with("_dkg_manager_read_re_dkg_epoch_from_v2_contract_total") {
                        assert!(value.parse::<u64>().unwrap() > 0);
                    }
                    if metric.ends_with("_dkg_manager_syncing_players") {
                        assert_eq!(
                            0,
                            value.parse::<u64>().unwrap(),
                            "once migrated, the node should no longer consider syncing players",
                        );
                    }
                }
                epoch_count += 1;
            }
        })
    }
}
