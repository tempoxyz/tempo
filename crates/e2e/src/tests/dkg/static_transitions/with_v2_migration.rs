use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
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
fn two_nodes_transitions_once() {
    AssertTransition {
        how_many_signers: 2,
        epoch_length: 10,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn two_nodes_transitions_twice() {
    AssertTransition {
        how_many_signers: 2,
        epoch_length: 10,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn four_nodes_transitions_once() {
    AssertTransition {
        how_many_signers: 4,
        epoch_length: 20,
        how_many_epochs: 1,
    }
    .run()
}

#[test_traced]
fn four_nodes_transitions_twice() {
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
            tracing::debug!(
                block.number = execution_runtime
                    .initialize_if_migrated(http_url.clone())
                    .await
                    .unwrap()
                    .block_number,
                "initializeIfMigrated returned receipt",
            );

            let mut target_epoch = 0;
            while target_epoch < how_many_epochs {
                target_epoch += 1;
                wait_for_validators_to_reach_epoch(&context, target_epoch, how_many_signers).await;

                for line in context.encode().lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();
                    if metric.ends_with("_dkg_manager_read_players_from_v1_contract_total") {
                        assert!(value.parse::<u64>().unwrap() == 0);
                    }
                    if metric.ends_with("_dkg_manager_read_players_from_v2_contract_total") {
                        assert!(value.parse::<u64>().unwrap() > 0);
                    }
                    if metric.ends_with("_dkg_manager_read_re_dkg_from_v1_contract_total") {
                        assert!(value.parse::<u64>().unwrap() == 0);
                    }
                    if metric.ends_with("_dkg_manager_read_re_dkg_from_v2_contract_total") {
                        assert!(value.parse::<u64>().unwrap() > 0);
                    }
                    if metric.ends_with("_dkg_manager_syncing_players") {
                        assert!(value.parse::<u64>().unwrap() == 0);
                    }
                }
            }
        })
    }
}
