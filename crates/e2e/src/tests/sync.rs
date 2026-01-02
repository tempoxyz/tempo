//! Tests for syncing nodes from scratch.
//!
//! These tests are similar to the tests in [`crate::tests::restart`], but
//! assume that the node has never been run but been given a synced execution
//! layer database./// Runs a validator restart test with the given configuration

use std::{net::SocketAddr, time::Duration};

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, execution_runtime::validator, setup_validators};

#[test_traced]
fn joins_from_snapshot() {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
        .epoch_length(20);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, execution_runtime) =
            setup_validators(context.clone(), setup.clone()).await;

        let mut synced_validator = {
            let idx = validators
                .iter()
                .position(|node| node.consensus_config().share.is_none())
                .expect("at least one node must be a verifier, i.e. not have a share");
            validators.remove(idx)
        };
        join_all(validators.iter_mut().map(|v| v.start())).await;

        // We will send an arbitrary node of the initial validator set the smart
        // contract call.
        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        let receipt = execution_runtime
            // XXX: The addValidator call above adding the initial set
            // adds validators 0..validators.len(). So this is the last of
            // the validators
            .change_validator_status(
                http_url.clone(),
                validator(validators.len() as u32 - 1),
                false,
            )
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "changeValidatorStatus call returned receipt"
        );
        tracing::info!(
            "validator was removed from the contract; waiting for it to leave the network"
        );

        'network_update: loop {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_epoch_manager_latest_participants") {
                    let value = value.parse::<u64>().unwrap();
                    if value < 4 {
                        break 'network_update;
                    }
                }
            }
        }

        let latest_epoch: u64 = {
            let metrics = context.encode();

            let mut latest_epoch = None;
            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    let latest_epoch = latest_epoch.get_or_insert(value);
                    *latest_epoch = (*latest_epoch).max(value);
                }
            }
            latest_epoch.unwrap()
        };

        let mut stopped = validators.pop().unwrap();
        stopped.stop().await;

        // Now add and start the new validator.
        let receipt = execution_runtime
            .add_validator(
                http_url.clone(),
                validator(validators.len() as u32 + 1),
                synced_validator.public_key().clone(),
                SocketAddr::from(([127, 0, 0, 1], (validators.len() + 2) as u16)),
            )
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "addValidator call returned receipt"
        );

        tracing::debug!("copying over stopped validator to new validator");
        synced_validator.execution_node_datadir = stopped.execution_node_datadir.clone();
        let _synced_validator = synced_validator.start().await;
        tracing::info!("new validator was started");

        // Now wait until all validators have progressed at least 1 epoch
        loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();
            let mut how_many = 0;

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    how_many += (value > latest_epoch) as u32;
                }
            }
            // 3 from the initial set + the synced validator.
            if how_many >= 4 {
                break;
            }
        }
    });
}
