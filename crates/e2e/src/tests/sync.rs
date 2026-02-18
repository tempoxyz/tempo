//! Tests for syncing nodes from scratch.
//!
//! These tests are similar to the tests in [`crate::tests::restart`], but
//! assume that the node has never been run but been given a synced execution
//! layer database./// Runs a validator restart test with the given configuration

use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockNumReader as _;
use tracing::info;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced]
fn joins_from_snapshot() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    // Create a verifier that we will never start. It just the private keys
    // we desire.
    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
        .connect_execution_layer_nodes(true)
        .epoch_length(epoch_length);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        // The validator that will donate its address to the snapshot syncing
        // validator.
        let donor = {
            let idx = validators
                .iter()
                .position(|node| node.consensus_config().share.is_none())
                .expect("at least one node must be a verifier, i.e. not have a share");
            validators.remove(idx)
        };

        assert!(
            validators
                .iter()
                .all(|node| node.consensus_config().share.is_some()),
            "must have removed the one non-signer node; must be left with only signers",
        );
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // The validator that will receive the donor's addresses to simulate
        // a late start.
        let mut receiver = validators.remove(validators.len() - 1);

        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        // First, remove the last actual validator (index 3 = last of 4 signers).
        let receiver_index = 3u64;
        let receipt = execution_runtime
            .change_validator_status(http_url.clone(), receiver_index, false)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "changeValidatorStatus call returned receipt"
        );

        // Then wait until the validator has left the committee.
        wait_for_participants(&context, 3).await;

        info!("validator left the committee");

        // Then, add the sacrificial validator without starting it(!).
        let receipt = execution_runtime
            .add_validator(
                http_url.clone(),
                donor.chain_address,
                donor.public_key().clone(),
                donor.network_address,
            )
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "addValidator call returned receipt"
        );

        // Wait until it was added to the committee
        wait_for_participants(&context, 4).await;

        info!("new validator was added to the committee, but not started");

        receiver.stop().await;
        let last_epoch_before_stop = latest_epoch_of_validator(&context, &receiver.uid);
        info!(%last_epoch_before_stop, "stopped the original validator");

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        receiver.uid = donor.uid;
        receiver.public_key = donor.public_key;
        receiver.consensus_config = donor.consensus_config;
        receiver.network_address = donor.network_address;
        receiver.chain_address = donor.chain_address;
        receiver.start(&context).await;

        info!(
            uid = %receiver.uid,
            "started the validator with a changed identity",
        );

        loop {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();
            let mut validators_at_epoch = 0;

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                // Check if this is a height metric
                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let epoch = value.parse::<u64>().unwrap();

                    assert!(
                        epoch < last_epoch_before_stop + 4,
                        "network advanced 4 epochs before without the new \
                        validator catching up; there is likely a bug",
                    );

                    if epoch > last_epoch_before_stop {
                        validators_at_epoch += 1;
                    }

                    if metric.contains(&receiver.uid) {
                        // -1 to account for stopping on boundaries.
                        assert!(
                            epoch >= last_epoch_before_stop.saturating_sub(1),
                            "when starting from snapshot, older epochs must never \
                            had consensus engines running"
                        );
                    }
                }
            }
            if validators_at_epoch == 4 {
                break;
            }
        }
    });
}

#[test_traced]
fn can_restart_after_joining_from_snapshot() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    // Create a verifier that we will never start. It just the private keys
    // we desire.
    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
        .epoch_length(epoch_length)
        .connect_execution_layer_nodes(true);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        // The validator that will donate its address to the snapshot syncing
        // validator.
        let donor = {
            let idx = validators
                .iter()
                .position(|node| node.consensus_config().share.is_none())
                .expect("at least one node must be a verifier, i.e. not have a share");
            validators.remove(idx)
        };

        assert!(
            validators
                .iter()
                .all(|node| node.consensus_config().share.is_some()),
            "must have removed the one non-signer node; must be left with only signers",
        );
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // The validator that will receive the donor's addresses to simulate
        // a late start.
        let mut receiver = validators.remove(validators.len() - 1);

        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        // First, remove the last actual validator (index 3 = last of 4 signers).
        let receiver_index = 3u64;
        let receipt = execution_runtime
            .change_validator_status(http_url.clone(), receiver_index, false)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "changeValidatorStatus call returned receipt"
        );

        // Then wait until the validator has left the committee.
        wait_for_participants(&context, 3).await;

        info!("validator left the committee");

        // Then, add the sacrificial validator without starting it(!).
        let receipt = execution_runtime
            .add_validator(
                http_url.clone(),
                donor.chain_address,
                donor.public_key().clone(),
                donor.network_address,
            )
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "addValidator call returned receipt"
        );

        // Wait until it was added to the committee
        wait_for_participants(&context, 4).await;

        info!("new validator was added to the committee, but not started");

        receiver.stop().await;

        let last_epoch_before_stop = latest_epoch_of_validator(&context, &receiver.uid);

        info!(
            %last_epoch_before_stop,
            id = %receiver.uid,
            "stopped the original validator",
        );

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        receiver.uid = donor.uid;
        receiver.public_key = donor.public_key;
        receiver.consensus_config = donor.consensus_config;
        receiver.network_address = donor.network_address;
        receiver.chain_address = donor.chain_address;
        receiver.start(&context).await;

        info!(
            uid = %receiver.uid,
            "started the validator with a changed identity",
        );

        loop {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();
            let mut validators_at_epoch = 0;

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let epoch = value.parse::<u64>().unwrap();

                    assert!(
                        epoch < last_epoch_before_stop + 4,
                        "network advanced 4 epochs before without the new \
                        validator catching up; there is likely a bug",
                    );

                    if epoch > last_epoch_before_stop {
                        validators_at_epoch += 1;
                    }

                    if metric.contains(&receiver.uid) {
                        // -1 to account for stopping on boundaries.
                        assert!(
                            epoch >= last_epoch_before_stop.saturating_sub(1),
                            "when starting from snapshot, older epochs must never \
                            had consensus engines running"
                        );
                    }
                }
            }

            if validators_at_epoch == 4 {
                break;
            }
        }

        // Restart the node. This ensures that it's state is still sound after
        // doing a snapshot sync.
        receiver.stop().await;

        let network_head = validators[0]
            .execution_provider()
            .best_block_number()
            .unwrap();

        receiver.start(&context).await;

        info!(
            network_head,
            "restarting the node and waiting for it to catch up"
        );

        'progress: loop {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.contains(&receiver.uid)
                    && metric.ends_with("_marshal_processed_height")
                    && value.parse::<u64>().unwrap() > network_head
                {
                    break 'progress;
                }
            }
        }
    });
}

async fn wait_for_participants(context: &Context, target: u32) {
    loop {
        let metrics = context.encode();

        for line in metrics.lines() {
            if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                continue;
            }

            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();

            // Check if this is a height metric
            if metric.ends_with("_epoch_manager_latest_participants")
                && value.parse::<u32>().unwrap() == target
            {
                return;
            }
        }
        context.sleep(Duration::from_secs(1)).await;
    }
}

fn latest_epoch_of_validator(context: &Context, id: &str) -> u64 {
    let metrics = context.encode();

    for line in metrics.lines() {
        if !line.starts_with(CONSENSUS_NODE_PREFIX) {
            continue;
        }

        let mut parts = line.split_whitespace();
        let metric = parts.next().unwrap();
        let value = parts.next().unwrap();

        if metric.ends_with("_epoch_manager_latest_epoch") && metric.contains(id) {
            return value.parse::<u64>().unwrap();
        }
    }

    panic!("validator had no entry for latest epoch");
}
