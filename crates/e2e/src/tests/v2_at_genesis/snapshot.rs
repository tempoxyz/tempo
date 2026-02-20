//! Tests for syncing nodes from scratch.
//!
//! These tests are similar to the tests in [`crate::tests::restart`], but
//! assume that the node has never been run but been given a synced execution
//! layer database./// Runs a validator restart test with the given configuration

use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use reth_ethereum::provider::BlockNumReader as _;
use tracing::info;

use crate::{
    CONSENSUS_NODE_PREFIX, Setup, setup_validators,
    tests::v2_at_genesis::dkg::common::wait_for_outcome,
};

/// This is a lengthy test. First, a validator needs to be run for a sufficiently
/// long time to populate its database. Then, a new validator is rotated in
/// by taking the replaced validator's database. This simulates starting from
/// a snapshot.
#[test_traced]
fn joins_from_snapshot() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    // Create a verifier that we will never start. It just the private keys
    // we desire.
    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
        .t2_time(0)
        .connect_execution_layer_nodes(true)
        .epoch_length(epoch_length);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        // The replacement validator that will start later.
        let mut replacement = {
            let idx = validators
                .iter()
                .position(|node| node.consensus_config().share.is_none())
                .expect("at least one node must be a verifier, i.e. not have a share");
            validators.remove(idx)
        };
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // The validator that will donate it its database to the replacement.
        let mut donor = validators.pop().unwrap();

        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        // Validator setup generated 2 different addresses for both validators.
        // Make them the same so that ValidatorConfigV2.rotateValidator knows
        // which one to target.
        replacement.chain_address = donor.chain_address;
        let receipt = execution_runtime
            .rotate_validator(http_url, &replacement)
            .await
            .unwrap();

        let rotate_height = Height::new(receipt.block_number.unwrap());
        tracing::debug!(
            block.height = %rotate_height,
            "validatorConfigV2.rotateValidator executed",
        );

        // Wait for the next DKG outcome - unless rotate_height is on a boundary.
        // Then wait one more epoch.
        let epoch_strat = FixedEpocher::new(NZU64!(epoch_length));
        let info = epoch_strat.containing(rotate_height).unwrap();
        let target_epoch = if info.last() == rotate_height {
            info.epoch().next()
        } else {
            info.epoch()
        };

        let outcome_start_rotation =
            wait_for_outcome(&context, &validators, target_epoch.get(), epoch_length).await;

        assert!(
            outcome_start_rotation
                .players()
                .position(&donor.public_key())
                .is_some()
        );
        assert!(
            outcome_start_rotation
                .next_players()
                .position(&donor.public_key())
                .is_none()
        );
        assert!(
            outcome_start_rotation
                .players()
                .position(&replacement.public_key())
                .is_none()
        );
        assert!(
            outcome_start_rotation
                .next_players()
                .position(&replacement.public_key())
                .is_some()
        );

        let outcome_finish_rotation = wait_for_outcome(
            &context,
            &validators,
            target_epoch.next().get(),
            epoch_length,
        )
        .await;

        assert!(
            outcome_finish_rotation
                .players()
                .position(&donor.public_key())
                .is_none()
        );
        assert!(
            outcome_finish_rotation
                .next_players()
                .position(&donor.public_key())
                .is_none()
        );
        assert!(
            outcome_finish_rotation
                .players()
                .position(&replacement.public_key())
                .is_some()
        );
        assert!(
            outcome_finish_rotation
                .next_players()
                .position(&replacement.public_key())
                .is_some()
        );

        info!("new validator was added to the committee, but not started");

        donor.stop().await;
        let last_epoch_before_stop = latest_epoch_of_validator(&context, &donor.uid);
        info!(%last_epoch_before_stop, "stopped the original validator");

        // Now the old validator donates its database to the new validator.
        //
        // This works by assigning the replacement validator's fields to the
        // old validator's. This way, the old validator "donates" its database
        // to the replacement. This is to simulate a snapshot.
        donor.uid = replacement.uid;
        donor.private_key = replacement.private_key;
        {
            let peer_manager = replacement.consensus_config.peer_manager.clone();
            donor.consensus_config = replacement.consensus_config;
            donor.consensus_config.peer_manager = peer_manager;
        }
        donor.network_address = replacement.network_address;
        donor.chain_address = replacement.chain_address;
        donor.start(&context).await;

        // Rename, so that it's less confusing below.
        let replacement = donor;

        info!(
            uid = %replacement.uid,
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

                    if metric.contains(&replacement.uid) {
                        assert!(
                            epoch >= last_epoch_before_stop,
                            "the replacement validator should never enter epochs \
                            older than what is in the snapshot"
                        );
                    }

                    if epoch > last_epoch_before_stop {
                        validators_at_epoch += 1;
                    }

                    if metric.contains(&replacement.uid) {
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

/// This test is the same as `joins_from_snapshot`, but with the extra condition
/// that the validator can restart (stop, start), after having booted from a
/// snapshot.
#[test_traced]
fn can_restart_after_joining_from_snapshot() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    // Create a verifier that we will never start. It just the private keys
    // we desire.
    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
        .t2_time(0)
        .connect_execution_layer_nodes(true)
        .epoch_length(epoch_length);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        // The replacement validator that will start later.
        let mut replacement = {
            let idx = validators
                .iter()
                .position(|node| node.consensus_config().share.is_none())
                .expect("at least one node must be a verifier, i.e. not have a share");
            validators.remove(idx)
        };
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // The validator that will donate it its database to the replacement.
        let mut donor = validators.pop().unwrap();

        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        // Validator setup generated 2 different addresses for both validators.
        // Make them the same so that ValidatorConfigV2.rotateValidator knows
        // which one to target.
        replacement.chain_address = donor.chain_address;
        let receipt = execution_runtime
            .rotate_validator(http_url, &replacement)
            .await
            .unwrap();

        let rotate_height = Height::new(receipt.block_number.unwrap());
        tracing::debug!(
            block.height = %rotate_height,
            "validatorConfigV2.rotateValidator executed",
        );

        // Wait for the next DKG outcome - unless rotate_height is on a boundary.
        // Then wait one more epoch.
        let epoch_strat = FixedEpocher::new(NZU64!(epoch_length));
        let info = epoch_strat.containing(rotate_height).unwrap();
        let target_epoch = if info.last() == rotate_height {
            info.epoch().next()
        } else {
            info.epoch()
        };

        let outcome_start_rotation =
            wait_for_outcome(&context, &validators, target_epoch.get(), epoch_length).await;

        assert!(
            outcome_start_rotation
                .players()
                .position(&donor.public_key())
                .is_some()
        );
        assert!(
            outcome_start_rotation
                .next_players()
                .position(&donor.public_key())
                .is_none()
        );
        assert!(
            outcome_start_rotation
                .players()
                .position(&replacement.public_key())
                .is_none()
        );
        assert!(
            outcome_start_rotation
                .next_players()
                .position(&replacement.public_key())
                .is_some()
        );

        let outcome_finish_rotation = wait_for_outcome(
            &context,
            &validators,
            target_epoch.next().get(),
            epoch_length,
        )
        .await;

        assert!(
            outcome_finish_rotation
                .players()
                .position(&donor.public_key())
                .is_none()
        );
        assert!(
            outcome_finish_rotation
                .next_players()
                .position(&donor.public_key())
                .is_none()
        );
        assert!(
            outcome_finish_rotation
                .players()
                .position(&replacement.public_key())
                .is_some()
        );
        assert!(
            outcome_finish_rotation
                .next_players()
                .position(&replacement.public_key())
                .is_some()
        );

        info!("new validator was added to the committee, but not started");

        donor.stop().await;
        let last_epoch_before_stop = latest_epoch_of_validator(&context, &donor.uid);
        info!(%last_epoch_before_stop, "stopped the original validator");

        // Now the old validator donates its database to the new validator.
        //
        // This works by assigning the replacement validator's fields to the
        // old validator's. This way, the old validator "donates" its database
        // to the replacement. This is to simulate a snapshot.
        donor.uid = replacement.uid;
        donor.private_key = replacement.private_key;
        {
            let peer_manager = replacement.consensus_config.peer_manager.clone();
            donor.consensus_config = replacement.consensus_config;
            donor.consensus_config.peer_manager = peer_manager;
        }
        donor.network_address = replacement.network_address;
        donor.chain_address = replacement.chain_address;
        donor.start(&context).await;

        // Rename, so that it's less confusing below.
        let mut replacement = donor;

        info!(
            uid = %replacement.uid,
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

                    if metric.contains(&replacement.uid) {
                        assert!(
                            epoch >= last_epoch_before_stop,
                            "the replacement validator should never enter epochs \
                            older than what is in the snapshot"
                        );
                    }

                    if epoch > last_epoch_before_stop {
                        validators_at_epoch += 1;
                    }

                    if metric.contains(&replacement.uid) {
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
        replacement.stop().await;

        let network_head = validators[0]
            .execution_provider()
            .best_block_number()
            .unwrap();

        replacement.start(&context).await;

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

                if metric.contains(&replacement.uid)
                    && metric.ends_with("_marshal_processed_height")
                    && value.parse::<u64>().unwrap() > network_head
                {
                    break 'progress;
                }
            }
        }
    });
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
