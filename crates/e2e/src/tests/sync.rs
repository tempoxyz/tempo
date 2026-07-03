//! Tests for syncing nodes from scratch.
//!
//! These tests are similar to the tests in [`crate::tests::restart`], but
//! assume that the node has never been run but been given a synced execution
//! layer database./// Runs a validator restart test with the given configuration

use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockNumReader as _;
use tracing::info;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    metrics::{
        MetricsExt, wait_for_height_with_interval, wait_for_metrics,
        wait_for_metrics_with_interval, wait_for_participants, wait_for_participants_with_interval,
    },
    setup_validators,
};

const SNAPSHOT_RESTART_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[test_traced]
fn joins_from_snapshot() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    // Create a verifier that we will never start. It just the private keys
    // we desire.
    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
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
        connect_execution_peers(&validators).await;

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

        // First, deactivate the last actual validator (the receiver).
        let receipt = execution_runtime
            .deactivate_validator_v2(http_url.clone(), &receiver)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "deactivateValidator call returned receipt"
        );

        // Then wait until the validator has left the committee.
        wait_for_participants(&context, 3).await;

        info!("validator left the committee");

        // Then, add the sacrificial validator without starting it(!).
        let receipt = execution_runtime
            .add_validator_v2(http_url.clone(), &donor)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "addValidatorV2 call returned receipt"
        );

        // Wait until it was added to the committee
        wait_for_participants(&context, 4).await;

        info!("new validator was added to the committee, but not started");

        receiver.stop().await;
        let last_epoch_before_stop = context
            .to_metrics()
            .for_scope(&receiver)
            .latest_consensus_epoch()
            .expect("validator had no entry for latest epoch");
        info!(%last_epoch_before_stop, "stopped the original validator");

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        receiver.uid = donor.uid;
        receiver.private_key = donor.private_key;
        {
            let peer_manager = receiver.consensus_config.peer_manager.clone();
            receiver.consensus_config = donor.consensus_config;
            receiver.consensus_config.peer_manager = peer_manager;
        }
        receiver.network_address = donor.network_address;
        receiver.chain_address = donor.chain_address;
        receiver.start(&context).await;
        connect_execution_to_peers(&receiver, &validators).await;

        info!(
            uid = %receiver.uid,
            "started the validator with a changed identity",
        );

        wait_for_metrics(&context, |metrics| {
            assert!(
                metrics.consensus_before_epoch(last_epoch_before_stop + 4),
                "network advanced 4 epochs before without the new \
                validator catching up; there is likely a bug",
            );

            if let Some(epoch) = metrics.for_scope(&receiver).latest_active_consensus_epoch() {
                assert!(epoch > 0, "validator should never boot into genesis epoch");
            }

            metrics.consensus_at_epoch(last_epoch_before_stop + 1) == 4
        })
        .await;
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
        connect_execution_peers(&validators).await;

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

        // First, deactivate the last actual validator (the receiver).
        let receipt = execution_runtime
            .deactivate_validator_v2(http_url.clone(), &receiver)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "deactivateValidator call returned receipt"
        );

        // Then wait until the validator has left the committee.
        wait_for_participants_with_interval(&context, 3, SNAPSHOT_RESTART_POLL_INTERVAL).await;

        info!("validator left the committee");

        // Then, add the sacrificial validator without starting it(!).
        let receipt = execution_runtime
            .add_validator_v2(http_url.clone(), &donor)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "addValidatorV2 call returned receipt"
        );

        // Wait until it was added to the committee
        wait_for_participants_with_interval(&context, 4, SNAPSHOT_RESTART_POLL_INTERVAL).await;

        info!("new validator was added to the committee, but not started");

        receiver.stop().await;

        let last_epoch_before_stop = context
            .to_metrics()
            .for_scope(&receiver)
            .latest_consensus_epoch()
            .expect("validator had no entry for latest epoch");

        info!(
            %last_epoch_before_stop,
            id = %receiver.uid,
            "stopped the original validator",
        );

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        receiver.uid = donor.uid;
        receiver.private_key = donor.private_key;
        {
            let peer_manager = receiver.consensus_config.peer_manager.clone();
            receiver.consensus_config = donor.consensus_config;
            receiver.consensus_config.peer_manager = peer_manager;
        }
        receiver.network_address = donor.network_address;
        receiver.chain_address = donor.chain_address;
        receiver.start(&context).await;
        connect_execution_to_peers(&receiver, &validators).await;

        info!(
            uid = %receiver.uid,
            "started the validator with a changed identity",
        );

        wait_for_metrics_with_interval(&context, SNAPSHOT_RESTART_POLL_INTERVAL, |metrics| {
            assert!(
                metrics.consensus_before_epoch(last_epoch_before_stop + 4),
                "network advanced 4 epochs before without the new \
                validator catching up; there is likely a bug",
            );

            if let Some(epoch) = metrics.for_scope(&receiver).latest_active_consensus_epoch() {
                assert!(epoch > 0, "validator should never boot into genesis epoch");
            }

            metrics.consensus_at_epoch(last_epoch_before_stop + 1) == 4
        })
        .await;

        // Restart the node. This ensures that it's state is still sound after
        // doing a snapshot sync.
        receiver.stop().await;

        let network_head = validators[0]
            .execution_provider()
            .best_block_number()
            .unwrap();

        receiver.start(&context).await;
        connect_execution_to_peers(&receiver, &validators).await;

        info!(
            network_head,
            "restarting the node and waiting for it to catch up"
        );

        wait_for_height_with_interval(
            &context,
            &receiver,
            network_head + 1,
            SNAPSHOT_RESTART_POLL_INTERVAL,
        )
        .await;
    });
}
