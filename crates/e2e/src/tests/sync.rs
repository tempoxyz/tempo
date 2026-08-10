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
use reth_ethereum::provider::{BlockIdReader as _, BlockNumReader as _};
use tracing::info;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    consensus_snapshot::write_consensus_snapshot,
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

        let last_epoch_before_stop = context
            .to_metrics()
            .for_scope(&receiver)
            .latest_consensus_epoch()
            .expect("validator had no entry for latest epoch");
        let execution_provider = receiver.execution_provider();
        receiver.stop().await;
        info!(%last_epoch_before_stop, "stopped the original validator");

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        let target_partition_prefix = donor.consensus_config.partition_prefix.clone();
        write_consensus_snapshot(
            &context,
            &receiver,
            execution_provider,
            &target_partition_prefix,
        )
        .await;
        receiver.adopt_identity_from(donor);
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

            // Since the snapshot does not include secret material, there's an epoch's
            // worth of downtime before the replacement enters/participates.
            metrics
                .for_scope(&receiver)
                .latest_consensus_epoch()
                .is_some_and(|epoch| epoch > 0)
                && metrics.consensus_at_epoch(last_epoch_before_stop + 2) == 4
        })
        .await;
    });
}

/// A consensus snapshot can anchor *below* the finality of the execution
/// database it is restored next to: snapshot construction falls back to an
/// older finalization certificate when the prunable finalized-blocks archive
/// has no contiguous path from execution finality to the finalization tip.
///
/// On startup, the marshal re-dispatches finalized blocks from that anchor
/// upwards. The executor must acknowledge the already-finalized blocks
/// without re-executing them or repointing the execution layer's finalized
/// tip backwards, and the node must then catch up with the network.
///
/// The stale snapshot is simulated by snapshotting the consensus state early
/// and restoring it next to the same node's execution database a few epochs
/// later.
#[test_traced]
fn joins_from_consensus_snapshot_anchored_below_execution_finality() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    // Create a verifier that we will never start. It just has the private
    // keys we desire.
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

        // First, deactivate the last actual validator (the receiver), so that
        // the network keeps making progress while it is stopped.
        execution_runtime
            .deactivate_validator_v2(http_url.clone(), &receiver)
            .await
            .unwrap();
        wait_for_participants(&context, 3).await;

        // Then, add the sacrificial validator without starting it(!).
        execution_runtime
            .add_validator_v2(http_url.clone(), &donor)
            .await
            .unwrap();
        wait_for_participants(&context, 4).await;

        info!("new validator was added to the committee, but not started");

        // Snapshot the receiver's consensus state *early*: the snapshot
        // anchors at the receiver's current finalized height.
        let execution_provider = receiver.execution_provider();
        receiver.stop().await;
        let target_partition_prefix = donor.consensus_config.partition_prefix.clone();
        let stale_snapshot = write_consensus_snapshot(
            &context,
            &receiver,
            execution_provider,
            &target_partition_prefix,
        )
        .await;
        info!(
            anchor = stale_snapshot.anchor_finalization_height,
            execution_finalized = stale_snapshot.execution_finalized_height,
            "wrote early consensus snapshot",
        );

        // Restart the receiver and let its execution layer finalize well past
        // the snapshot's anchor.
        receiver.start(&context).await;
        connect_execution_to_peers(&receiver, &validators).await;
        let resume_target = stale_snapshot.execution_finalized_height + 2 * epoch_length;
        wait_for_height_with_interval(
            &context,
            &receiver,
            resume_target,
            SNAPSHOT_RESTART_POLL_INTERVAL,
        )
        .await;

        let last_epoch_before_stop = context
            .to_metrics()
            .for_scope(&receiver)
            .latest_consensus_epoch()
            .expect("validator had no entry for latest epoch");
        let execution_finalized = receiver
            .execution_provider()
            .finalized_block_num_hash()
            .expect("must be able to read the finalized block")
            .expect("must have a finalized block")
            .number;
        receiver.stop().await;

        assert!(
            execution_finalized > stale_snapshot.anchor_finalization_height,
            "test precondition violated: the execution layer (finalized: \
            `{execution_finalized}`) must have finalized past the consensus \
            snapshot anchor (`{}`)",
            stale_snapshot.anchor_finalization_height,
        );

        // Restore: the node keeps its execution database, finalized well past
        // the consensus snapshot's anchor, but starts from the stale
        // consensus snapshot.
        receiver.adopt_identity_from(donor);
        receiver.start(&context).await;
        connect_execution_to_peers(&receiver, &validators).await;

        info!(
            uid = %receiver.uid,
            "restarted the node from the stale consensus snapshot",
        );

        // The node must start up - the marshal re-dispatches finalized blocks
        // from the snapshot anchor, below the execution layer's finality -
        // and catch up with the network.
        let catch_up_target = execution_finalized + epoch_length;
        wait_for_metrics_with_interval(&context, SNAPSHOT_RESTART_POLL_INTERVAL, |metrics| {
            assert!(
                metrics.consensus_before_epoch(last_epoch_before_stop + 5),
                "network advanced 5 epochs without the restored validator \
                catching up; there is likely a bug",
            );

            metrics
                .for_scope(&receiver)
                .latest_consensus_height()
                .is_some_and(|height| height >= catch_up_target)
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

        let last_epoch_before_stop = context
            .to_metrics()
            .for_scope(&receiver)
            .latest_consensus_epoch()
            .expect("validator had no entry for latest epoch");
        let execution_provider = receiver.execution_provider();
        receiver.stop().await;

        info!(
            %last_epoch_before_stop,
            id = %receiver.uid,
            "stopped the original validator",
        );

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        let target_partition_prefix = donor.consensus_config.partition_prefix.clone();
        write_consensus_snapshot(
            &context,
            &receiver,
            execution_provider,
            &target_partition_prefix,
        )
        .await;
        receiver.adopt_identity_from(donor);
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

            // Since the snapshot does not include secret material, there's an epoch's
            // worth of downtime before the replacement enters/participates.
            metrics
                .for_scope(&receiver)
                .latest_consensus_epoch()
                .is_some_and(|epoch| epoch > 0)
                && metrics.consensus_at_epoch(last_epoch_before_stop + 2) == 4
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
