//! Tests for syncing nodes from scratch.
//!
//! These tests are similar to the tests in [`crate::tests::restart`], but
//! assume that the node has never been run but been given a synced execution
//! layer database./// Runs a validator restart test with the given configuration

use std::{num::NonZeroU64, time::Duration};

use alloy::transports::http::reqwest::Url;
use commonware_consensus::types::{Epocher, FixedEpocher, Height};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockNumReader as _;

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
        .epoch_length(epoch_length);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, execution_runtime) =
            setup_validators(context.clone(), setup.clone()).await;

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
        join_all(validators.iter_mut().map(|v| v.start())).await;

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

        // First, remove the last actual validator.
        let receipt = execution_runtime
            .change_validator_status(http_url.clone(), receiver.chain_address, false)
            .await
            .unwrap();

        tracing::debug!(
            block.number = receipt.block_number,
            "changeValidatorStatus call returned receipt"
        );

        // Then wait until the validator has left the committee.
        wait_for_participants(&context, 3).await;

        tracing::info!("validator left the committe");

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

        // Wait until it was added to the commitee
        wait_for_participants(&context, 4).await;

        tracing::info!("new validator was added to the committee, but not started");

        // Stop the validator that was originally removed. It should have
        // remained in the peer set for a while and received many of the latest
        // blocks without being a signer.

        // TODO: remove this once the panic using `execution_provider_offline`
        // works.
        let last_epoch_before_stop = {
            let provider = receiver.execution_provider();
            let height = provider.best_block_number().unwrap();
            FixedEpocher::new(NonZeroU64::new(epoch_length).unwrap())
                .containing(Height::new(height))
                .unwrap()
                .epoch()
        };
        receiver.stop().await;

        // FIXME: This panics with, even though the docs suggest that this
        // should work after stopping the node.
        //
        // > thread 'tests::sync::joins_from_snapshot' (1590206) panicked at crates/e2e/src/testing_node.rs:403:14:
        // > failed to open execution node database: Could not open database at path: /var/folders/67/p5bqzp895gngs5k_dlth5w7w0000gn/T/tempo_e2e_testAbLHo5/execution-e0ac6b28476eac8c0ae43d327da5e77316f280f9c1c6b2bf5def422988d90597/db
        //
        // > Caused by:
        // >     failed to open the database: unknown error code: 35 (35)
        // let last_epoch_before_stop = {
        //     let provider = receiver.execution_provider_offline();
        //     let height = provider.best_block_number().unwrap();
        //     FixedEpocher::new(NonZeroU64::new(epoch_length).unwrap())
        //         .containing(Height::new(height))
        //         .unwrap()
        //         .epoch()
        // };

        tracing::info!(%last_epoch_before_stop, "stopped the original validator");

        // Now turn the receiver into the donor - except for the database dir and
        // env. This simulates a start from a snapshot.
        receiver.uid = donor.uid;
        receiver.public_key = donor.public_key;
        receiver.consensus_config = donor.consensus_config;
        receiver.network_address = donor.network_address;
        receiver.chain_address = donor.chain_address;
        receiver.start().await;

        tracing::info!(
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

                    if epoch > last_epoch_before_stop.get() {
                        validators_at_epoch += 1;
                    }

                    if metric.contains(&receiver.uid) {
                        assert!(
                            epoch >= last_epoch_before_stop.get(),
                            "when starting from snapshot, older epochs must never \
                            had consensus engines running"
                        );
                    }
                }
            }
            if validators_at_epoch == 4 {
                std::fs::write("metrics", metrics).unwrap();
                break;
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
