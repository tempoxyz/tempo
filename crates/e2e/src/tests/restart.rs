//! Tests for validator restart/kill scenarios
//!
//! These tests verify that validators can be killed and restarted, and that they
//! properly catch up to the rest of the network after restart.

use std::{future::Future, pin::Pin, time::Duration};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{dkg::ops, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_macros::test_traced;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::quorum;
use futures::future::join_all;
use rand::Rng;
use tracing::{debug, info};

use crate::{ExecutionRuntime, Setup, ValidatorNode, link_validators, setup_validators};

/// Test configuration for restart scenarios
#[derive(Clone)]
struct RestartSetup {
    /// How many validators to launch
    pub how_many: u32,
    /// The seed used for setting up the deterministic runtime
    pub seed: u64,
    /// The linkage between individual validators
    pub linkage: Link,
    /// The number of heights in an epoch
    pub epoch_length: u64,
    /// Height at which to shutdown a validator
    pub shutdown_height: u64,
    /// Height at which to restart the validator
    pub restart_height: u64,
    /// Final height that all validators (including restarted) must reach
    pub final_height: u64,
}

/// Runs a validator restart test with the given configuration
fn run_restart_test(setup: RestartSetup) -> String {
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let execution_runtime = ExecutionRuntime::new();

        // Setup and start all validators
        let (mut nodes, mut oracle) = setup_validators(
            context.clone(),
            &execution_runtime,
            Setup {
                how_many: setup.how_many,
                seed: setup.seed,
                linkage: setup.linkage.clone(),
                epoch_length: setup.epoch_length,
            },
        )
        .await;

        // Start all validators
        let mut start_futures: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
        for node in nodes.iter_mut() {
            start_futures.push(Box::pin(node.start()));
        }
        join_all(start_futures).await;

        // Wait for all validators to reach shutdown height
        info!(
            "Waiting for validators to reach shutdown height {}",
            setup.shutdown_height
        );
        wait_for_height(&context, setup.how_many, setup.shutdown_height).await;

        // Randomly select a validator to kill
        let idx = context.gen_range(0..nodes.len());
        let killed_node = nodes.remove(idx);
        let killed_public_key = killed_node.public_key.clone();

        // Kill the validator by dropping it
        info!(
            "Killing validator at index {} with public key {:?}",
            idx, killed_public_key
        );
        drop(killed_node);

        // Wait for remaining validators to reach restart height
        info!(
            "Waiting for {} remaining validators to reach restart height {}",
            setup.how_many - 1,
            setup.restart_height
        );
        wait_for_height(&context, setup.how_many - 1, setup.restart_height).await;

        // Restart the killed validator
        info!(
            "Restarting validator at index {} with public key {:?}",
            idx, killed_public_key
        );
        let restarted_node = restart_validator(RestartParams {
            context: context.clone(),
            execution_runtime: &execution_runtime,
            oracle: &mut oracle,
            validator_index: idx,
            total_validators: setup.how_many,
            linkage: setup.linkage.clone(),
            epoch_length: setup.epoch_length,
            existing_nodes: &nodes,
        })
        .await;

        // Start the restarted validator
        let mut restarted_node = restarted_node;
        restarted_node.start().await;

        // Add restarted node back to the list
        nodes.insert(idx, restarted_node);

        // Wait for all validators (including restarted) to reach final height
        info!(
            "Waiting for all {} validators to reach final height {}",
            setup.how_many, setup.final_height
        );
        wait_for_height(&context, setup.how_many, setup.final_height).await;

        info!("Test completed successfully");
        context.auditor().state()
    })
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_height(context: &Context, expected_validators: u32, target_height: u64) {
    loop {
        let metrics = context.encode();
        let mut validators_at_height = 0;

        for line in metrics.lines() {
            if !line.starts_with("validator-") {
                continue;
            }

            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();

            // Check if this is a height metric
            if metric.ends_with("_marshal_processed_height")
                && let Ok(height) = value.parse::<u64>()
                && height >= target_height
            {
                validators_at_height += 1;
            }
        }

        if validators_at_height >= expected_validators {
            debug!(
                "Found {} validators at height {} (target: {})",
                validators_at_height, target_height, expected_validators
            );
            break;
        }

        context.sleep(Duration::from_secs(1)).await;
    }
}

/// Parameters for restarting a validator
struct RestartParams<'a> {
    context: Context,
    execution_runtime: &'a ExecutionRuntime,
    oracle: &'a mut Oracle<PublicKey>,
    validator_index: usize,
    total_validators: u32,
    linkage: Link,
    epoch_length: u64,
    existing_nodes: &'a [ValidatorNode],
}

/// Restart a validator that was previously killed
async fn restart_validator(params: RestartParams<'_>) -> ValidatorNode {
    let RestartParams {
        mut context,
        execution_runtime,
        oracle,
        validator_index,
        total_validators,
        linkage,
        epoch_length,
        existing_nodes,
    } = params;
    let threshold = quorum(total_validators);

    // Recreate the validator's keys (deterministic from index)
    let signer = PrivateKey::from_seed(validator_index as u64);
    let public_key = signer.public_key();

    // Get all validator public keys for the network (sorted)
    let mut signers = Vec::new();
    let mut validators = Vec::new();
    for i in 0..total_validators {
        let s = PrivateKey::from_seed(i as u64);
        let pk = s.public_key();
        signers.push(s);
        validators.push(pk);
    }
    validators.sort();
    signers.sort_by_key(|s| s.public_key());

    // Find the correct position in the sorted list
    let sorted_index = signers
        .iter()
        .position(|s| s.public_key() == public_key)
        .expect("validator must be in the list");

    // Regenerate the DKG shares (deterministic)
    let (polynomial, shares) =
        ops::generate_shares::<_, MinSig>(&mut context, None, total_validators, threshold);

    // Spawn a new execution node
    let node = execution_runtime
        .spawn_node_blocking(&format!("node-{validator_index}-restarted"))
        .expect("must be able to spawn restarted node");

    // Connect to existing nodes for EL p2p connectivity
    for existing_node in existing_nodes {
        existing_node.node.connect_peer(&node).await;
    }

    // Create the consensus engine with a unique identifier to avoid channel conflicts
    let uid = format!("validator-{public_key}-restarted");
    let random_id: u64 = context.r#gen();
    let unique_partition = format!("{uid}-{random_id}");
    let engine = tempo_commonware_node::consensus::Builder {
        context: context.with_label(&uid),
        fee_recipient: alloy_primitives::Address::ZERO,
        execution_node: node.node.clone(),
        blocker: oracle.control(public_key.clone()),
        peer_manager: oracle.socket_manager().clone(),
        partition_prefix: unique_partition,
        signer: signer.clone(),
        polynomial: polynomial.clone(),
        share: shares[sorted_index].clone(), // Use the correct share based on sorted position
        participants: validators.clone().into(),
        mailbox_size: 1024,
        deque_size: 10,
        time_to_propose: Duration::from_secs(2),
        time_to_collect_notarizations: Duration::from_secs(3),
        time_to_retry_nullify_broadcast: Duration::from_secs(10),
        time_for_peer_response: Duration::from_secs(2),
        views_to_track: 10,
        views_until_leader_skip: 5,
        new_payload_wait_time: Duration::from_millis(100),
        time_to_build_subblock: Duration::from_millis(100),
        epoch_length,
    }
    .try_init()
    .await
    .expect("must be able to initialize restarted consensus engine");

    // Re-register the validator with the network oracle
    let mut oracle_clone = oracle.clone();
    let validators_clone = validators.clone();
    let link_clone = linkage.clone();

    ValidatorNode {
        node,
        public_key: signer.public_key(),
        start_engine: Some(Box::pin(async move {
            // Use new channel IDs for the restarted validator to avoid conflicts
            // Add offset of 100 to all channel IDs
            let pending = oracle_clone
                .control(signer.public_key())
                .register(100)
                .await
                .unwrap();
            let recovered = oracle_clone
                .control(signer.public_key())
                .register(101)
                .await
                .unwrap();
            let resolver = oracle_clone
                .control(signer.public_key())
                .register(102)
                .await
                .unwrap();
            let broadcast = oracle_clone
                .control(signer.public_key())
                .register(103)
                .await
                .unwrap();
            let marshal = oracle_clone
                .control(signer.public_key())
                .register(104)
                .await
                .unwrap();
            let dkg = oracle_clone
                .control(signer.public_key())
                .register(105)
                .await
                .unwrap();
            let boundary_certs = oracle_clone
                .control(signer.public_key())
                .register(106)
                .await
                .unwrap();
            let subblocks = oracle_clone
                .control(signer.public_key())
                .register(107)
                .await
                .unwrap();

            // Re-establish network links
            link_validators(&mut oracle_clone, &validators_clone, link_clone, None).await;

            // Start the engine
            engine.start(
                pending,
                recovered,
                resolver,
                broadcast,
                marshal,
                dkg,
                boundary_certs,
                subblocks,
            );

            debug!(%uid, "restarted validator");
        })),
    }
}

#[test_traced]
fn test_validator_restart_simple() {
    let _ = tempo_eyre::install();

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    // Very simple test - just check that validator can be killed and restarted
    let setup = RestartSetup {
        how_many: 3, // Minimum for BFT
        seed: 0,
        linkage,
        epoch_length: 10,
        shutdown_height: 3, // Kill very early
        restart_height: 6,  // Restart soon after
        final_height: 10,   // Reach one epoch
    };

    let _state = run_restart_test(setup);
    // If we get here without panicking, the test passed
}

#[test_traced]
fn test_validator_restart_perfect_links() {
    let _ = tempo_eyre::install();

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let epoch_length = 10; // Shorter epoch for faster testing
    let setup = RestartSetup {
        how_many: 4,
        seed: 0,
        linkage,
        epoch_length,
        shutdown_height: 5, // Kill at height 5
        restart_height: 10, // Restart at height 10
        final_height: 15,   // All reach height 15
    };

    let _state = run_restart_test(setup);
    // If we get here without panicking, the test passed

    // TODO: Enable determinism check - see https://github.com/commonwarexyz/monorepo/pull/218
    // The commonware reshare example runs tests twice with the same seed to verify determinism.
    // Currently the state hash differs between runs in our tests, maybe due to the mixed
    // deterministic (commonware) and non-deterministic (tokio for reth) runtimes.
}

#[test_traced]
fn test_validator_restart_with_failures() {
    let _ = tempo_eyre::install();

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate: 0.95, // 5% packet loss
    };

    let epoch_length = 30;
    let setup = RestartSetup {
        how_many: 5, // More validators to handle failures
        seed: 42,
        linkage,
        epoch_length,
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
    };

    let _state = run_restart_test(setup);
    // If we get here without panicking, the test passed

    // TODO: Enable determinism check - see https://github.com/commonwarexyz/monorepo/pull/218
    // The commonware reshare example runs tests twice with the same seed to verify determinism.
    // Currently the state hash differs between runs in our tests, maybe due to the mixed
    // deterministic (commonware) and non-deterministic (tokio for reth) runtimes.
}
