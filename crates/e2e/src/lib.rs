//! e2e tests using the [`commonware_runtime::deterministic`].
//!
//! This crate mimics how a full tempo node is run in production but runs the
//! consensus engine in a deterministic runtime while maintaining a tokio
//! async environment to launch execution nodes.
//!
//! All definitions herein are only intended to support the the tests defined
//! in tests/.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{dkg::ops, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};

use commonware_runtime::{Clock, Metrics as _, Runner as _, deterministic, deterministic::Runner};
use commonware_utils::quorum;
use tracing::debug;

pub mod execution_runtime;
pub use execution_runtime::ExecutionRuntime;

#[cfg(test)]
mod tests;

/// The test setup run by [`run`].
#[derive(Clone)]
pub struct Setup {
    /// How many validators to launch.
    pub how_many: u32,
    /// The seed used for setting up the deterministic runtime.
    pub seed: u64,
    /// The linkage between individual validators.
    pub linkage: Link,
    /// The number of heights in an epoch.
    pub epoch_length: u64,
}

/// Runs a test configured by [`Setup`].
pub fn run(
    Setup {
        how_many,
        seed,
        linkage,
        epoch_length,
    }: Setup,
    mut stop_condition: impl FnMut(&str, &str) -> bool,
) -> String {
    let threshold = quorum(how_many);
    let cfg = deterministic::Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
            },
        );
        network.start();

        let mut signers = Vec::new();
        let mut validators = Vec::new();
        for i in 0..how_many {
            let signer = PrivateKey::from_seed(u64::from(i));
            let public_key = signer.public_key();
            signers.push(signer);
            validators.push(public_key);
        }
        validators.sort();
        signers.sort_by_key(|s| s.public_key());
        let mut registrations = register_validators(&mut oracle, &validators).await;

        link_validators(&mut oracle, &validators, linkage, None).await;

        let (polynomial, shares) =
            ops::generate_shares::<_, MinSig>(&mut context, None, how_many, threshold);

        let mut public_keys = HashSet::new();
        for (i, (signer, share)) in signers.into_iter().zip(shares).enumerate() {
            let public_key = signer.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator-{public_key}");

            let node = execution_runtime
                .spawn_node_blocking(&format!("node-{i}"))
                .expect("must be able to spawn nodes on the runtime");

            let engine = tempo_commonware_node::consensus::Builder {
                context: context.with_label(&uid),
                fee_recipient: alloy_primitives::Address::ZERO,
                execution_node: node.node,
                blocker: oracle.control(public_key.clone()),
                partition_prefix: uid.clone(),
                signer,
                polynomial: polynomial.clone(),
                share,
                participants: validators.clone().into(),
                mailbox_size: 1024,
                deque_size: 10,
                time_to_propose: Duration::from_secs(2),
                time_to_collect_notarizations: Duration::from_secs(3),
                time_to_retry_nullify_broadcast: Duration::from_secs(10),
                time_for_peer_response: Duration::from_secs(2),
                views_to_track: 10,
                views_until_leader_skip: 5,
                new_payload_wait_time: Duration::from_millis(750),
                epoch_length,
            }
            .try_init()
            .await
            .expect("must be able to initialize consensus engines to run tests");

            let (pending, recovered, resolver, broadcast, backfill, dkg, subblocks) = registrations
                .remove(&public_key)
                .expect("public key must have an entry in registrations map");

            engine.start(
                pending, recovered, resolver, broadcast, backfill, dkg, subblocks,
            );

            debug!(%uid, "started validator");
        }

        loop {
            let metrics = context.encode();

            std::fs::write("metrics_dump", &metrics).unwrap();

            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with("validator-") {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metrics.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if stop_condition(metric, value) {
                    success = true;
                    break;
                }
            }

            if success {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        context.auditor().state()
    })
}

/// Registers all validators using the oracle.
async fn register_validators(
    oracle: &mut Oracle<PublicKey>,
    validators: &[PublicKey],
) -> HashMap<
    PublicKey,
    (
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let (pending_sender, pending_receiver) =
            oracle.register(validator.clone(), 0).await.unwrap();
        let (recovered_sender, recovered_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        let (broadcast_sender, broadcast_receiver) =
            oracle.register(validator.clone(), 3).await.unwrap();
        let (backfill_sender, backfill_receiver) =
            oracle.register(validator.clone(), 4).await.unwrap();
        let (dkg_sender, dkg_receiver) = oracle.register(validator.clone(), 5).await.unwrap();
        let (subblocks_sender, subblocks_receiver) =
            oracle.register(validator.clone(), 6).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
                (broadcast_sender, broadcast_receiver),
                (backfill_sender, backfill_receiver),
                (dkg_sender, dkg_receiver),
                (subblocks_sender, subblocks_receiver),
            ),
        );
    }
    registrations
}

/// Links (or unlinks) validators using the oracle.
///
/// The `action` parameter determines the action (e.g. link, unlink) to take.
/// The `restrict_to` function can be used to restrict the linking to certain connections,
/// otherwise all validators will be linked to all other validators.
pub async fn link_validators(
    oracle: &mut Oracle<PublicKey>,
    validators: &[PublicKey],
    link: Link,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            // Ignore self
            if v2 == v1 {
                continue;
            }

            // Restrict to certain connections
            if let Some(f) = restrict_to
                && !f(validators.len(), i1, i2)
            {
                continue;
            }

            // Add link
            oracle
                .add_link(v1.clone(), v2.clone(), link.clone())
                .await
                .unwrap();
        }
    }
}
