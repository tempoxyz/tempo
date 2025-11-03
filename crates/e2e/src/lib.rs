//! e2e tests using the [`commonware_runtime::deterministic`].
//!
//! This crate mimics how a full tempo node is run in production but runs the
//! consensus engine in a deterministic runtime while maintaining a tokio
//! async environment to launch execution nodes.
//!
//! All definitions herein are only intended to support the the tests defined
//! in tests/.

use std::{net::SocketAddr, pin::Pin, time::Duration};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{
        dkg::ops,
        primitives::{group::Share, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    // simulated::{self, Link, Network, Oracle},
    authenticated::lookup::{self, Network, Oracle},
};

use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::{
    NZU32, quorum,
    set::{Ordered, OrderedAssociated},
};
use futures::future::join_all;
use governor::Quota;
use tracing::debug;

pub mod execution_runtime;
pub use execution_runtime::ExecutionRuntime;

use crate::execution_runtime::ExecutionNode;

#[cfg(test)]
mod tests;

/// A Tempo node with lazily started consensus engine.
pub struct ValidatorNode {
    /// Execution-layer node. Spawned in the background but won't progress unless consensus engine is started.
    pub node: ExecutionNode,

    /// Future that should be awaited to start the consensus engine.
    start_engine: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl ValidatorNode {
    pub fn start(&mut self) -> impl Future<Output = ()> + use<> {
        self.start_engine.take().expect("engine already started")
    }
}

/// The test setup run by [`run`].
#[derive(Clone)]
pub struct Setup {
    /// How many validators to launch.
    pub how_many: u32,
    /// The seed used for setting up the deterministic runtime.
    pub seed: u64,

    // FIXME(janis): bring back linkage once simulated p2p works with lookup.
    // /// The linkage between individual validators.
    // pub linkage: Link,
    /// The number of heights in an epoch.
    pub epoch_length: u64,

    pub start_port: u16,
}

pub async fn setup_validators(
    mut context: Context,
    execution_runtime: &ExecutionRuntime,
    Setup {
        how_many,
        seed: _,
        // linkage,
        epoch_length,
        start_port,
    }: Setup,
) -> Vec<ValidatorNode> {
    struct SetupValidator {
        signer: PrivateKey,
        oracle: Oracle<PublicKey>,
        addr: SocketAddr,
        network: Network<Context, PrivateKey>,
        share: Share,
    }

    let threshold = quorum(how_many);
    let (polynomial, shares) =
        ops::generate_shares::<_, MinSig>(&mut context, None, how_many, threshold);

    let mut port = start_port;

    let mut setups = vec![];

    let mut signers = (0..how_many)
        .map(|i| PrivateKey::from_seed(i as u64))
        .collect::<Vec<_>>();

    signers.sort_by_key(|s| s.public_key());

    for (i, signer) in signers.into_iter().enumerate() {
        // Should be port=0, but there is no way to get the dialable addr
        // out or set to the same as listen_addr. At least for now.
        let listen_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let (network, oracle) = Network::new(
            context.with_label(&format!("network-{i}")),
            lookup::Config::local(
                signer.clone(),
                b"P2P",
                listen_addr,
                listen_addr,
                1024 * 1024,
            ),
        );
        setups.push(SetupValidator {
            signer,
            oracle,
            addr: listen_addr,
            network,
            share: shares[i].clone(),
        });
        port += 1;
    }

    let mut nodes = Vec::new();

    let unresolved_peers: OrderedAssociated<_, _> = setups
        .iter()
        .map(|setup| (setup.signer.public_key(), setup.addr.to_string()))
        .collect::<Vec<_>>()
        .into();

    // TODO: Technically unnecessary, done by unresolved_peers.
    let participants: Ordered<_> = setups
        .iter()
        .map(|setup| setup.signer.public_key())
        .collect::<Vec<_>>()
        .into();

    for (
        i,
        SetupValidator {
            signer,
            oracle,
            share,
            mut network,
            ..
        },
    ) in setups.into_iter().enumerate()
    {
        let uid = format!("validator-{}", signer.public_key());

        let node = execution_runtime
            .spawn_node_blocking(&format!("node-{i}"))
            .expect("must be able to spawn nodes on the runtime");

        let engine = tempo_commonware_node::consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: node.node.clone(),
            blocker: oracle.clone(),
            peer_manager: oracle.clone(),
            partition_prefix: uid.clone(),
            signer: signer.clone(),
            polynomial: polynomial.clone(),
            share,
            participants: participants.clone(),
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
            unresolved_peers: unresolved_peers.clone(),
        }
        .try_init()
        .await
        .expect("must be able to initialize consensus engines to run tests");

        let pending = network.register(0, Quota::per_second(NZU32!(128)), 16_384);
        let recovered = network.register(1, Quota::per_second(NZU32!(128)), 16_384);
        let resolver = network.register(2, Quota::per_second(NZU32!(128)), 16_384);
        let broadcast = network.register(3, Quota::per_second(NZU32!(8)), 16_384);
        let marshal = network.register(4, Quota::per_second(NZU32!(8)), 16_384);
        let dkg = network.register(5, Quota::per_second(NZU32!(128)), 16_384);
        let boundary_certs = network.register(6, Quota::per_second(NZU32!(1)), 16_384);

        // FIXME: bind to port 0, get the bound port out of this.
        // let mut listener_info = network.listener_info();
        network.start();

        // FIXME(janis): bring back linkage once simulated p2p works with lookup.
        // let link = linkage.clone();
        nodes.push(ValidatorNode {
            node,
            start_engine: Some(Box::pin(async move {
                // FIXME(janis): bring back linkage once simulated p2p works with lookup.
                // link_validators(&mut oracle, &validators, link, None).await;

                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    marshal,
                    dkg,
                    boundary_certs,
                );

                debug!(%uid, "started validator");
            })),
        });
    }
    nodes
}

/// Runs a test configured by [`Setup`].
pub fn run(setup: Setup, mut stop_condition: impl FnMut(&str, &str) -> bool) -> String {
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        // Setup and run all validators.
        let nodes = setup_validators(context.clone(), &execution_runtime, setup).await;
        join_all(nodes.into_iter().map(|mut node| node.start())).await;

        loop {
            let metrics = context.encode();

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

// FIXME(janis): bring back linkage once simulated p2p works with lookup.
// /// Links (or unlinks) validators using the oracle.
// ///
// /// The `action` parameter determines the action (e.g. link, unlink) to take.
// /// The `restrict_to` function can be used to restrict the linking to certain connections,
// /// otherwise all validators will be linked to all other validators.
// pub async fn link_validators(
//     oracle: &mut Oracle<PublicKey>,
//     validators: &[PublicKey],
//     link: Link,
//     restrict_to: Option<fn(usize, usize, usize) -> bool>,
// ) {
//     for (i1, v1) in validators.iter().enumerate() {
//         for (i2, v2) in validators.iter().enumerate() {
//             // Ignore self
//             if v2 == v1 {
//                 continue;
//             }

//             // Restrict to certain connections
//             if let Some(f) = restrict_to
//                 && !f(validators.len(), i1, i2)
//             {
//                 continue;
//             }

//             // Add link
//             match oracle.add_link(v1.clone(), v2.clone(), link.clone()).await {
//                 Ok(()) => (),
//                 // TODO: it should be possible to remove the below if Commonware simulated network exposes list of registered peers.
//                 //
//                 // This is fine because some of the peers might be registered later
//                 Err(commonware_p2p::simulated::Error::PeerMissing) => (),
//                 // This is fine because we might call this multiple times as peers are joining the network.
//                 Err(commonware_p2p::simulated::Error::LinkExists) => (),
//                 res @ Err(_) => res.unwrap(),
//             }
//         }
//     }
// }
