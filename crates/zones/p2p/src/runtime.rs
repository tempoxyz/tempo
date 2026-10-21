//! Commonware runtime and network for Simplex-sequenced zones.
//!
//! The runtime owns one dedicated OS thread running a Commonware tokio runtime. It starts the
//! authenticated lookup network over the manifest's participants, registers the Simplex channel
//! set, relays forwarded transactions, and runs the caller's consensus future on the same context.
//! Leadership never gates any of these channels: every participant votes, may propose, and
//! retains every transaction.

use std::{future::Future, sync::Arc, time::Duration};

use alloy_primitives::B256;
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::{
    AddressableManager as _, Blocker as _, Recipients, Sender as _, authenticated::lookup,
};
use commonware_runtime::{IoBuf, Quota, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::NZU32;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    P2pConfig, P2pNetworkId,
    network::{self, MAX_TRANSACTION_MESSAGE_SIZE},
};

/// Simplex vote channel.
pub const VOTES_CHANNEL: u64 = 0;
/// Simplex notarization, nullification, and finalization certificates.
pub const CERTIFICATES_CHANNEL: u64 = 1;
/// Simplex certificate backfill.
pub const RESOLVER_CHANNEL: u64 = 2;
/// Buffered broadcast of proposed blocks.
pub const BROADCASTER_CHANNEL: u64 = 3;
/// Marshal backfill of finalized blocks and certificates.
pub const MARSHAL_CHANNEL: u64 = 4;
/// Raw transaction propagation to every other participant.
pub const TRANSACTIONS_CHANNEL: u64 = 5;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_BACKLOG: usize = 128;
const EVENT_BACKLOG: usize = 128;

/// A registered Commonware channel: authenticated sender and receiver.
pub type Channel = (
    lookup::Sender<PublicKey, commonware_runtime::tokio::Context>,
    lookup::Receiver<PublicKey>,
);

/// One canonical EIP-2718 transaction to send to every other participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTransaction {
    pub transaction_hash: B256,
    pub transaction: Vec<u8>,
}

/// A raw transaction received from an authenticated participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedTransaction {
    pub peer: PublicKey,
    pub transaction: Vec<u8>,
}

/// Everything the consensus engine needs from the network, handed to the consensus future.
pub struct SimplexNetwork {
    /// This node's Ed25519 identity, also its Simplex vote key.
    pub private_key: PrivateKey,
    /// Ed25519 identities of every participant, including this node.
    pub participants: Vec<PublicKey>,
    /// Blocks peers that send invalid consensus messages.
    pub oracle: lookup::Oracle<PublicKey>,
    /// Network namespace; consensus derives its signing namespace from it.
    pub namespace: Vec<u8>,
    /// Maximum size of one network message.
    pub max_message_size: u32,
    /// Simplex votes.
    pub votes: Channel,
    /// Simplex certificates.
    pub certificates: Channel,
    /// Simplex certificate backfill.
    pub resolver: Channel,
    /// Proposed-block broadcast.
    pub broadcaster: Channel,
    /// Marshal finalized-block backfill.
    pub marshal: Channel,
}

/// Cross-runtime channels and lifecycle controls of a running Simplex runtime.
pub struct SimplexHandle {
    /// Cancels the dedicated runtime.
    pub shutdown: CancellationToken,
    /// Resolves when the dedicated runtime exits.
    pub stopped: oneshot::Receiver<Result<(), String>>,
    /// OS thread hosting the dedicated Commonware runtime.
    pub thread: std::thread::JoinHandle<()>,
    /// Outbound transaction forwarding.
    pub commands: mpsc::Sender<ForwardTransaction>,
    /// Transactions forwarded by other participants.
    pub events: mpsc::Receiver<ForwardedTransaction>,
}

/// Starts the Simplex network on a dedicated OS thread and runs `consensus` on its context.
///
/// The runtime stops when `consensus` returns, the network fails, or `shutdown` is cancelled.
/// `consensus` returning `Ok` is still reported as an unexpected stop.
pub fn spawn_simplex<F, Fut>(
    config: P2pConfig,
    network_id: P2pNetworkId,
    worker_threads: usize,
    consensus: F,
) -> eyre::Result<SimplexHandle>
where
    F: FnOnce(commonware_runtime::tokio::Context, SimplexNetwork) -> Fut + Send + 'static,
    Fut: Future<Output = eyre::Result<()>> + Send + 'static,
{
    let shutdown = CancellationToken::new();
    let thread_shutdown = shutdown.clone();
    let (stopped_tx, stopped) = oneshot::channel();
    let (commands, command_rx) = mpsc::channel(COMMAND_BACKLOG);
    let (events_tx, events) = mpsc::channel(EVENT_BACKLOG);

    let thread = std::thread::Builder::new()
        .name("zone-simplex".to_owned())
        .spawn(move || {
            let result = run(
                config,
                network_id,
                worker_threads,
                thread_shutdown,
                command_rx,
                events_tx,
                consensus,
            )
            .map_err(|err| format!("{err:?}"));
            let _ = stopped_tx.send(result);
        })
        .map_err(|err| eyre::eyre!("failed spawning Simplex runtime thread: {err}"))?;

    Ok(SimplexHandle {
        shutdown,
        stopped,
        thread,
        commands,
        events,
    })
}

fn run<F, Fut>(
    config: P2pConfig,
    network_id: P2pNetworkId,
    worker_threads: usize,
    shutdown: CancellationToken,
    commands: mpsc::Receiver<ForwardTransaction>,
    events: mpsc::Sender<ForwardedTransaction>,
    consensus: F,
) -> eyre::Result<()>
where
    F: FnOnce(commonware_runtime::tokio::Context, SimplexNetwork) -> Fut + Send + 'static,
    Fut: Future<Output = eyre::Result<()>> + Send + 'static,
{
    let mut runtime_config = commonware_runtime::tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(worker_threads)
        .with_catch_panics(true);
    if let Some(directory) = config.storage_directory() {
        runtime_config = runtime_config.with_storage_directory(directory.to_owned());
    }
    commonware_runtime::tokio::Runner::new(runtime_config).start(|context| async move {
        let local = config.ed25519_public_key();
        let manifest = config.manifest().clone();
        let private_key = config.ed25519_private_key();
        let (mut commonware, mut oracle, peers) = network::instantiate(
            &context,
            &manifest,
            config.zone_id(),
            private_key.clone(),
            config.listen(),
            config.bypass_ip_check(),
            network_id,
        )?;
        oracle.track(0, peers);

        let consensus_quota = Quota::per_second(NZU32!(128));
        let votes = commonware.register(VOTES_CHANNEL, consensus_quota);
        let certificates = commonware.register(CERTIFICATES_CHANNEL, consensus_quota);
        let resolver = commonware.register(RESOLVER_CHANNEL, consensus_quota);
        let broadcaster = commonware.register(BROADCASTER_CHANNEL, consensus_quota);
        let marshal = commonware.register(MARSHAL_CHANNEL, consensus_quota);
        let (transaction_sender, transaction_receiver) =
            commonware.register(TRANSACTIONS_CHANNEL, network::transaction_quota());
        let mut network_task = commonware.start();

        info!(
            target: "zone::simplex",
            ed25519_public_key = %local,
            listen = %config.listen(),
            participants = manifest.nodes().len(),
            "Started Simplex networking"
        );

        let participants: Vec<_> = manifest.participants().cloned().collect();
        let recipients = Arc::new(
            participants
                .iter()
                .filter(|peer| *peer != &local)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let simplex_network = SimplexNetwork {
            private_key,
            participants,
            oracle: oracle.clone(),
            namespace: network::namespace(config.zone_id(), network_id),
            max_message_size: network::MAX_MESSAGE_SIZE,
            votes,
            certificates,
            resolver,
            broadcaster,
            marshal,
        };
        let mut consensus_task = context
            .child("consensus")
            .spawn(move |context| consensus(context, simplex_network));

        let forward = forward_transactions(recipients, transaction_sender, commands);
        tokio::pin!(forward);
        let receive = receive_transactions(oracle, transaction_receiver, events);
        tokio::pin!(receive);

        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Ok(()),
            result = &mut network_task => match result {
                Ok(()) => Err(eyre::eyre!("Commonware network stopped unexpectedly")),
                Err(err) => Err(eyre::eyre!("Commonware network failed: {err}")),
            },
            result = &mut consensus_task => match result {
                Ok(Ok(())) => Err(eyre::eyre!("Simplex consensus stopped unexpectedly")),
                Ok(Err(err)) => Err(err.wrap_err("Simplex consensus failed")),
                Err(err) => Err(eyre::eyre!("Simplex consensus task failed: {err}")),
            },
            result = &mut forward => result,
            result = &mut receive => result,
        };
        if let Err(err) = &result {
            error!(target: "zone::simplex", %err, "Simplex runtime stopping");
        }

        context
            .stop(0, Some(SHUTDOWN_TIMEOUT))
            .await
            .map_err(|err| eyre::eyre!("failed stopping Commonware runtime: {err}"))?;
        result
    })
}

/// Send every locally originated transaction to all other participants.
///
/// Forwarding to all of them, rather than to the current leader, means every future Simplex leader
/// already holds the transaction when its view starts.
async fn forward_transactions(
    recipients: Arc<Vec<PublicKey>>,
    mut sender: lookup::Sender<PublicKey, commonware_runtime::tokio::Context>,
    mut commands: mpsc::Receiver<ForwardTransaction>,
) -> eyre::Result<()> {
    while let Some(ForwardTransaction {
        transaction_hash,
        transaction,
    }) = commands.recv().await
    {
        if transaction.len() > MAX_TRANSACTION_MESSAGE_SIZE {
            metrics::counter!(
                "zone_p2p_oversized_messages_dropped_total",
                "channel" => "transaction",
                "direction" => "outbound",
            )
            .increment(1);
            warn!(
                target: "zone::simplex",
                ?transaction_hash,
                transaction_size_bytes = transaction.len(),
                "Dropping oversized forwarded transaction"
            );
            continue;
        }
        let admitted = sender.send(
            Recipients::Some(recipients.as_ref().clone()),
            transaction,
            false,
        );
        if admitted.is_empty() && !recipients.is_empty() {
            metrics::counter!("zone_p2p_transaction_sends_without_peers_total").increment(1);
            debug!(target: "zone::simplex", ?transaction_hash, "Transaction forwarding reached no peer");
        }
    }
    Err(eyre::eyre!(
        "transaction command channel closed unexpectedly"
    ))
}

/// Relay transactions forwarded by authenticated participants to the node's pool.
async fn receive_transactions(
    mut blocker: lookup::Oracle<PublicKey>,
    mut receiver: lookup::Receiver<PublicKey>,
    events: mpsc::Sender<ForwardedTransaction>,
) -> eyre::Result<()> {
    loop {
        let (peer, bytes) = commonware_p2p::Receiver::recv(&mut receiver)
            .await
            .map_err(|err| eyre::eyre!("transaction channel receive failed: {err}"))?;
        let transaction = match into_bounded_payload(bytes, MAX_TRANSACTION_MESSAGE_SIZE) {
            Ok(transaction) => transaction,
            Err(size) => {
                commonware_p2p::block!(
                    blocker,
                    peer,
                    transaction_size_bytes = size,
                    "Blocking peer for oversized forwarded transaction"
                );
                continue;
            }
        };
        metrics::counter!("zone_p2p_transactions_received_total").increment(1);
        events
            .send(ForwardedTransaction { peer, transaction })
            .await
            .map_err(|_| eyre::eyre!("Simplex event channel closed"))?;
    }
}

fn into_bounded_payload(bytes: IoBuf, max_size: usize) -> Result<Vec<u8>, usize> {
    let size = bytes.len();
    if size > max_size {
        return Err(size);
    }
    Ok(bytes.into())
}
