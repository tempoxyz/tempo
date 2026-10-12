use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{Address as EthereumAddress, B256};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{AddressableManager as _, Recipients, Sender as _, authenticated::lookup};
use commonware_runtime::{IoBuf, Runner as _, Spawner as _};
use eyre::WrapErr as _;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    LeadershipSchedule, P2pNetworkId, Role, ZoneManifest,
    backfill::{
        BackfillCommand, BackfillCoordinator, BackfillPorts, BackfillRequest, BackfillResponse,
        BackfillRuntimeChannels,
    },
    capabilities::PeerCapabilities,
    identity::{Ed25519Identity, Secp256k1Identity},
    network::{
        self, BACKFILL_REQUEST_CHANNEL, BACKFILL_RESPONSE_CHANNEL, BLOCK_CHANNEL, MAX_MESSAGE_SIZE,
        MAX_TRANSACTION_MESSAGE_SIZE, SETTLEMENT_PROPOSAL_CHANNEL, SETTLEMENT_SIGNATURE_CHANNEL,
        TRANSACTION_CHANNEL,
    },
    protocol::EncodedBlock,
    routing::{RoutingMembership, RoutingPolicy},
};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const BROADCAST_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const BROADCAST_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_BACKLOG: usize = 128;
const EVENT_BACKLOG: usize = 128;

type CommonwareSender = lookup::Sender<PublicKey, commonware_runtime::tokio::Context>;
type CommonwareReceiver = lookup::Receiver<PublicKey>;

fn into_bounded_payload(bytes: IoBuf, max_size: usize) -> Result<Vec<u8>, usize> {
    let size = bytes.len();
    if size > max_size {
        return Err(size);
    }
    Ok(bytes.into())
}

struct P2pSenders {
    blocks: CommonwareSender,
    settlement_proposals: CommonwareSender,
    settlement_signatures: CommonwareSender,
    transactions: CommonwareSender,
}

struct P2pReceivers<R = CommonwareReceiver> {
    blocks: R,
    settlement_proposals: R,
    settlement_signatures: R,
    transactions: R,
}

struct BackfillNodeChannels {
    commands: mpsc::Receiver<BackfillCommand>,
    requests: mpsc::Sender<BackfillRequest>,
    responses: mpsc::Sender<BackfillResponse>,
}

/// Fully validated configuration for one node's Zone P2P runtime.
#[derive(Clone)]
pub struct P2pConfig {
    zone_id: u32,
    manifest: Arc<ZoneManifest>,
    ed25519_identity: Ed25519Identity,
    // This individual node key will be used to sign zone blocks for the on-chain quorum.
    // `None` on an `rpc_only` node: it never signs, so it is not provisioned with quorum key
    // material at all.
    secp256k1_identity: Option<Secp256k1Identity>,
    listen: SocketAddr,
    bypass_ip_check: bool,
    leadership: LeadershipSchedule,
    storage_directory: Option<PathBuf>,
}

impl P2pConfig {
    /// Loads the Commonware Ed25519 key and manifest, then validates this node's membership and
    /// optional role assertion. `zone_id` comes from the node's genesis configuration.
    ///
    /// `secp256k1_key_path` is required for a quorum member and rejected for an `rpc_only`
    /// node; [`ZoneManifest::validate_node`] enforces the correspondence.
    pub fn load(
        manifest_path: impl AsRef<Path>,
        ed25519_key_path: impl AsRef<Path>,
        secp256k1_key_path: Option<impl AsRef<Path>>,
        listen: SocketAddr,
        bypass_ip_check: bool,
        zone_id: u32,
        asserted_role: Option<Role>,
    ) -> eyre::Result<Self> {
        let ed25519_identity = Ed25519Identity::read_from_file(ed25519_key_path)?;
        let secp256k1_identity = secp256k1_key_path
            .map(Secp256k1Identity::read_from_file)
            .transpose()?;
        let manifest = ZoneManifest::read_from_file(manifest_path)?;
        validate_ip_check_configuration(&manifest, bypass_ip_check)?;
        manifest.validate_node(
            &ed25519_identity.ed25519_public_key(),
            secp256k1_identity.as_ref().map(Secp256k1Identity::address),
            asserted_role,
        )?;
        // The schedule starts uninitialized but already carries the manifest's static quorum
        // membership. The node seeds the transitions from the finalized portal snapshot at the
        // local Tempo checkpoint before any role-dependent task starts.
        let leadership = manifest.leadership_schedule();
        Ok(Self {
            zone_id,
            manifest: Arc::new(manifest),
            ed25519_identity,
            secp256k1_identity,
            listen,
            bypass_ip_check,
            leadership,
            storage_directory: None,
        })
    }

    /// The shared leadership schedule for this node.
    pub fn leadership(&self) -> LeadershipSchedule {
        self.leadership.clone()
    }

    /// The validated static topology manifest.
    pub fn manifest(&self) -> &Arc<ZoneManifest> {
        &self.manifest
    }

    /// This node's Ed25519 public key used by Commonware.
    pub fn ed25519_public_key(&self) -> PublicKey {
        self.ed25519_identity.ed25519_public_key()
    }

    /// Whether this node replicates without joining the on-chain settlement quorum.
    pub fn is_rpc_only(&self) -> bool {
        self.leadership.is_rpc_only(&self.ed25519_public_key())
    }

    /// This node's address derived from its individual secp256k1 key, when it holds one.
    pub fn secp256k1_address(&self) -> Option<EthereumAddress> {
        self.secp256k1_identity
            .as_ref()
            .map(Secp256k1Identity::address)
    }

    /// Signer used for EIP-712 zone-block attestations, when this node is a quorum member.
    pub fn block_attestation_signer(&self) -> Option<alloy_signer_local::PrivateKeySigner> {
        self.secp256k1_identity
            .as_ref()
            .map(Secp256k1Identity::signer)
    }

    /// Expected attestation address for every quorum peer.
    ///
    /// RPC-only members are deliberately absent: they never sign, so a signature claiming to
    /// come from one has no registered address to match and is rejected.
    pub fn block_attestation_addresses(&self) -> HashMap<PublicKey, EthereumAddress> {
        self.manifest
            .quorum_nodes()
            .map(|(node, address)| (node.ed25519_public_key().clone(), address))
            .collect()
    }

    /// Local socket bound by Commonware.
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Zone ID included in each block attestation.
    pub fn zone_id(&self) -> u32 {
        self.zone_id
    }

    /// Sets the Commonware runtime's storage directory, including its startup lock file.
    /// Defaults to Commonware's temporary directory when not configured.
    pub fn with_storage_directory(mut self, directory: PathBuf) -> Self {
        self.storage_directory = Some(directory);
        self
    }
}

impl std::fmt::Debug for P2pConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pConfig")
            .field("zone_id", &self.zone_id)
            .field("ed25519_public_key", &self.ed25519_public_key())
            .field("secp256k1_address", &self.secp256k1_address())
            .field("listen", &self.listen)
            .field("bypass_ip_check", &self.bypass_ip_check)
            .field("leadership", &self.leadership.latest())
            .finish_non_exhaustive()
    }
}

fn validate_ip_check_configuration(
    manifest: &ZoneManifest,
    bypass_ip_check: bool,
) -> eyre::Result<()> {
    eyre::ensure!(
        !manifest.has_dns_addresses() || bypass_ip_check,
        "DNS peer addresses require --p2p.bypass-ip-check because their egress IPs are not known; this disables pre-authentication source-IP filtering for all inbound P2P connections"
    );
    Ok(())
}

/// Outbound protocol commands accepted by the dedicated P2P runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pCommand {
    /// Broadcast a block and its optional witness to every peer.
    BroadcastBlock(EncodedBlock),
    /// Broadcast one ABI-encoded settlement proposal to all followers.
    BroadcastSettlementProposal(Vec<u8>),
    /// Return one ABI-encoded settlement signature to the leader that proposed it.
    SendSettlementSignature {
        /// The peer whose proposal this signature answers.
        leader: PublicKey,
        signature: Vec<u8>,
    },
    /// Forward one canonical EIP-2718 transaction to every other quorum member.
    ForwardTransaction {
        transaction_hash: B256,
        transaction: Vec<u8>,
    },
}

/// Observable lifecycle and block events emitted by the P2P runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pEvent {
    /// The network and block channel were started.
    Started {
        ed25519_public_key: PublicKey,
        listen: SocketAddr,
    },
    /// A follower received an encoded sealed block from its configured leader.
    BlockReceived {
        leader_ed25519_public_key: PublicKey,
        block: Vec<u8>,
    },
    /// A follower received a proposed settlement statement from the leader.
    SettlementProposalReceived {
        leader: PublicKey,
        proposal: Vec<u8>,
    },
    /// The leader received a settlement signature from a follower.
    SettlementSignatureReceived {
        follower: PublicKey,
        signature: Vec<u8>,
    },
    /// A quorum member received a raw transaction from an authenticated follower.
    TransactionReceived {
        follower_ed25519_public_key: PublicKey,
        transaction: Vec<u8>,
    },
}

/// Handle used to communicate with, supervise, and stop the dedicated P2P runtime.
pub struct P2pHandle {
    parts: Option<P2pHandleParts>,
}

/// Cross-runtime channels and lifecycle controls returned by [`P2pHandle::into_parts`].
pub struct P2pHandleParts {
    /// Cancels the dedicated P2P runtime.
    pub shutdown: CancellationToken,
    /// Resolves when the dedicated P2P runtime exits.
    pub stopped: oneshot::Receiver<Result<(), String>>,
    /// OS thread hosting the dedicated Commonware runtime.
    pub thread: std::thread::JoinHandle<()>,
    /// Bounded outbound command channel into the dedicated P2P runtime.
    pub commands: mpsc::Sender<P2pCommand>,
    /// Bounded inbound event channel from the dedicated P2P runtime.
    pub events: mpsc::Receiver<P2pEvent>,
    /// Typed backfill command, request, and response channels.
    pub backfill: BackfillPorts,
}

impl P2pHandle {
    /// Returns the inbound P2P event channel.
    pub fn events_mut(&mut self) -> &mut mpsc::Receiver<P2pEvent> {
        &mut self
            .parts
            .as_mut()
            .expect("P2P handle already consumed")
            .events
    }

    /// Requests shutdown, waits for the Commonware runtime, and joins its OS thread.
    pub async fn shutdown(mut self) -> eyre::Result<()> {
        let P2pHandleParts {
            shutdown,
            stopped,
            thread,
            commands,
            events,
            backfill,
        } = self.parts.take().expect("P2P handle already consumed");
        shutdown.cancel();

        // Close the caller-side channels while the runtime is winding down.
        drop(commands);
        drop(events);
        drop(backfill);
        let stopped_result = stopped.await;

        join_runtime_thread(thread).await?;
        stopped_result
            .map_err(|err| eyre::eyre!("P2P runtime dropped its completion channel: {err}"))?
            .map_err(|err| eyre::eyre!("P2P runtime failed: {err}"))
    }

    /// Splits the handle into the pieces needed by a node supervisor.
    pub fn into_parts(mut self) -> P2pHandleParts {
        self.parts.take().expect("P2P handle already consumed")
    }
}

impl Drop for P2pHandle {
    fn drop(&mut self) {
        if let Some(parts) = &self.parts {
            parts.shutdown.cancel();
        }
    }
}

async fn join_runtime_thread(thread: std::thread::JoinHandle<()>) -> eyre::Result<()> {
    tokio::task::spawn_blocking(move || thread.join())
        .await
        .map_err(|err| eyre::eyre!("failed joining P2P runtime thread: {err}"))?
        .map_err(|_| eyre::eyre!("P2P runtime thread panicked"))
}

/// Starts Commonware block transport on a dedicated OS thread.
pub fn spawn_p2p(config: P2pConfig, network_id: P2pNetworkId) -> eyre::Result<P2pHandle> {
    let shutdown = CancellationToken::new();
    let thread_shutdown = shutdown.clone();
    let (stopped_tx, stopped) = oneshot::channel();
    let (commands, command_rx) = mpsc::channel(COMMAND_BACKLOG);
    let (events_tx, events) = mpsc::channel(EVENT_BACKLOG);
    let (backfill_commands, backfill_command_rx) = mpsc::channel(COMMAND_BACKLOG);
    let (backfill_requests_tx, backfill_requests) = mpsc::channel(EVENT_BACKLOG);
    let (backfill_responses_tx, backfill_responses) = mpsc::channel(EVENT_BACKLOG);

    let thread = std::thread::Builder::new()
        .name("zone-p2p".to_owned())
        .spawn(move || {
            let result = run(
                config,
                network_id,
                thread_shutdown,
                command_rx,
                events_tx,
                BackfillNodeChannels {
                    commands: backfill_command_rx,
                    requests: backfill_requests_tx,
                    responses: backfill_responses_tx,
                },
            )
            .map_err(|err| format!("{err:?}"));
            let _ = stopped_tx.send(result);
        })
        .map_err(|err| eyre::eyre!("failed spawning P2P runtime thread: {err}"))?;

    Ok(P2pHandle {
        parts: Some(P2pHandleParts {
            shutdown,
            stopped,
            thread,
            commands,
            events,
            backfill: BackfillPorts {
                commands: backfill_commands,
                requests: backfill_requests,
                responses: backfill_responses,
            },
        }),
    })
}

fn run(
    config: P2pConfig,
    network_id: P2pNetworkId,
    shutdown: CancellationToken,
    command_rx: mpsc::Receiver<P2pCommand>,
    events: mpsc::Sender<P2pEvent>,
    backfill: BackfillNodeChannels,
) -> eyre::Result<()> {
    let mut runtime_config = commonware_runtime::tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(2)
        .with_catch_panics(true);
    if let Some(directory) = &config.storage_directory {
        runtime_config = runtime_config.with_storage_directory(directory.clone());
    }
    commonware_runtime::tokio::Runner::new(runtime_config).start(|context| async move {
        let local_ed25519_public_key = config.ed25519_public_key();
        let leadership = config.leadership();
        let (mut commonware, mut oracle, peers) = network::instantiate(
            &context,
            &config.manifest,
            config.zone_id,
            config.ed25519_identity.into_private_key(),
            config.listen,
            config.bypass_ip_check,
            network_id,
        )?;
        oracle.track(0, peers);
        let (block_sender, block_receiver) =
            commonware.register(BLOCK_CHANNEL, network::block_quota());
        let (settlement_proposal_sender, settlement_proposal_receiver) = commonware.register(
            SETTLEMENT_PROPOSAL_CHANNEL,
            network::settlement_quota(),
        );
        let (settlement_signature_sender, settlement_signature_receiver) = commonware.register(
            SETTLEMENT_SIGNATURE_CHANNEL,
            network::settlement_quota(),
        );

        // The backfill request and responses are on separate channels
        let (backfill_request_sender, backfill_request_receiver) = commonware.register(
            BACKFILL_REQUEST_CHANNEL,
            network::backfill_request_quota(),
        );
        let (backfill_response_sender, backfill_response_receiver) = commonware.register(
            BACKFILL_RESPONSE_CHANNEL,
            network::backfill_response_quota(),
        );
        let (transaction_sender, transaction_receiver) = commonware.register(
            TRANSACTION_CHANNEL,
            network::transaction_quota(),
        );
        let mut network_task = commonware.start();

        if config.bypass_ip_check {
            warn!(
                target: "zone::p2p",
                "P2P source-IP filtering is disabled; relying on network-level access controls and manifest Ed25519 public keys"
            );
        }

        info!(
            target: "zone::p2p",
            zone_id = config.zone_id,
            ed25519_public_key = %local_ed25519_public_key,
            listen = %config.listen,
            peers = config.manifest.nodes().len(),
            "Started P2P networking"
        );

        let _ = events
            .send(P2pEvent::Started {
                ed25519_public_key: local_ed25519_public_key.clone(),
                listen: config.listen,
            })
            .await;

        let membership = RoutingMembership::from_manifest(&config.manifest);
        let capabilities = PeerCapabilities::default();

        let command_loop = run_commands(
            local_ed25519_public_key.clone(),
            membership.clone(),
            leadership.clone(),
            capabilities.clone(),
            P2pSenders {
                blocks: block_sender,
                settlement_proposals: settlement_proposal_sender,
                settlement_signatures: settlement_signature_sender,
                transactions: transaction_sender,
            },
            command_rx,
        );
        tokio::pin!(command_loop);

        let receive_loop = run_receivers(
            local_ed25519_public_key.clone(),
            membership.clone(),
            leadership.clone(),
            oracle,
            P2pReceivers {
                blocks: block_receiver,
                settlement_proposals: settlement_proposal_receiver,
                settlement_signatures: settlement_signature_receiver,
                transactions: transaction_receiver,
            },
            events,
        );
        tokio::pin!(receive_loop);

        let backfill_loop = BackfillCoordinator::new(
            local_ed25519_public_key,
            membership,
            leadership,
            capabilities,
            BackfillRuntimeChannels {
                request_sender: backfill_request_sender,
                request_receiver: backfill_request_receiver,
                response_sender: backfill_response_sender,
                response_receiver: backfill_response_receiver,
                commands: backfill.commands,
                requests: backfill.requests,
                responses: backfill.responses,
            },
        )
        .run();
        tokio::pin!(backfill_loop);

        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Ok(()),
            network_result = &mut network_task => match network_result {
                Ok(()) => Err(eyre::eyre!("Commonware network stopped unexpectedly")),
                Err(err) => Err(eyre::eyre!("Commonware network failed: {err}")),
            },
            result = &mut command_loop => result,
            result = &mut receive_loop => result,
            result = &mut backfill_loop => result,
        };

        context
            .stop(0, Some(SHUTDOWN_TIMEOUT))
            .await
            .map_err(|err| eyre::eyre!("failed stopping Commonware runtime: {err}"))?;
        result
    })
}

async fn run_commands(
    local_ed25519_public_key: PublicKey,
    membership: RoutingMembership,
    leadership: LeadershipSchedule,
    capabilities: PeerCapabilities,
    mut senders: P2pSenders,
    mut commands: mpsc::Receiver<P2pCommand>,
) -> eyre::Result<()> {
    while let Some(command) = commands.recv().await {
        match command {
            P2pCommand::BroadcastBlock(block) => {
                // Mirror of the inbound transport check: the sender must lead somewhere in
                // the retained schedule; every importer applies the exact
                // `producer == leader_for(anchor)` fence. Recipients are all other manifest
                // members — during a scheduled handoff the incoming leader must keep
                // receiving live blocks.
                let policy =
                    RoutingPolicy::new(&local_ed25519_public_key, &membership, &leadership);
                let (may_broadcast, recipients) =
                    (policy.may_broadcast_block(), policy.block_recipients());
                if !may_broadcast {
                    metrics::counter!("zone_p2p_role_invalid_messages_dropped_total").increment(1);
                    warn!(target: "zone::p2p", "Ignoring live block broadcast command without retained scheduled leadership");
                    continue;
                }

                let encoded = block.encode();
                if encoded.len() > MAX_MESSAGE_SIZE as usize {
                    error!(target: "zone::p2p", block_size_bytes = encoded.len(), max_message_size_bytes = MAX_MESSAGE_SIZE, "Canonical block exceeds the P2P message size limit; block was not broadcast");
                    continue;
                }

                let admitted = tokio::time::timeout(BROADCAST_RETRY_TIMEOUT, async {
                    loop {
                        let now = Instant::now();
                        let (witness_peers, legacy_peers): (Vec<_>, Vec<_>) = recipients.iter()
                            .cloned()
                            .partition(|peer| capabilities.supports_witnesses(peer, now));
                        let mut admitted = Vec::new();
                        for (peers, witnesses) in [(legacy_peers, false), (witness_peers, true)] {
                            if peers.is_empty() {
                                continue;
                            }
                            let payload = if witnesses { encoded.clone() } else { block.block.clone() };
                            admitted.extend(senders.blocks.send(Recipients::Some(peers), payload, true));
                        }
                        if !admitted.is_empty() || recipients.is_empty() {
                            break admitted;
                        }
                        debug!(target: "zone::p2p", "Canonical block broadcast was not admitted; retrying");
                        tokio::time::sleep(BROADCAST_RETRY_INTERVAL).await;
                    }
                }).await;
                let admitted = match admitted {
                    Ok(admitted) => admitted,
                    Err(_) => {
                        warn!(target: "zone::p2p", timeout_secs = BROADCAST_RETRY_TIMEOUT.as_secs(), "Canonical block broadcast was not admitted before timing out");
                        continue;
                    }
                };
                if admitted.len() != recipients.len() {
                    debug!(target: "zone::p2p", admitted = admitted.len(), configured = recipients.len(), "Canonical block broadcast was not admitted for every recipient");
                }
            }

            P2pCommand::BroadcastSettlementProposal(proposal) => {
                let policy =
                    RoutingPolicy::new(&local_ed25519_public_key, &membership, &leadership);
                let recipients = policy
                    .may_broadcast_settlement_proposal()
                    .then(|| policy.settlement_proposal_recipients());
                let Some(recipients) = recipients else {
                    metrics::counter!("zone_p2p_role_invalid_messages_dropped_total").increment(1);
                    warn!(target: "zone::p2p", "Ignoring settlement proposal command without retained scheduled leadership");
                    continue;
                };
                // Only quorum members sign, so only they are asked. An RPC-only standby that
                // received a proposal would have nothing to answer it with.
                let _ =
                    senders
                        .settlement_proposals
                        .send(Recipients::Some(recipients), proposal, true);
            }

            P2pCommand::SendSettlementSignature { leader, signature } => {
                // The signature answers a specific proposal, so it returns to that
                // proposal's sender (not to the most recent leader. Important during handoff)
                let may_send =
                    RoutingPolicy::new(&local_ed25519_public_key, &membership, &leadership)
                        .may_send_settlement_signature(&leader);
                if !may_send {
                    metrics::counter!("zone_p2p_role_invalid_messages_dropped_total").increment(1);
                    warn!(target: "zone::p2p", %leader, "Ignoring settlement signature addressed to a peer without retained scheduled leadership");
                    continue;
                }
                let _ = senders.settlement_signatures.send(
                    Recipients::Some(vec![leader]),
                    signature,
                    true,
                );
            }

            P2pCommand::ForwardTransaction {
                transaction_hash,
                transaction,
            } => {
                // Only followers run the transaction-forwarding task. Keep the outbound role
                // fence, but send to every other quorum member so every possible successor
                // retains the transaction before a leadership handoff. RPC-only standbys can
                // originate transactions but never need to retain transactions from other nodes.
                let policy =
                    RoutingPolicy::new(&local_ed25519_public_key, &membership, &leadership);
                let forwarding = policy.transaction_forwarding_status();
                let (may_forward, initialized, recipients) = (
                    forwarding.unwrap_or(false),
                    forwarding.is_some(),
                    policy.transaction_recipients(),
                );
                if !may_forward {
                    if !initialized {
                        metrics::counter!(
                            "zone_p2p_uninitialized_leadership_commands_dropped_total"
                        )
                        .increment(1);
                        warn!(target: "zone::p2p", ?transaction_hash, "Dropping forwarded transaction while leadership is uninitialized");
                    } else {
                        metrics::counter!("zone_p2p_role_invalid_messages_dropped_total")
                            .increment(1);
                        warn!(target: "zone::p2p", ?transaction_hash, "Ignoring outbound transaction command on the next-anchor leader");
                    }
                    continue;
                }
                if transaction.len() > MAX_TRANSACTION_MESSAGE_SIZE {
                    metrics::counter!(
                        "zone_p2p_oversized_messages_dropped_total",
                        "channel" => "transaction",
                        "direction" => "outbound",
                    )
                    .increment(1);
                    warn!(
                        target: "zone::p2p",
                        ?transaction_hash,
                        transaction_size_bytes = transaction.len(),
                        max_transaction_size_bytes = MAX_TRANSACTION_MESSAGE_SIZE,
                        "Dropping oversized forwarded transaction"
                    );
                    continue;
                }
                let configured = recipients.len();
                let transaction_size = transaction.len();
                let admitted =
                    senders
                        .transactions
                        .send(Recipients::Some(recipients), transaction, false);
                if admitted.is_empty() {
                    metrics::counter!("zone_p2p_transaction_sends_without_peers_total")
                        .increment(1);
                    warn!(target: "zone::p2p", ?transaction_hash, configured, transaction_size_bytes = transaction_size, "Transaction forwarding was not admitted for any quorum peer; dropping this send attempt");
                } else {
                    debug!(target: "zone::p2p", ?transaction_hash, admitted = admitted.len(), configured, transaction_size_bytes = transaction_size, "Submitted transaction forwarding to quorum peers");
                }
            }
        }
    }

    Err(eyre::eyre!("P2P command channel closed unexpectedly"))
}

async fn run_receivers<R, B>(
    local_ed25519_public_key: PublicKey,
    membership: RoutingMembership,
    leadership: LeadershipSchedule,
    mut blocker: B,
    receivers: P2pReceivers<R>,
    events: mpsc::Sender<P2pEvent>,
) -> eyre::Result<()>
where
    R: commonware_p2p::Receiver<PublicKey = PublicKey>,
    B: commonware_p2p::Blocker<PublicKey = PublicKey>,
{
    let P2pReceivers {
        mut blocks,
        mut settlement_proposals,
        mut settlement_signatures,
        mut transactions,
    } = receivers;

    loop {
        let event = tokio::select! {
            // Got a block
            result = blocks.recv() => {
                let (peer, bytes) = result.map_err(|err| eyre::eyre!("block channel receive failed: {err}"))?;
                // Commonware authenticates every sender against the manifest. The importer
                // applies the authoritative `sender == leader_for(block anchor)` fence after
                // decoding the block and observing its Tempo anchor.
                P2pEvent::BlockReceived { leader_ed25519_public_key: peer, block: bytes.into() }
            }

            // Got a settlement proposal at a batch boundary
            result = settlement_proposals.recv() => {
                let (peer, bytes) = result.wrap_err("settlement proposal channel receive failed")?;
                // The proposer must lead somewhere in the retained schedule — during a scheduled handoff the
                // outgoing leader still settles pre-boundary batches. The follower rebuilds
                // the proposal from its own state before signing. An RPC-only member drops the
                // proposal here: only the on-chain quorum signs.
                let may_accept = RoutingPolicy::new(
                    &local_ed25519_public_key,
                    &membership,
                    &leadership,
                )
                .may_accept_settlement_proposal(&peer);
                if !may_accept {
                    warn!(target: "zone::p2p", %peer, "Ignoring settlement proposal from ineligible peer");
                    continue;
                }
                P2pEvent::SettlementProposalReceived { leader: peer, proposal: bytes.into() }
            }

            // Got a response from a follower to the settlement proposal
            result = settlement_signatures.recv() => {
                let (peer, bytes) = result.wrap_err("settlement signature channel receive failed")?;
                // An RPC-only member has no address registered with `ZonePortal`, so its
                // signature could never be counted; reject it at the transport instead of
                // relying on the attestation-address lookup further in.
                let may_accept = RoutingPolicy::new(
                    &local_ed25519_public_key,
                    &membership,
                    &leadership,
                )
                .may_accept_settlement_signature(&peer);
                if !may_accept {
                    warn!(target: "zone::p2p", %peer, "Ignoring settlement signature from ineligible peer");
                    continue;
                }
                P2pEvent::SettlementSignatureReceived { follower: peer, signature: bytes.into() }
            }

            // Got a transaction forwarded by an authenticated manifest peer. Only quorum members
            // admit these into their pools; RPC-only standbys can never become leader.
            result = transactions.recv() => {
                let (peer, bytes) = result.map_err(|err| eyre::eyre!("transaction channel receive failed: {err}"))?;
                let transaction = match into_bounded_payload(bytes, MAX_TRANSACTION_MESSAGE_SIZE) {
                    Ok(transaction) => transaction,
                    Err(size) => {
                        metrics::counter!(
                            "zone_p2p_oversized_messages_dropped_total",
                            "channel" => "transaction",
                            "direction" => "inbound",
                        )
                        .increment(1);
                        commonware_p2p::block!(
                            blocker,
                            peer,
                            transaction_size_bytes = size,
                            max_transaction_size_bytes = MAX_TRANSACTION_MESSAGE_SIZE,
                            "Blocking peer for oversized forwarded transaction"
                        );
                        continue;
                    }
                };
                let may_accept = RoutingPolicy::new(
                    &local_ed25519_public_key,
                    &membership,
                    &leadership,
                )
                .may_accept_transaction(&peer);
                if !may_accept {
                    metrics::counter!("zone_p2p_role_invalid_messages_dropped_total").increment(1);
                    warn!(target: "zone::p2p", %peer, "Ignoring transaction from role-invalid peer");
                    continue;
                }
                metrics::counter!("zone_p2p_transactions_received_total").increment(1);
                P2pEvent::TransactionReceived {
                    follower_ed25519_public_key: peer,
                    transaction,
                }
            }
        };
        events
            .send(event)
            .await
            .map_err(|_| eyre::eyre!("P2P event channel closed"))?;
    }
}

#[cfg(test)]
mod tests {

    use std::{
        io,
        net::{SocketAddr, TcpListener},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use alloy_primitives::{Address, B256};
    use commonware_actor::Feedback;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::IoBuf;

    use super::{
        P2pCommand, P2pConfig, P2pEvent, P2pReceivers, into_bounded_payload, run_receivers,
        spawn_p2p, validate_ip_check_configuration,
    };
    use crate::{
        P2pHandle, P2pHandleParts, P2pNetworkId, ZoneManifest,
        identity::{Ed25519Identity, Secp256k1Identity},
        network::MAX_TRANSACTION_MESSAGE_SIZE,
        routing::RoutingMembership,
    };

    #[derive(Debug)]
    struct MockReceiver {
        receiver: tokio::sync::mpsc::UnboundedReceiver<commonware_p2p::Message<PublicKey>>,
    }

    impl commonware_p2p::Receiver for MockReceiver {
        type Error = io::Error;
        type PublicKey = PublicKey;

        async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingBlocker {
        blocked: Arc<Mutex<Vec<PublicKey>>>,
    }

    impl commonware_p2p::Blocker for RecordingBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, peer: Self::PublicKey) -> Feedback {
            self.blocked.lock().unwrap().push(peer);
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            panic!("receiver tests do not subscribe to blocked peers")
        }
    }

    fn mock_receiver() -> (
        tokio::sync::mpsc::UnboundedSender<commonware_p2p::Message<PublicKey>>,
        MockReceiver,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        (sender, MockReceiver { receiver })
    }

    fn test_tip(zone_height: u64) -> crate::PeerTip {
        crate::PeerTip {
            zone_height,
            zone_hash: B256::with_last_byte(zone_height as u8),
            tempo_block_number: zone_height + 1000,
            tempo_block_hash: B256::with_last_byte((zone_height + 1) as u8),
        }
    }

    fn available_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    fn ed25519_identity(seed: u64) -> Ed25519Identity {
        let key = PrivateKey::from_seed(seed);
        Ed25519Identity::from_hex(&const_hex::encode_prefixed(key.encode().as_ref())).unwrap()
    }

    fn secp256k1_identity(seed: u64) -> Secp256k1Identity {
        Secp256k1Identity::from_hex(&format!("0x{seed:064x}")).unwrap()
    }

    #[test]
    fn bounded_payload_rejects_oversized_frames_before_event_allocation() {
        let accepted = into_bounded_payload(IoBuf::from(vec![0x11; 4]), 4).unwrap();
        assert_eq!(accepted, vec![0x11; 4]);

        let oversized = into_bounded_payload(IoBuf::from(vec![0x22; 5]), 4).unwrap_err();
        assert_eq!(oversized, 5);
    }

    /// Resend `command` until the test drops the returned handle.
    ///
    /// Commonware drops messages for peers that have not handshaked yet, so a phase that must be
    /// observed repeats its command until the expected peer sees it.
    fn repeat(
        commands: tokio::sync::mpsc::Sender<P2pCommand>,
        command: P2pCommand,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                commands.send(command.clone()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    }

    /// Stop a peer that may still be receiving traffic.
    ///
    /// Unlike [`P2pHandle::shutdown`], this keeps the event receiver alive until the runtime
    /// observes cancellation, so an in-flight `BlockReceived` cannot fail the runtime with
    /// "P2P event channel closed" during mid-test peer restarts.
    async fn shutdown_while_receiving(handle: P2pHandle) -> eyre::Result<()> {
        let P2pHandleParts {
            shutdown,
            stopped,
            thread,
            commands,
            events,
            backfill,
        } = handle.into_parts();
        shutdown.cancel();
        drop(commands);
        drop(backfill);
        let stopped_result = stopped.await;
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|err| eyre::eyre!("failed joining P2P runtime thread: {err}"))?
            .map_err(|_| eyre::eyre!("P2P runtime thread panicked"))?;
        drop(events);
        stopped_result
            .map_err(|err| eyre::eyre!("P2P runtime dropped its completion channel: {err}"))?
            .map_err(|err| eyre::eyre!("P2P runtime failed: {err}"))
    }

    /// Drain events for `duration`, failing if any of them satisfies `forbidden`.
    async fn assert_no_event_matching(
        events: &mut tokio::sync::mpsc::Receiver<P2pEvent>,
        duration: Duration,
        context: &str,
        forbidden: impl Fn(&P2pEvent) -> bool,
    ) {
        let result = tokio::time::timeout(duration, async {
            while let Some(event) = events.recv().await {
                assert!(!forbidden(&event), "{context}");
            }
        })
        .await;
        assert!(result.is_err(), "{context}: event channel closed");
    }

    /// Manifest TOML for a topology with one `rpc_only` standby.
    ///
    /// Node `index` gets `secp256k1_identity(seed_base + index)`, except the standby, which
    /// declares no address at all — the shape the loader requires.
    fn manifest_with_standby(
        identities: &[Ed25519Identity],
        addresses: &[SocketAddr],
        seed_base: u64,
        standby: usize,
    ) -> String {
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            let rpc_only = index == standby;
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\naddress = \"{address}\"\nrpc_only = {rpc_only}\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
            ));
            if !rpc_only {
                input.push_str(&format!(
                    "secp256k1_address = \"{}\"\n",
                    secp256k1_identity(seed_base + index as u64).address(),
                ));
            }
        }
        input
    }

    #[test]
    fn attestation_addresses_and_peer_sets_exclude_rpc_only_members() {
        let identities = [41_u64, 42, 43, 44].map(ed25519_identity);
        let addresses: Vec<SocketAddr> = (0..4)
            .map(|index| format!("127.0.0.1:{}", 9200 + index).parse().unwrap())
            .collect();
        let input = manifest_with_standby(&identities, &addresses, 41, 3);
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let config = P2pConfig {
            zone_id: 9,
            manifest: manifest.clone(),
            ed25519_identity: ed25519_identity(41),
            secp256k1_identity: Some(secp256k1_identity(41)),
            listen: available_address(),
            bypass_ip_check: false,
            storage_directory: None,
            leadership: manifest.leadership_schedule(),
        };

        // The standby has no registered address, so a signature claiming to be its has nothing
        // to match against and the leader cannot count it.
        let addresses = config.block_attestation_addresses();
        assert_eq!(addresses.len(), 3);
        assert!(!addresses.contains_key(&identities[3].ed25519_public_key()));
    }

    #[test]
    fn dns_manifest_requires_explicit_ip_check_bypass() {
        let identities = [
            ed25519_identity(1),
            ed25519_identity(2),
            ed25519_identity(3),
        ];
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, identity) in identities.iter().enumerate() {
            let secp256k1_identity = secp256k1_identity(index as u64 + 1);
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"node-{index}.zone.local:9200\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity.address(),
            ));
        }
        let manifest = ZoneManifest::parse(&input).unwrap();

        let error = validate_ip_check_configuration(&manifest, false).unwrap_err();
        assert!(error.to_string().contains("--p2p.bypass-ip-check"));
        validate_ip_check_configuration(&manifest, true).unwrap();
    }

    #[tokio::test]
    async fn oversized_inbound_transaction_blocks_peer_before_emitting_event() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [91_u64, 92, 93].map(ed25519_identity);
        let input = manifest_with_standby(&identities, &addresses, 91, usize::MAX);
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let membership = RoutingMembership::from_manifest(&manifest);
        let leadership = crate::LeadershipSchedule::seeded(manifest.bootstrap_leadership());
        let local_peer = identities[0].ed25519_public_key();
        let malicious_peer = identities[1].ed25519_public_key();

        let (_blocks_tx, blocks) = mock_receiver();
        let (_proposals_tx, settlement_proposals) = mock_receiver();
        let (_signatures_tx, settlement_signatures) = mock_receiver();
        let (transactions_tx, transactions) = mock_receiver();
        let (events_tx, mut events) = tokio::sync::mpsc::channel(4);
        let blocker = RecordingBlocker::default();
        let observed_blocker = blocker.clone();
        let receiver_task = tokio::spawn(run_receivers(
            local_peer,
            membership,
            leadership,
            blocker,
            P2pReceivers {
                blocks,
                settlement_proposals,
                settlement_signatures,
                transactions,
            },
            events_tx,
        ));

        transactions_tx
            .send((
                malicious_peer.clone(),
                IoBuf::from(vec![0; MAX_TRANSACTION_MESSAGE_SIZE + 1]),
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if observed_blocker
                    .blocked
                    .lock()
                    .unwrap()
                    .contains(&malicious_peer)
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("oversized transaction sender was not blocked");
        assert!(
            events.try_recv().is_err(),
            "oversized transaction reached the event queue"
        );
        receiver_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn witness_transport_requires_peer_announcements() {
        use commonware_p2p::{AddressableManager as _, Receiver as _, Recipients, Sender as _};
        use commonware_runtime::{Runner as _, Spawner as _};

        use crate::{
            EncodedBlock,
            capabilities::{ANNOUNCEMENT_INTERVAL, ANNOUNCEMENT_TTL, LOCAL_CAPABILITIES_VERSION},
            network,
            protocol::{DecodeError, RequestFrame, ResponseFrame},
        };

        enum Command {
            Advertise(bool),
            Request(RequestFrame),
        }
        #[derive(Debug)]
        enum Event {
            Block(Vec<u8>),
            Response(ResponseFrame),
            IgnoredAnnouncement,
        }

        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [301, 302, 303].map(ed25519_identity);
        let manifest = Arc::new(
            ZoneManifest::parse(&manifest_with_standby(
                &identities,
                &addresses,
                301,
                usize::MAX,
            ))
            .unwrap(),
        );
        let network_id = P2pNetworkId::new(1, Address::repeat_byte(0x11));
        let config = |index: usize| P2pConfig {
            zone_id: 9,
            manifest: manifest.clone(),
            ed25519_identity: ed25519_identity(301 + index as u64),
            secp256k1_identity: Some(secp256k1_identity(301 + index as u64)),
            listen: addresses[index],
            bypass_ip_check: false,
            storage_directory: None,
            leadership: crate::LeadershipSchedule::seeded(manifest.bootstrap_leadership()),
        };
        let mut leader = spawn_p2p(config(0), network_id).unwrap();
        let mut upgraded = spawn_p2p(config(2), network_id).unwrap();
        let legacy_config = config(1);
        let leader_peer = identities[0].ed25519_public_key();
        let legacy_peer = identities[1].ed25519_public_key();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let stop = shutdown.clone();
        let (commands, mut command_rx) = tokio::sync::mpsc::unbounded_channel();
        let (events, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

        // A wire-level legacy peer: only the original six Commonware channels, no
        // advertisements by default, and the old response tag check. Explicitly enabling
        // advertisements below simulates upgrading this peer without changing its identity.
        let legacy_thread = std::thread::spawn(move || {
            commonware_runtime::tokio::Runner::new(
                commonware_runtime::tokio::Config::default().with_worker_threads(2),
            ).start(|context| async move {
                let (mut network, mut oracle, peers) = network::instantiate(
                    &context, &legacy_config.manifest, legacy_config.zone_id,
                    legacy_config.ed25519_identity.into_private_key(), legacy_config.listen,
                    false, network_id,
                ).unwrap();
                oracle.track(0, peers);
                let (_, mut blocks) = network.register(network::BLOCK_CHANNEL, network::block_quota());
                let (mut requests, _) = network.register(network::BACKFILL_REQUEST_CHANNEL, network::backfill_request_quota());
                let (mut responses, mut backfill) = network.register(network::BACKFILL_RESPONSE_CHANNEL, network::backfill_response_quota());
                let _remaining = [network::TRANSACTION_CHANNEL, network::SETTLEMENT_PROPOSAL_CHANNEL, network::SETTLEMENT_SIGNATURE_CHANNEL]
                    .map(|channel| network.register(channel, network::settlement_quota()));
                let mut network_task = network.start();
                let mut advertise = false;
                let mut announcements = tokio::time::interval(ANNOUNCEMENT_INTERVAL);
                loop {
                    tokio::select! {
                        () = stop.cancelled() => break,
                        result = &mut network_task => panic!("legacy transport stopped: {result:?}"),
                        _ = announcements.tick(), if advertise => {
                            let _ = responses.send(Recipients::All, ResponseFrame::Capabilities(LOCAL_CAPABILITIES_VERSION).encode().unwrap(), false);
                        }
                        command = command_rx.recv() => match command {
                            None => break,
                            Some(Command::Advertise(enabled)) => {
                                advertise = enabled;
                                announcements.reset_immediately();
                            }
                            Some(Command::Request(frame)) => {
                                let _ = requests.send(Recipients::Some(vec![leader_peer.clone()]), frame.encode().to_vec(), true);
                            }
                        },
                        received = blocks.recv() => {
                            let (_, bytes) = received.unwrap();
                            events.send(Event::Block(bytes.into())).unwrap();
                        }
                        received = backfill.recv() => {
                            let (_, bytes) = received.unwrap();
                            // Pre-announcement decoder's exact tag check. Malformed frames
                            // are ignored at the application layer, leaving transport intact.
                            let frame = match bytes.as_ref().first().copied() {
                                Some(0 | 1) => ResponseFrame::decode(bytes.as_ref()),
                                Some(tag) => Err(DecodeError::UnknownResponseTag(tag)),
                                None => Err(DecodeError::EmptyResponse),
                            };
                            match frame {
                                Ok(frame) => events.send(Event::Response(frame)).unwrap(),
                                Err(DecodeError::UnknownResponseTag(2)) => events.send(Event::IgnoredAnnouncement).unwrap(),
                                Err(err) => panic!("unexpected legacy response error: {err}"),
                            }
                        }
                    }
                }
                context.stop(0, Some(Duration::from_secs(5))).await.unwrap();
            });
        });
        let block = EncodedBlock {
            block: vec![0xc1, 0x80],
            witness: Some(vec![0x01]),
        };
        let broadcaster = repeat(
            leader.parts.as_ref().unwrap().commands.clone(),
            P2pCommand::BroadcastBlock(block.clone()),
        );

        // Old peer never advertises: announcements must not disconnect it or cause witnesses.
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut ignored = false;
            let mut received_block = false;
            while !(ignored && received_block) {
                match event_rx.recv().await.unwrap() {
                    Event::IgnoredAnnouncement => ignored = true,
                    Event::Block(bytes) => {
                        assert_eq!(bytes, block.block);
                        received_block = true;
                    }
                    other => panic!("unexpected event: {other:?}"),
                }
            }
        })
        .await
        .expect("legacy peer did not keep receiving bare blocks after announcement");
        // The other upgraded peer advertises and receives witnessed blocks concurrently.
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::BlockReceived { block: bytes, .. }) =
                    upgraded.events_mut().recv().await
                {
                    if bytes == block.encode() {
                        break;
                    }
                    assert_eq!(bytes, block.block);
                }
            }
        })
        .await
        .expect("upgraded peer did not receive witnesses");

        for (request_id, supports_witnesses) in [(41, false), (42, true), (43, false)] {
            if request_id == 42 {
                commands.send(Command::Advertise(true)).unwrap();
                tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        if let Event::Block(bytes) = event_rx.recv().await.unwrap() {
                            if bytes == block.encode() {
                                break;
                            }
                            assert_eq!(bytes, block.block);
                        }
                    }
                })
                .await
                .expect("explicit support did not enable witnesses");
            } else if request_id == 43 {
                commands.send(Command::Advertise(false)).unwrap();
                tokio::time::sleep(ANNOUNCEMENT_TTL + Duration::from_secs(1)).await;
                // Drain traffic queued during the lease. Subsequent sends must be legacy.
                while event_rx.try_recv().is_ok() {}
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if let Event::Block(bytes) = event_rx.recv().await.unwrap() {
                            assert_eq!(bytes, block.block);
                            break;
                        }
                    }
                })
                .await
                .expect("expired support did not restore bare blocks");
            }
            // Backfill requests have a one-message/second quota, so consecutive phases
            // retry until the request is admitted rather than assuming the first send wins.
            let request = tokio::time::timeout(Duration::from_secs(5), async {
                let mut retry = tokio::time::interval(Duration::from_millis(1100));
                loop {
                    tokio::select! {
                        _ = retry.tick() => commands.send(Command::Request(RequestFrame { request_id, start: 7 })).unwrap(),
                        request = leader.parts.as_mut().unwrap().backfill.requests.recv() => break request.unwrap(),
                    }
                }
            }).await.expect("legacy peer's backfill request did not arrive");
            assert_eq!(request.peer, legacy_peer);
            assert_eq!(request.request_id, request_id);
            leader
                .parts
                .as_ref()
                .unwrap()
                .backfill
                .commands
                .send(crate::BackfillCommand::SendBlock {
                    peer: legacy_peer.clone(),
                    request_id,
                    block: block.clone(),
                })
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Event::Response(ResponseFrame::Block {
                        request_id: actual_id,
                        block: bytes,
                    }) = event_rx.recv().await.unwrap()
                    {
                        assert_eq!(actual_id, request_id);
                        assert_eq!(
                            bytes,
                            if supports_witnesses {
                                block.encode()
                            } else {
                                block.block.clone()
                            }
                        );
                        break;
                    }
                }
            })
            .await
            .expect("backfill response did not arrive");
        }
        broadcaster.abort();
        shutdown.cancel();
        tokio::task::spawn_blocking(move || legacy_thread.join())
            .await
            .unwrap()
            .unwrap();
        shutdown_while_receiving(leader).await.unwrap();
        shutdown_while_receiving(upgraded).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leader_broadcasts_blocks_and_serves_backfill() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [
            ed25519_identity(1),
            ed25519_identity(2),
            ed25519_identity(3),
        ];
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            let secp256k1_identity = secp256k1_identity(index as u64 + 1);
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity.address(),
            ));
        }
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let mut handles = identities
            .into_iter()
            .zip(addresses)
            .enumerate()
            .map(|(index, (identity, listen))| {
                let secp256k1_identity = secp256k1_identity(index as u64 + 1);
                manifest
                    .validate_node(
                        &identity.ed25519_public_key(),
                        Some(secp256k1_identity.address()),
                        None,
                    )
                    .unwrap();
                spawn_p2p(
                    P2pConfig {
                        zone_id: 9,
                        manifest: manifest.clone(),
                        ed25519_identity: identity,
                        secp256k1_identity: Some(secp256k1_identity),
                        listen,
                        bypass_ip_check: false,
                        storage_directory: None,
                        leadership: crate::LeadershipSchedule::seeded(
                            manifest.bootstrap_leadership(),
                        ),
                    },
                    P2pNetworkId::new(1, Address::repeat_byte(0x11)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let block = vec![0xf8, 0x01, 0x80];
        let commands = handles[0].parts.as_ref().unwrap().commands.clone();
        let broadcaster = repeat(
            commands,
            P2pCommand::BroadcastBlock(crate::EncodedBlock {
                block: block.clone(),
                witness: None,
            }),
        );

        for handle in handles.iter_mut().skip(1) {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::BlockReceived {
                        block: received, ..
                    }) = handle.events_mut().recv().await
                    {
                        assert_eq!(received, block);
                        return;
                    }
                }
            })
            .await
            .expect("follower did not receive block");
        }
        broadcaster.abort();

        // Upgraded followers eventually advertise support and receive witness envelopes.
        let witness = vec![0x01];
        let encoded = crate::EncodedBlock {
            block: block.clone(),
            witness: Some(witness.clone()),
        };
        let witnessed_block = encoded.encode();
        let commands = handles[0].parts.as_ref().unwrap().commands.clone();
        let broadcaster = repeat(commands, P2pCommand::BroadcastBlock(encoded));
        for handle in handles.iter_mut().skip(1) {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::BlockReceived {
                        block: received, ..
                    }) = handle.events_mut().recv().await
                    {
                        if received == witnessed_block {
                            break;
                        }
                        // Plain blocks may be queued or sent before the advertisement arrives.
                        assert_eq!(received, block);
                    }
                }
            })
            .await
            .expect("follower did not receive witnessed blocks");
        }
        broadcaster.abort();

        // A responder at the follower's head sends an empty page. Its completion must reach the
        // follower without causing the coordinator to fan out another request.
        const LOCAL_BEST: u64 = 6;
        let level_start = LOCAL_BEST + 1;
        let follower_commands = handles[1].parts.as_ref().unwrap().backfill.commands.clone();
        let requester = tokio::spawn(async move {
            loop {
                follower_commands
                    .send(crate::BackfillCommand::Request { start: level_start })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let (requesting_peer, request_id) = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(request) = handles[0]
                    .parts
                    .as_mut()
                    .unwrap()
                    .backfill
                    .requests
                    .recv()
                    .await
                {
                    assert_eq!(request.start, level_start);
                    return (request.peer, request.request_id);
                }
            }
        })
        .await
        .expect("leader did not receive the level-peer backfill request");
        requester.abort();

        // Let any retry already queued by the test helper be discarded while this request is
        // still outstanding, before the completion frees the reservation.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let leader_commands = handles[0].parts.as_ref().unwrap().backfill.commands.clone();
        leader_commands
            .send(crate::BackfillCommand::Complete {
                peer: requesting_peer,
                request_id,
                tip: test_tip(LOCAL_BEST),
            })
            .await
            .unwrap();

        let level_response = tokio::time::timeout(
            Duration::from_secs(15),
            handles[1].parts.as_mut().unwrap().backfill.responses.recv(),
        )
        .await
        .expect("follower did not receive the level-peer completion")
        .expect("follower backfill response channel closed");
        assert!(matches!(
            level_response,
            crate::BackfillResponse::Completed { tip, .. } if tip == test_tip(LOCAL_BEST)
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(500),
                handles[2].parts.as_mut().unwrap().backfill.requests.recv(),
            )
            .await
            .is_err(),
            "level-peer completion triggered an unnecessary fallback backfill request"
        );

        // Exercise a non-empty backfill response through the real Commonware senders and
        // receivers. Blocks must arrive before the completion, and a completed request must
        // reject a replay with the same request ID.
        let follower_commands = handles[1].parts.as_ref().unwrap().backfill.commands.clone();
        let requester = tokio::spawn(async move {
            loop {
                follower_commands
                    .send(crate::BackfillCommand::Request { start: 7 })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let (requesting_peer, request_id) = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(request) = handles[0]
                    .parts
                    .as_mut()
                    .unwrap()
                    .backfill
                    .requests
                    .recv()
                    .await
                {
                    assert_eq!(request.start, 7);
                    return (request.peer, request.request_id);
                }
            }
        })
        .await
        .expect("leader did not receive the backfill request");
        requester.abort();

        // Drain any retry already queued by the helper while the request remains reserved.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let backfill_blocks = [vec![0xf8, 0x02, 0x80], vec![0xf8, 0x03, 0x80]];
        for block in &backfill_blocks {
            leader_commands
                .send(crate::BackfillCommand::SendBlock {
                    peer: requesting_peer.clone(),
                    request_id,
                    block: crate::EncodedBlock {
                        block: block.clone(),
                        witness: Some(witness.clone()),
                    },
                })
                .await
                .unwrap();
        }
        leader_commands
            .send(crate::BackfillCommand::Complete {
                peer: requesting_peer.clone(),
                request_id,
                tip: test_tip(9),
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(15), async {
            let mut received_blocks = Vec::new();
            loop {
                match handles[1]
                    .parts
                    .as_mut()
                    .unwrap()
                    .backfill
                    .responses
                    .recv()
                    .await
                {
                    Some(crate::BackfillResponse::Block { block, .. }) => {
                        received_blocks.push(block);
                    }
                    Some(crate::BackfillResponse::Completed { tip, .. }) => {
                        assert_eq!(tip, test_tip(9));
                        assert_eq!(
                            received_blocks,
                            backfill_blocks.map(|block| crate::EncodedBlock {
                                block,
                                witness: Some(witness.clone())
                            }
                            .encode())
                        );
                        return;
                    }
                    None => panic!("follower backfill response channel closed"),
                }
            }
        })
        .await
        .expect("follower did not receive the complete backfill response");

        leader_commands
            .send(crate::BackfillCommand::Complete {
                peer: requesting_peer,
                request_id,
                tip: test_tip(10),
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(500),
                handles[1].parts.as_mut().unwrap().backfill.responses.recv(),
            )
            .await
            .is_err(),
            "completed backfill request accepted a replay"
        );

        // Backfill without a stored witness still uses plain blocks.
        handles[2]
            .parts
            .as_ref()
            .unwrap()
            .backfill
            .commands
            .send(crate::BackfillCommand::Request { start: 10 })
            .await
            .unwrap();
        let request = tokio::time::timeout(
            Duration::from_secs(15),
            handles[0].parts.as_mut().unwrap().backfill.requests.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        leader_commands
            .send(crate::BackfillCommand::SendBlock {
                peer: request.peer.clone(),
                request_id: request.request_id,
                block: crate::EncodedBlock {
                    block: block.clone(),
                    witness: None,
                },
            })
            .await
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(15),
            handles[2].parts.as_mut().unwrap().backfill.responses.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(response, crate::BackfillResponse::Block { block: received, .. } if received == block)
        );

        for handle in handles {
            tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
                .await
                .expect("P2P runtime did not stop")
                .expect("P2P runtime failed");
        }
    }

    /// A finalized transition observed ahead of its activation boundary must not reroute
    /// traffic early: while the local applied anchor is still governed by the outgoing
    /// leader, its block broadcasts and settlement proposals keep flowing (including to the
    /// incoming leader), signatures return to the proposer, and forwarded transactions
    /// reach every replica before the transition activates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn advance_scheduled_transition_keeps_anchor_relevant_routing() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [
            ed25519_identity(21),
            ed25519_identity(22),
            ed25519_identity(23),
        ];
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            let secp256k1_identity = secp256k1_identity(index as u64 + 21);
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity.address(),
            ));
        }
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let outgoing_leader = identities[0].ed25519_public_key();
        let incoming_leader = identities[1].ed25519_public_key();
        let follower_peer = identities[2].ed25519_public_key();

        let mut handles = identities
            .into_iter()
            .zip(addresses)
            .enumerate()
            .map(|(index, (identity, listen))| {
                // Every node has observed the A→B transition at a future activation while
                // its applied anchor is still before the boundary: A (node 0) remains the
                // producer of the next anchor.
                let leadership = crate::LeadershipSchedule::seeded(manifest.bootstrap_leadership());
                leadership
                    .publish(crate::LeadershipState::new(1, incoming_leader.clone(), 100))
                    .unwrap();
                leadership.record_applied_anchor(10);
                spawn_p2p(
                    P2pConfig {
                        zone_id: 9,
                        manifest: manifest.clone(),
                        ed25519_identity: identity,
                        secp256k1_identity: Some(secp256k1_identity(index as u64 + 21)),
                        listen,
                        bypass_ip_check: false,
                        storage_directory: None,
                        leadership,
                    },
                    P2pNetworkId::new(1, Address::repeat_byte(0x11)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        // The outgoing leader's live blocks reach every other member — including the
        // incoming leader, which must keep importing until the boundary.
        let block = vec![0xf8, 0x01, 0x80];
        let outgoing_commands = handles[0].parts.as_ref().unwrap().commands.clone();
        let broadcast_block = block.clone();
        let broadcaster = tokio::spawn(async move {
            loop {
                outgoing_commands
                    .send(P2pCommand::BroadcastBlock(crate::EncodedBlock {
                        block: broadcast_block.clone(),
                        witness: None,
                    }))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        for handle in handles.iter_mut().skip(1) {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::BlockReceived {
                        leader_ed25519_public_key,
                        block: received,
                    }) = handle.events_mut().recv().await
                    {
                        assert_eq!(leader_ed25519_public_key, outgoing_leader);
                        assert_eq!(received, block);
                        return;
                    }
                }
            })
            .await
            .expect("peer did not receive the outgoing leader's live block");
        }
        broadcaster.abort();

        let outgoing_commands = handles[0].parts.as_ref().unwrap().commands.clone();
        let incoming_commands = handles[1].parts.as_ref().unwrap().commands.clone();
        let follower_commands = handles[2].parts.as_ref().unwrap().commands.clone();

        // The outgoing leader still settles pre-boundary batches: its proposal is accepted
        // and the signature returns to it, not to the incoming leader.
        let proposal = vec![0x10, 0x20];
        outgoing_commands
            .send(P2pCommand::BroadcastSettlementProposal(proposal.clone()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::SettlementProposalReceived {
                    leader,
                    proposal: received,
                }) = handles[2].events_mut().recv().await
                {
                    assert_eq!(leader, outgoing_leader);
                    assert_eq!(received, proposal);
                    return;
                }
            }
        })
        .await
        .expect("follower did not receive the outgoing leader's settlement proposal");

        let signature = vec![0x30, 0x40];
        follower_commands
            .send(P2pCommand::SendSettlementSignature {
                leader: outgoing_leader.clone(),
                signature: signature.clone(),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::SettlementSignatureReceived {
                    follower,
                    signature: received,
                }) = handles[0].events_mut().recv().await
                {
                    assert_eq!(follower, follower_peer);
                    assert_eq!(received, signature);
                    return;
                }
            }
        })
        .await
        .expect("outgoing leader did not receive the settlement signature");

        // Forwarded transactions reach every other replica. In particular, B retains C's
        // transaction before its leadership activates, while B's own forward reaches A and C.
        let transaction = vec![0x76, 0x01, 0x02, 0x03];
        follower_commands
            .send(P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(3),
                transaction: vec![0; MAX_TRANSACTION_MESSAGE_SIZE + 1],
            })
            .await
            .unwrap();
        let follower_forwarder = repeat(
            follower_commands.clone(),
            P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(1),
                transaction: transaction.clone(),
            },
        );
        let incoming_forwarder = repeat(
            incoming_commands.clone(),
            P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(2),
                transaction: transaction.clone(),
            },
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut received_from_incoming = false;
            let mut received_from_follower = false;
            loop {
                if let Some(P2pEvent::TransactionReceived {
                    follower_ed25519_public_key,
                    transaction: received,
                }) = handles[0].events_mut().recv().await
                {
                    assert_eq!(received, transaction);
                    if follower_ed25519_public_key == incoming_leader {
                        received_from_incoming = true;
                    } else if follower_ed25519_public_key == follower_peer {
                        received_from_follower = true;
                    }
                    if received_from_incoming && received_from_follower {
                        return;
                    }
                }
            }
        })
        .await
        .expect("outgoing leader did not receive both forwarded transactions");

        for (recipient, expected_sender) in
            [(1, follower_peer.clone()), (2, incoming_leader.clone())]
        {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::TransactionReceived {
                        follower_ed25519_public_key,
                        transaction: received,
                    }) = handles[recipient].events_mut().recv().await
                    {
                        assert_eq!(follower_ed25519_public_key, expected_sender);
                        assert_eq!(received, transaction);
                        return;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("node-{recipient} did not receive the peer's forwarded transaction")
            });
        }
        follower_forwarder.abort();
        incoming_forwarder.abort();

        for handle in handles {
            tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
                .await
                .expect("P2P runtime did not stop")
                .expect("P2P runtime failed");
        }
    }

    /// An RPC-only member replicates blocks and forwards its own transactions into the quorum,
    /// but receives neither settlement traffic nor transactions submitted to other nodes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rpc_only_follower_replicates_but_never_settles() {
        const LEADER: usize = 0;
        const QUORUM_FOLLOWER: usize = 1;
        const QUORUM_FOLLOWER_B: usize = 2;
        const RPC_FOLLOWER: usize = 3;

        let addresses = [
            available_address(),
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [31_u64, 32, 33, 34].map(ed25519_identity);
        let input = manifest_with_standby(&identities, &addresses, 31, RPC_FOLLOWER);
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let leader_peer = identities[LEADER].ed25519_public_key();
        let rpc_follower_peer = identities[RPC_FOLLOWER].ed25519_public_key();
        let mut handles = identities
            .into_iter()
            .zip(addresses)
            .enumerate()
            .map(|(index, (identity, listen))| {
                let leadership = manifest.leadership_schedule();
                leadership.publish(manifest.bootstrap_leadership()).unwrap();
                spawn_p2p(
                    P2pConfig {
                        zone_id: 9,
                        manifest: manifest.clone(),
                        ed25519_identity: identity,
                        // The standby is provisioned without quorum key material at all.
                        secp256k1_identity: (index != RPC_FOLLOWER)
                            .then(|| secp256k1_identity(index as u64 + 31)),
                        listen,
                        bypass_ip_check: false,
                        storage_directory: None,
                        leadership,
                    },
                    P2pNetworkId::new(1, Address::repeat_byte(0x11)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let leader_commands = handles[LEADER].parts.as_ref().unwrap().commands.clone();
        let quorum_follower_commands = handles[QUORUM_FOLLOWER]
            .parts
            .as_ref()
            .unwrap()
            .commands
            .clone();
        let rpc_commands = handles[RPC_FOLLOWER]
            .parts
            .as_ref()
            .unwrap()
            .commands
            .clone();

        // Replication reaches every replica, including the RPC standby: it serves reads from its
        // own imported chain. Waiting for all three also establishes the full mesh.
        let block = vec![0xf8, 0x01, 0x80];
        let broadcaster = repeat(
            leader_commands.clone(),
            P2pCommand::BroadcastBlock(crate::EncodedBlock {
                block: block.clone(),
                witness: None,
            }),
        );
        for index in [QUORUM_FOLLOWER, QUORUM_FOLLOWER_B, RPC_FOLLOWER] {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::BlockReceived {
                        leader_ed25519_public_key,
                        block: received,
                    }) = handles[index].events_mut().recv().await
                    {
                        assert_eq!(leader_ed25519_public_key, leader_peer);
                        assert_eq!(received, block);
                        return;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("node-{index} did not receive the leader's block"));
        }
        broadcaster.abort();

        // Settlement proposals go only to the quorum.
        let proposal = vec![0x10, 0x20];
        let proposer = repeat(
            leader_commands.clone(),
            P2pCommand::BroadcastSettlementProposal(proposal.clone()),
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::SettlementProposalReceived {
                    proposal: received, ..
                }) = handles[QUORUM_FOLLOWER].events_mut().recv().await
                {
                    assert_eq!(received, proposal);
                    return;
                }
            }
        })
        .await
        .expect("quorum follower did not receive the settlement proposal");
        // Proposals keep flowing through this window, so the standby has every chance to leak one.
        assert_no_event_matching(
            handles[RPC_FOLLOWER].events_mut(),
            Duration::from_secs(2),
            "RPC-only follower was asked to sign a settlement",
            |event| matches!(event, P2pEvent::SettlementProposalReceived { .. }),
        )
        .await;
        proposer.abort();

        // Operator RPC submissions reach every quorum member, not just the active leader.
        let transaction_hash = B256::with_last_byte(7);
        let transaction = vec![0x76, 0x07];
        let forwarder = repeat(
            rpc_commands.clone(),
            P2pCommand::ForwardTransaction {
                transaction_hash,
                transaction: transaction.clone(),
            },
        );
        for index in [LEADER, QUORUM_FOLLOWER, QUORUM_FOLLOWER_B] {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::TransactionReceived {
                        follower_ed25519_public_key,
                        transaction: received,
                    }) = handles[index].events_mut().recv().await
                    {
                        assert_eq!(follower_ed25519_public_key, rpc_follower_peer);
                        assert_eq!(received, transaction);
                        return;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("node-{index} did not receive the RPC-only follower's transaction")
            });
        }
        forwarder.abort();

        // Transactions submitted to a quorum follower stay within the quorum. The RPC-only
        // standby continues replicating blocks but does not retain unrelated pending bodies.
        let quorum_forwarder = repeat(
            quorum_follower_commands,
            P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(8),
                transaction: vec![0x76, 0x08],
            },
        );
        assert_no_event_matching(
            handles[RPC_FOLLOWER].events_mut(),
            Duration::from_secs(2),
            "RPC-only follower received another node's transaction",
            |event| matches!(event, P2pEvent::TransactionReceived { .. }),
        )
        .await;
        quorum_forwarder.abort();

        for handle in handles {
            tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
                .await
                .expect("P2P runtime did not stop")
                .expect("P2P runtime failed");
        }
    }

    /// Catch-up must reach a reachable quorum follower while the leader is offline.
    ///
    /// Commonware admission does not prove connectivity, so the offline leader can initially hold
    /// the sole reservation. Once its inactivity timeout elapses, the request must widen to the
    /// reachable quorum followers rather than remain stuck for the whole outage.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_reaches_a_quorum_follower_while_the_leader_is_offline() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [51_u64, 52, 53].map(ed25519_identity);
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity(index as u64 + 51).address(),
            ));
        }
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());

        // The leader (node 0) is never spawned, so it is a configured peer that never connects.
        let mut handles = [1_usize, 2]
            .map(|index| {
                spawn_p2p(
                    P2pConfig {
                        zone_id: 9,
                        manifest: manifest.clone(),
                        ed25519_identity: ed25519_identity(index as u64 + 51),
                        secp256k1_identity: Some(secp256k1_identity(index as u64 + 51)),
                        listen: addresses[index],
                        bypass_ip_check: false,
                        storage_directory: None,
                        leadership: crate::LeadershipSchedule::seeded(
                            manifest.bootstrap_leadership(),
                        ),
                    },
                    P2pNetworkId::new(1, Address::repeat_byte(0x11)),
                )
                .unwrap()
            })
            .into_iter()
            .collect::<Vec<_>>();

        let requester_commands = handles[0].parts.as_ref().unwrap().backfill.commands.clone();
        let requester = tokio::spawn(async move {
            loop {
                requester_commands
                    .send(crate::BackfillCommand::Request { start: 1 })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(request) = handles[1]
                    .parts
                    .as_mut()
                    .unwrap()
                    .backfill
                    .requests
                    .recv()
                    .await
                {
                    assert_eq!(request.peer, identities[1].ed25519_public_key());
                    assert_eq!(request.start, 1);
                    return;
                }
            }
        })
        .await
        .expect("catch-up never widened past the offline leader to a reachable quorum follower");
        requester.abort();

        for handle in handles {
            tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
                .await
                .expect("P2P runtime did not stop")
                .expect("P2P runtime failed");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn followers_exchange_transactions_while_leader_is_offline() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [
            ed25519_identity(11),
            ed25519_identity(12),
            ed25519_identity(13),
        ];
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            let secp256k1_identity = secp256k1_identity(index as u64 + 11);
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity.address(),
            ));
        }
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let sender_peer = identities[1].ed25519_public_key();
        let mut handles = identities
            .into_iter()
            .zip(addresses)
            .enumerate()
            .skip(1)
            .map(|(index, (identity, listen))| {
                let secp256k1_identity = secp256k1_identity(index as u64 + 11);
                let role = manifest
                    .validate_node(
                        &identity.ed25519_public_key(),
                        Some(secp256k1_identity.address()),
                        None,
                    )
                    .unwrap();
                assert_eq!(role, crate::Role::Follower);
                spawn_p2p(
                    P2pConfig {
                        zone_id: 9,
                        manifest: manifest.clone(),
                        ed25519_identity: identity,
                        secp256k1_identity: Some(secp256k1_identity),
                        listen,
                        bypass_ip_check: false,
                        storage_directory: None,
                        leadership: crate::LeadershipSchedule::seeded(
                            manifest.bootstrap_leadership(),
                        ),
                    },
                    P2pNetworkId::new(1, Address::repeat_byte(0x11)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        for handle in &mut handles {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !matches!(
                    handle.events_mut().recv().await,
                    Some(P2pEvent::Started { .. })
                ) {}
            })
            .await
            .expect("follower P2P runtime did not start");
        }
        let commands = handles[0].parts.as_ref().unwrap().commands.clone();
        let transaction = vec![0x76, 0x01];
        let forwarder = repeat(
            commands,
            P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(1),
                transaction: transaction.clone(),
            },
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::TransactionReceived {
                    follower_ed25519_public_key,
                    transaction: received,
                }) = handles[1].events_mut().recv().await
                {
                    assert_eq!(follower_ed25519_public_key, sender_peer);
                    assert_eq!(received, transaction);
                    return;
                }
            }
        })
        .await
        .expect("reachable follower did not receive transaction while leader was offline");
        forwarder.abort();

        for handle in handles {
            handle.shutdown().await.unwrap();
        }
    }

    /// A quorum follower that is shut down and respawned with the same identity and listen
    /// address must remesh and resume receiving the leader's live block broadcasts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follower_remeshes_after_shutdown_and_respawn() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [
            ed25519_identity(61),
            ed25519_identity(62),
            ed25519_identity(63),
        ];
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            let secp256k1_identity = secp256k1_identity(index as u64 + 61);
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity.address(),
            ));
        }
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let network_id = P2pNetworkId::new(1, Address::repeat_byte(0x11));
        let leader_peer = identities[0].ed25519_public_key();

        let spawn_node = |index: usize| {
            spawn_p2p(
                P2pConfig {
                    zone_id: 9,
                    manifest: manifest.clone(),
                    ed25519_identity: ed25519_identity(index as u64 + 61),
                    secp256k1_identity: Some(secp256k1_identity(index as u64 + 61)),
                    listen: addresses[index],
                    bypass_ip_check: false,
                    storage_directory: None,
                    leadership: crate::LeadershipSchedule::seeded(manifest.bootstrap_leadership()),
                },
                network_id,
            )
            .unwrap()
        };

        let leader = spawn_node(0);
        let mut follower_a = spawn_node(1);
        let mut follower_b = spawn_node(2);

        let initial_block = vec![0xf8, 0x01, 0x80];
        let leader_commands = leader.parts.as_ref().unwrap().commands.clone();
        let initial_broadcaster = repeat(
            leader_commands.clone(),
            P2pCommand::BroadcastBlock(crate::EncodedBlock {
                block: initial_block.clone(),
                witness: None,
            }),
        );
        for (label, handle) in [
            ("follower-a", &mut follower_a),
            ("follower-b", &mut follower_b),
        ] {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(P2pEvent::BlockReceived {
                        leader_ed25519_public_key,
                        block: received,
                    }) = handle.events_mut().recv().await
                    {
                        assert_eq!(leader_ed25519_public_key, leader_peer);
                        assert_eq!(received, initial_block);
                        return;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{label} did not receive the initial leader block"));
        }
        initial_broadcaster.abort();

        tokio::time::timeout(
            Duration::from_secs(10),
            shutdown_while_receiving(follower_b),
        )
        .await
        .expect("stopped follower did not shut down")
        .expect("stopped follower runtime failed");

        // While the peer is down, the remaining follower must keep receiving broadcasts.
        let offline_block = vec![0xf8, 0x02, 0x80];
        let offline_broadcaster = repeat(
            leader_commands.clone(),
            P2pCommand::BroadcastBlock(crate::EncodedBlock {
                block: offline_block.clone(),
                witness: None,
            }),
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::BlockReceived {
                    leader_ed25519_public_key,
                    block: received,
                }) = follower_a.events_mut().recv().await
                    && leader_ed25519_public_key == leader_peer
                    && received == offline_block
                {
                    return;
                }
            }
        })
        .await
        .expect("remaining follower did not receive blocks while the peer was shut down");
        offline_broadcaster.abort();

        // Listen-port reuse can race the OS briefly after shutdown; retry spawn if needed.
        let mut follower_b = None;
        for attempt in 0..10 {
            match spawn_p2p(
                P2pConfig {
                    zone_id: 9,
                    manifest: manifest.clone(),
                    ed25519_identity: ed25519_identity(63),
                    secp256k1_identity: Some(secp256k1_identity(63)),
                    listen: addresses[2],
                    bypass_ip_check: false,
                    storage_directory: None,
                    leadership: crate::LeadershipSchedule::seeded(manifest.bootstrap_leadership()),
                },
                network_id,
            ) {
                Ok(handle) => {
                    follower_b = Some(handle);
                    break;
                }
                Err(err) => {
                    assert!(
                        attempt < 9,
                        "respawned follower failed to bind after retries: {err}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        let mut follower_b = follower_b.expect("respawned follower handle");

        let remesh_block = vec![0xf8, 0x03, 0x80];
        let remesh_broadcaster = repeat(
            leader_commands,
            P2pCommand::BroadcastBlock(crate::EncodedBlock {
                block: remesh_block.clone(),
                witness: None,
            }),
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(P2pEvent::BlockReceived {
                    leader_ed25519_public_key,
                    block: received,
                }) = follower_b.events_mut().recv().await
                    && leader_ed25519_public_key == leader_peer
                    && received == remesh_block
                {
                    return;
                }
            }
        })
        .await
        .expect("respawned follower did not remesh and receive subsequent leader blocks");
        remesh_broadcaster.abort();

        for handle in [leader, follower_a, follower_b] {
            tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
                .await
                .expect("P2P runtime did not stop")
                .expect("P2P runtime failed");
        }
    }

    /// Unlike the permanent offline-leader tests, this covers recovery: followers mesh while
    /// the leader is down, then remesh with the leader once it comes online.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mesh_recovers_when_leader_comes_online_after_being_offline() {
        let addresses = [
            available_address(),
            available_address(),
            available_address(),
        ];
        let identities = [
            ed25519_identity(71),
            ed25519_identity(72),
            ed25519_identity(73),
        ];
        let mut input = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            const_hex::encode_prefixed(identities[0].ed25519_public_key().as_ref())
        );
        for (index, (identity, address)) in identities.iter().zip(addresses).enumerate() {
            let secp256k1_identity = secp256k1_identity(index as u64 + 71);
            input.push_str(&format!(
                "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                const_hex::encode_prefixed(identity.ed25519_public_key().as_ref()),
                secp256k1_identity.address(),
            ));
        }
        let manifest = Arc::new(ZoneManifest::parse(&input).unwrap());
        let network_id = P2pNetworkId::new(1, Address::repeat_byte(0x11));
        let leader_peer = identities[0].ed25519_public_key();
        let sender_peer = identities[1].ed25519_public_key();

        // Spawn only the followers first — same shape as the permanent offline-leader tests.
        let mut followers = [1_usize, 2]
            .map(|index| {
                spawn_p2p(
                    P2pConfig {
                        zone_id: 9,
                        manifest: manifest.clone(),
                        ed25519_identity: ed25519_identity(index as u64 + 71),
                        secp256k1_identity: Some(secp256k1_identity(index as u64 + 71)),
                        listen: addresses[index],
                        bypass_ip_check: false,
                        storage_directory: None,
                        leadership: crate::LeadershipSchedule::seeded(
                            manifest.bootstrap_leadership(),
                        ),
                    },
                    network_id,
                )
                .unwrap()
            })
            .into_iter()
            .collect::<Vec<_>>();

        for handle in &mut followers {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !matches!(
                    handle.events_mut().recv().await,
                    Some(P2pEvent::Started { .. })
                ) {}
            })
            .await
            .expect("follower P2P runtime did not start");
        }

        let offline_transaction = vec![0x76, 0x01];
        let offline_forwarder = repeat(
            followers[0].parts.as_ref().unwrap().commands.clone(),
            P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(1),
                transaction: offline_transaction.clone(),
            },
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(P2pEvent::TransactionReceived {
                    follower_ed25519_public_key,
                    transaction: received,
                }) = followers[1].events_mut().recv().await
                {
                    assert_eq!(follower_ed25519_public_key, sender_peer);
                    assert_eq!(received, offline_transaction);
                    return;
                }
            }
        })
        .await
        .expect("followers did not exchange transactions while the leader was offline");
        offline_forwarder.abort();

        let mut leader = spawn_p2p(
            P2pConfig {
                zone_id: 9,
                manifest: manifest.clone(),
                ed25519_identity: ed25519_identity(71),
                secp256k1_identity: Some(secp256k1_identity(71)),
                listen: addresses[0],
                bypass_ip_check: false,
                storage_directory: None,
                leadership: crate::LeadershipSchedule::seeded(manifest.bootstrap_leadership()),
            },
            network_id,
        )
        .unwrap();

        let block = vec![0xf8, 0x01, 0x80];
        let leader_commands = leader.parts.as_ref().unwrap().commands.clone();
        let broadcaster = repeat(
            leader_commands.clone(),
            P2pCommand::BroadcastBlock(crate::EncodedBlock {
                block: block.clone(),
                witness: None,
            }),
        );
        for (index, handle) in followers.iter_mut().enumerate() {
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if let Some(P2pEvent::BlockReceived {
                        leader_ed25519_public_key,
                        block: received,
                    }) = handle.events_mut().recv().await
                        && leader_ed25519_public_key == leader_peer
                        && received == block
                    {
                        return;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("follower-{index} did not receive blocks after the leader came online")
            });
        }
        broadcaster.abort();

        let online_transaction = vec![0x76, 0x02];
        let online_forwarder = repeat(
            followers[0].parts.as_ref().unwrap().commands.clone(),
            P2pCommand::ForwardTransaction {
                transaction_hash: B256::with_last_byte(2),
                transaction: online_transaction.clone(),
            },
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(P2pEvent::TransactionReceived {
                    follower_ed25519_public_key,
                    transaction: received,
                }) = leader.events_mut().recv().await
                    && follower_ed25519_public_key == sender_peer
                    && received == online_transaction
                {
                    return;
                }
            }
        })
        .await
        .expect("leader did not receive a forwarded transaction after coming online");
        online_forwarder.abort();

        for handle in std::iter::once(leader).chain(followers) {
            tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
                .await
                .expect("P2P runtime did not stop")
                .expect("P2P runtime failed");
        }
    }
}
