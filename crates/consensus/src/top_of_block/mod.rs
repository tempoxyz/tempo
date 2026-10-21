//! Privileged top-of-block access for designated operators.
//!
//! Operators are authenticated commonware peers listed in the Ownable
//! `TopOfBlockRegistry` contract (`--consensus.top-of-block-registry`). The
//! peer manager reads the registry from the latest finalized state, so every
//! validator sees the same operators at the same height. Validators track
//! operators as secondary peers: operators dial validators, validators never
//! dial operators.
//!
//! The flow for one round:
//!
//! 1. Operators receive the validators' consensus certificates. The VRF
//!    leader of a view is elected from any certificate of the previous view,
//!    so an operator verifies the certificate and computes the next leader
//!    itself ([`leader::EpochLeaders`]), as early as the validators do.
//! 2. Operators send [`wire::Submit`] with signed transactions directly to
//!    that leader. Each transaction replaces the previous transaction of its
//!    maker (signer) in the round. The leader answers with [`wire::Ack`],
//!    since commonware may drop messages. The lane keeps submissions for
//!    rounds that have not started yet.
//! 3. When this node starts proposing the round, it opens its
//!    [`TopOfBlockLane`]. When the lane's window elapses, the payload builder takes the lane and
//!    executes its transactions after the start-of-block system work and
//!    before any pool transaction. Invalid or late transactions are skipped,
//!    and an empty lane builds a normal block.
//! 4. Operators read the lane transactions back from the proposed block,
//!    which validators broadcast to every connected peer.
//!
//! The ordering is the proposer's policy: validators verify these blocks like
//! any other block.

mod actor;
pub mod leader;
mod registry;
pub mod wire;

use std::net::SocketAddr;

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::{
    Address, AddressableManager as _, AddressableTrackedPeers, Receiver as _, authenticated::lookup,
};
use commonware_runtime::Spawner as _;
use commonware_utils::ordered;
use eyre::OptionExt as _;
use governor::Quota;
use tempo_payload_types::TopOfBlockLane;

pub(crate) use actor::{Actor, Mailbox};
pub use registry::{OperatorPolicy, Registry, RegistryHandle};

/// The p2p channel for top-of-block messages.
pub const CHANNEL: commonware_p2p::Channel = 6;

/// Per-peer quota on the top-of-block channel.
///
/// Sized for an operator streaming about a thousand single-transaction
/// submissions per second, and for the leader acknowledging each of them.
pub const LIMIT: Quota = Quota::per_second(std::num::NonZeroU32::new(2048).expect("not zero"));

/// Validator-side configuration.
pub struct Config {
    /// Address of the `TopOfBlockRegistry` contract.
    pub registry_address: alloy_primitives::Address,
    /// The registry as last read by the peer manager.
    pub registry: RegistryHandle,
    /// The lane of the execution node's payload builder.
    pub lane: TopOfBlockLane,
}

/// Initializes the validator-side actor and its mailbox.
pub(crate) fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox) {
    actor::init(context, config)
}

/// Settings for an operator's connection to the validators.
pub struct OperatorNetwork {
    /// The operator's identity, registered with the validators.
    pub signer: PrivateKey,
    /// Address to listen on; validators never dial operators, but the network
    /// needs a listener.
    pub listen: SocketAddr,
    /// Validators to connect to.
    pub validators: Vec<(PublicKey, SocketAddr)>,
    /// Must be at least the validators' `--consensus.max-message-size-bytes`:
    /// validators send consensus broadcasts to all connected peers, including
    /// operators, and a message larger than this closes the connection.
    pub max_message_size: u32,
    /// Must equal the validators' `--consensus.wait-before-peers-reping`.
    ///
    /// Each side accepts at most one ping per half of its own ping period and
    /// stops reading the connection until the next one is allowed. Pinging
    /// more often than the validators stalls every message behind the pings;
    /// pinging less often makes the operator stall the validators the same way.
    pub ping_frequency: std::time::Duration,
}

/// The operator's handles to the network.
pub struct OperatorChannels {
    /// The top-of-block channel.
    pub top_of_block: (
        lookup::Sender<PublicKey, commonware_runtime::tokio::Context>,
        lookup::Receiver<PublicKey>,
    ),
    /// Consensus certificates broadcast by the validators; decode them with
    /// [`leader::decode_certificate`].
    pub certificates: lookup::Receiver<PublicKey>,
    /// Blocks broadcast by their proposers; decode them with
    /// [`decode_proposal`].
    pub proposals: lookup::Receiver<PublicKey>,
}

/// Starts an operator's network and returns its channels.
///
/// Validators send their consensus broadcasts to operators as well, so the
/// other consensus channels are registered and drained. Their quotas must
/// exceed what validators send: an exceeded inbound quota stalls the whole
/// connection, including the top-of-block channel.
pub fn start_operator_network(
    context: &commonware_runtime::tokio::Context,
    config: OperatorNetwork,
) -> eyre::Result<OperatorChannels> {
    use commonware_runtime::Supervisor as _;

    let validators = ordered::Map::from_iter_dedup(
        config
            .validators
            .into_iter()
            .map(|(key, address)| (key, Address::Symmetric(address))),
    );
    eyre::ensure!(!validators.is_empty(), "no validators to connect to");
    let namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
    // Inbound mailboxes are preallocated for `max_peers_per_set *
    // tracked_peer_sets * burst` messages, so keep these bounds tight.
    let drained = Quota::per_second(std::num::NonZeroU32::new(1024).expect("not zero"));
    let (mut network, mut oracle) = lookup::Network::new(
        context.child("top_of_block_network"),
        lookup::Config {
            bypass_ip_check: true,
            allow_private_ips: true,
            tracked_peer_sets: std::num::NonZeroUsize::new(1).expect("not zero"),
            ping_frequency: config.ping_frequency,
            ..lookup::Config::local(
                config.signer,
                &namespace,
                config.listen,
                // The tracked set holds every validator, and the network counts
                // this node too.
                std::num::NonZeroUsize::new(validators.len() + 1).expect("not zero"),
                config.max_message_size,
            )
        },
    );

    let (_sender, certificates) =
        network.register(crate::config::CERTIFICATES_CHANNEL_IDENT, drained);
    let (_sender, proposals) = network.register(crate::config::BROADCASTER_CHANNEL_IDENT, drained);
    for channel in [
        crate::config::VOTES_CHANNEL_IDENT,
        crate::config::RESOLVER_CHANNEL_IDENT,
        crate::config::MARSHAL_CHANNEL_IDENT,
        crate::config::DKG_CHANNEL_IDENT,
    ] {
        let (_sender, mut receiver) = network.register(channel, drained);
        context
            .child("drain")
            .spawn(async move |_| while receiver.recv().await.is_ok() {});
    }
    let top_of_block = network.register(CHANNEL, LIMIT);

    oracle.track(
        0,
        AddressableTrackedPeers {
            primary: validators,
            secondary: ordered::Map::default(),
        },
    );
    network.start();
    Ok(OperatorChannels {
        top_of_block,
        certificates,
        proposals,
    })
}

/// Decodes a block received on the consensus broadcast channel.
///
/// Its header's consensus context names the round and the proposer. The block
/// is the proposer's claim until the round is notarized.
pub fn decode_proposal(
    mut message: commonware_runtime::IoBuf,
) -> Option<reth_primitives_traits::SealedBlock<tempo_primitives::Block>> {
    use commonware_codec::ReadExt as _;
    crate::consensus::block::Block::read(&mut message)
        .ok()
        .map(|block| block.block().clone())
}

/// Parses `<hex ed25519 public key>@<ip:port>`.
pub fn parse_peer(value: &str) -> eyre::Result<(PublicKey, SocketAddr)> {
    let (key, address) = value
        .split_once('@')
        .ok_or_eyre("expected `<public key>@<ip:port>`")?;
    Ok((registry::parse_public_key(key)?, address.parse()?))
}
