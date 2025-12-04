//! Command line arguments for configuring the consensus layer of a tempo node.
use std::{net::SocketAddr, path::PathBuf, sync::OnceLock};

use commonware_cryptography::ed25519::PublicKey;
use eyre::Context;
use tempo_commonware_node_config::SigningKey;

const DEFAULT_MAX_MESSAGE_SIZE_BYTES: usize = reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;

/// Command line arguments for configuring the consensus layer of a tempo node.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct Args {
    /// The file containing the ed25519 signing key for p2p communication.
    #[arg(
        long = "consensus.signing-key",
        required_unless_present_any = ["follow", "dev"],
    )]
    signing_key: Option<PathBuf>,

    /// The file containing a share of the bls12-381 threshold signing key.
    #[arg(long = "consensus.signing-share")]
    pub signing_share: Option<PathBuf>,

    /// The socket address that will be bound to listen for consensus communication from
    /// other nodes.
    #[arg(long = "consensus.listen-address", default_value = "127.0.0.1:8000")]
    pub listen_address: SocketAddr,

    /// The socket address that will be bound to export consensus specific
    /// metrics.
    #[arg(long = "consensus.metrics-address", default_value = "127.0.0.1:8001")]
    pub metrics_address: SocketAddr,

    #[arg(long = "consensus.max-message-size-bytes", default_value_t = DEFAULT_MAX_MESSAGE_SIZE_BYTES)]
    pub max_message_size_bytes: usize,

    // pub storage_directory: camino::Utf8PathBuf,
    /// The number of worker threads assigned to consensus.
    #[arg(long = "consensus.worker-threads", default_value_t = 3)]
    pub worker_threads: usize,

    /// The maximum number of messages that can be cute on the various consensus
    /// p2p channels before blocking.
    #[arg(long = "consensus.message-backlog", default_value_t = 16_384)]
    pub message_backlog: usize,

    /// The overall number of items that can be received on the various consensus
    /// p2p channels before blocking.
    #[arg(long = "consensus.mailbox-size", default_value_t = 16_384)]
    pub mailbox_size: usize,

    /// The maximum number of blocks that will be buffered per peer. Used to
    /// send and receive blocks over the p2p network of the consensus layer.
    #[arg(long = "consensus.deque-size", default_value_t = 10)]
    pub deque_size: usize,

    /// The fee recipien that will be specified by this node. Will use the
    /// coinbase address in genesis if not set.
    #[arg(
        long = "consensus.fee-recipient",
        required_unless_present_any = ["follow", "dev"],
    )]
    pub fee_recipient: Option<alloy_primitives::Address>,

    // The amount of time to wait for a peer to respond to a consensus request.
    #[arg(long = "consensus.wait-for-peer-response", default_value = "2s")]
    pub wait_for_peer_response: jiff::SignedDuration,

    /// The amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    #[arg(long = "consensus.wait-for-notarizations", default_value = "2s")]
    pub wait_for_notarizations: jiff::SignedDuration,

    /// Amount of time to wait to receive a proposal from the leader of the
    /// current view.
    #[arg(long = "consensus.wait-for-proposal", default_value = "2s")]
    pub wait_for_proposal: jiff::SignedDuration,

    /// The amount of time to wait before retrying a nullify broadcast if stuck
    /// in a view.
    #[arg(long = "consensus.wait-to-rebroadcast-nullify", default_value = "10s")]
    pub wait_to_rebroadcast_nullify: jiff::SignedDuration,

    /// The number of views (like voting rounds) to track. Also called an
    /// activity timeout.
    #[arg(long = "consensus.views-to-track", default_value_t = 256)]
    pub views_to_track: u64,

    /// The number of views (voting rounds) a validator is allowed to be
    /// inactive until it is immediately skipped should leader selection pick it
    /// as a proposer. Also called a skip timeout.
    #[arg(
        long = "consensus.inactive-views-until-leader-skip",
        default_value_t = 32
    )]
    pub inactive_views_until_leader_skip: u64,

    /// The amount of time this node will use to construct a block as a proposal.
    /// This value should be well below `consensus.wait-for-proposal` to account
    /// for the leader to enter the view, build and broadcast the proposal, and
    /// have the other peers receive the proposal.
    #[arg(long = "consensus.time-to-build-proposal", default_value = "500ms")]
    pub time_to_build_proposal: jiff::SignedDuration,

    /// The amount of time this node will use to construct a subblock before
    /// sending it to the next proposer. This value should be well below
    /// `consensus.time-to-build-proposal` to ensure the subblock is received
    /// before the build is complete.
    #[arg(long = "consensus.time-to-build-subblock", default_value = "100ms")]
    pub time_to_build_subblock: jiff::SignedDuration,

    /// Reduces security by disabling IP-based connection filtering.
    /// Connections are still authenticated via public key cryptography, but
    /// anyone can attempt handshakes, increasing exposure to DoS attacks.
    /// Only enable in trusted network environments.
    #[arg(
        long = "consensus.allow-unregistered-handshakes",
        default_value_t = false
    )]
    pub allow_unregistered_handshakes: bool,

    /// The interval at which to broadcast subblocks to the next proposer.
    /// Each built subblock is immediately broadcasted to the next proposer (if it's known).
    /// We broadcast subblock every `subblock-broadcast-interval` to ensure the next
    /// proposer is aware of the subblock even if they were slightly behind the chain
    /// once we sent it in the first time.
    #[arg(long = "consensus.subblock-broadcast-interval", default_value = "50ms")]
    pub subblock_broadcast_interval: jiff::SignedDuration,

    /// Cache for the signing key loaded from CLI-provided file.
    #[clap(skip)]
    loaded_signing_key: OnceLock<Option<SigningKey>>,
}

impl Args {
    /// Returns the signing key loaded from specified file.
    pub(crate) fn signing_key(&self) -> eyre::Result<Option<SigningKey>> {
        if let Some(signing_key) = self.loaded_signing_key.get() {
            return Ok(signing_key.clone());
        }

        let signing_key = self
            .signing_key
            .as_ref()
            .map(|path| {
                SigningKey::read_from_file(path).wrap_err_with(|| {
                    format!(
                        "failed reading private ed25519 signing key share from file `{}`",
                        path.display()
                    )
                })
            })
            .transpose()?;

        let _ = self.loaded_signing_key.set(signing_key.clone());

        Ok(signing_key)
    }

    /// Returns the public key derived from the configured signing key, if any.
    pub fn public_key(&self) -> eyre::Result<Option<PublicKey>> {
        Ok(self
            .signing_key()?
            .map(|signing_key| signing_key.public_key()))
    }
}
