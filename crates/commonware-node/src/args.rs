//! Command line arguments for configuring the consensus layer of a tempo node.
use std::{
    net::SocketAddr, num::NonZeroU32, path::PathBuf, str::FromStr, sync::OnceLock, time::Duration,
};

use commonware_cryptography::ed25519::PublicKey;
use eyre::Context;
use tempo_commonware_node_config::SigningKey;

const DEFAULT_MAX_MESSAGE_SIZE_BYTES: u32 =
    reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE as u32;

/// Command line arguments for configuring the consensus layer of a tempo node.
#[derive(Debug, Clone, clap::Args)]
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
    pub max_message_size_bytes: u32,

    /// The number of worker threads assigned to consensus.
    #[arg(long = "consensus.worker-threads", default_value_t = 3)]
    pub worker_threads: usize,

    /// The maximum number of messages that can be queued on the various consensus
    /// channels before blocking.
    #[arg(long = "consensus.message-backlog", default_value_t = 16_384)]
    pub message_backlog: usize,

    /// The overall number of items that can be received on the various consensus
    /// channels before blocking.
    #[arg(long = "consensus.mailbox-size", default_value_t = 16_384)]
    pub mailbox_size: usize,

    /// The maximum number of blocks that will be buffered per peer. Used to
    /// send and receive blocks over the network of the consensus layer.
    #[arg(long = "consensus.deque-size", default_value_t = 10)]
    pub deque_size: usize,

    /// The fee recipient that will be specified by this node. Will use the
    /// coinbase address in genesis if not set.
    #[arg(
        long = "consensus.fee-recipient",
        required_unless_present_any = ["follow", "dev"],
    )]
    pub fee_recipient: Option<alloy_primitives::Address>,

    /// The amount of time to wait for a peer to respond to a consensus request.
    #[arg(long = "consensus.wait-for-peer-response", default_value = "2s")]
    pub wait_for_peer_response: PositiveDuration,

    /// The amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    #[arg(long = "consensus.wait-for-notarizations", default_value = "2s")]
    pub wait_for_notarizations: PositiveDuration,

    /// Amount of time to wait to receive a proposal from the leader of the
    /// current view.
    #[arg(long = "consensus.wait-for-proposal", default_value = "2s")]
    pub wait_for_proposal: PositiveDuration,

    /// The amount of time to wait before retrying a nullify broadcast if stuck
    /// in a view.
    #[arg(long = "consensus.wait-to-rebroadcast-nullify", default_value = "10s")]
    pub wait_to_rebroadcast_nullify: PositiveDuration,

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
    #[arg(long = "consensus.time-to-build-proposal", default_value = "200ms")]
    pub time_to_build_proposal: PositiveDuration,

    /// The amount of time this node will use to construct a subblock before
    /// sending it to the next proposer. This value should be well below
    /// `consensus.time-to-build-proposal` to ensure the subblock is received
    /// before the build is complete.
    #[arg(long = "consensus.time-to-build-subblock", default_value = "100ms")]
    pub time_to_build_subblock: PositiveDuration,

    /// Use defaults optimized for local network environments.
    /// Only enable in non-production network nodes.
    #[arg(long = "consensus.use-local-defaults", default_value_t = false)]
    pub use_local_defaults: bool,

    /// Reduces security by disabling IP-based connection filtering.
    /// Connections are still authenticated via public key cryptography, but
    /// anyone can attempt handshakes, increasing exposure to DoS attacks.
    /// Only enable in trusted network environments.
    #[arg(long = "consensus.bypass-ip-check", default_value_t = false)]
    pub bypass_ip_check: bool,

    /// Whether to allow connections with private IP addresses.
    #[arg(
        long = "consensus.allow-private-ips",
        default_value_t = false,
        default_value_if("use_local_defaults", "true", "true")
    )]
    pub allow_private_ips: bool,

    /// Whether to allow DNS-based ingress addresses.
    #[arg(long = "consensus.allow-dns", default_value_t = true)]
    pub allow_dns: bool,

    /// Time into the future that a timestamp can be and still be considered valid.
    #[arg(long = "consensus.synchrony-bound", default_value = "5s")]
    pub synchrony_bound: PositiveDuration,

    /// How long to wait before attempting to dial peers. Run across all peers
    /// including the newly discovered ones.
    #[arg(
        long = "consensus.wait-before-peers-redial",
        default_value = "1s",
        default_value_if("use_local_defaults", "true", "500ms")
    )]
    pub wait_before_peers_redial: PositiveDuration,

    /// How long to wait before sending a ping message to peers for liveness detection.
    #[arg(
        long = "consensus.wait-before-peers-reping",
        default_value = "50s",
        default_value_if("use_local_defaults", "true", "5s")
    )]
    pub wait_before_peers_reping: PositiveDuration,

    /// How often to query for new dialable peers.
    #[arg(
        long = "consensus.wait-before-peers-discovery",
        default_value = "60s",
        default_value_if("use_local_defaults", "true", "30s")
    )]
    pub wait_before_peers_discovery: PositiveDuration,

    /// Minimum time between connection attempts to the same peer. A rate-limit
    /// on connection attempts.
    #[arg(
        long = "consensus.connection-per-peer-min-period",
        default_value = "60s",
        default_value_if("use_local_defaults", "true", "1s")
    )]
    pub connection_per_peer_min_period: PositiveDuration,

    /// Minimum time between handshake attempts from a single IP address. A rate-limit
    /// on attempts.
    #[arg(
        long = "consensus.handshake-per-ip-min-period",
        default_value = "5s",
        default_value_if("use_local_defaults", "true", "62ms")
    )]
    pub handshake_per_ip_min_period: PositiveDuration,

    /// Minimum time between handshake attempts from a single subnet. A rate-limit
    /// on attempts.
    #[arg(
        long = "consensus.handshake-per-subnet-min-period",
        default_value = "15ms",
        default_value_if("use_local_defaults", "true", "7ms")
    )]
    pub handshake_per_subnet_min_period: PositiveDuration,

    /// Duration after which a handshake message is considered stale.
    #[arg(long = "consensus.handshake-stale-after", default_value = "10s")]
    pub handshake_stale_after: PositiveDuration,

    /// Timeout for the handshake process.
    #[arg(long = "consensus.handshake-timeout", default_value = "5s")]
    pub handshake_timeout: PositiveDuration,

    /// Maximum number of concurrent handshake attempts allowed.
    #[arg(
        long = "consensus.max-concurrent-handshakes",
        default_value = "512",
        default_value_if("use_local_defaults", "true", "1024")
    )]
    pub max_concurrent_handshakes: NonZeroU32,

    /// Duration after which a blocked peer is allowed to reconnect.
    #[arg(
        long = "consensus.time-to-unblock-byzantine-peer",
        default_value = "4h",
        default_value_if("use_local_defaults", "true", "1h")
    )]
    pub time_to_unblock_byzantine_peer: PositiveDuration,

    /// Rate limit when backfilling blocks (requests per second).
    #[arg(long = "consensus.backfill-frequency", default_value = "8")]
    pub backfill_frequency: std::num::NonZeroU32,

    /// The interval at which to broadcast subblocks to the next proposer.
    /// Each built subblock is immediately broadcasted to the next proposer (if it's known).
    /// We broadcast subblock every `subblock-broadcast-interval` to ensure the next
    /// proposer is aware of the subblock even if they were slightly behind the chain
    /// once we sent it in the first time.
    #[arg(long = "consensus.subblock-broadcast-interval", default_value = "50ms")]
    pub subblock_broadcast_interval: PositiveDuration,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer. This is sent periodically even when there are no new
    /// blocks to ensure the execution layer stays in sync with the consensus
    /// layer's view of the chain head.
    #[arg(long = "consensus.fcu-heartbeat-interval", default_value = "5m")]
    pub fcu_heartbeat_interval: PositiveDuration,

    /// Cache for the signing key loaded from CLI-provided file.
    #[clap(skip)]
    loaded_signing_key: OnceLock<Option<SigningKey>>,

    /// Where to store consensus data. If not set, this will be derived from
    /// `--datadir`.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    pub storage_dir: Option<PathBuf>,
}

/// A jiff::SignedDuration that checks that the duration is positive and not zero.
#[derive(Debug, Clone, Copy)]
pub struct PositiveDuration(jiff::SignedDuration);
impl PositiveDuration {
    pub fn into_duration(self) -> Duration {
        self.0
            .try_into()
            .expect("must be positive. enforced when cli parsing.")
    }
}

impl FromStr for PositiveDuration {
    type Err = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let duration = s.parse::<jiff::SignedDuration>()?;
        let _: Duration = duration.try_into().wrap_err("duration must be positive")?;

        Ok(Self(duration))
    }
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
