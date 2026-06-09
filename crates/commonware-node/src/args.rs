//! Command line arguments for configuring the consensus layer of a tempo node.
use std::{
    net::SocketAddr,
    num::NonZeroU32,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use crate::network_identity::NetworkIdentity;
use commonware_cryptography::ed25519::PublicKey;
use eyre::Context;
use tempo_commonware_node_config::{SigningKey, SigningKeyPassphrase};

const DEFAULT_MAX_MESSAGE_SIZE_BYTES: u32 =
    reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE as u32;
const PASSPHRASE_SECRET_WAIT_WARNING_INTERVAL: Duration = Duration::from_secs(5);

/// Command line arguments for configuring the consensus layer of a tempo node.
#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// The file containing the ed25519 signing key for p2p communication.
    ///
    /// By default the file is expected to contain a hex-encoded ed25519
    /// private key in plaintext (unencrypted at rest). When
    /// `--consensus.secret` is also provided, the file is instead
    /// treated as a passphrase-encrypted `age` payload whose plaintext is
    /// the raw encoded ed25519 private key bytes; it is decrypted at
    /// startup using the passphrase read from the secret path.
    #[arg(
        long = "consensus.signing-key",
        required_unless_present_any = ["follow", "dev"],
    )]
    signing_key: Option<PathBuf>,

    /// Path from which the passphrase used to decrypt
    /// `--consensus.signing-key` is read.
    ///
    /// A FIFO created by `mkfifo`, or shell process substitution like `<(...)`,
    /// is preferred to avoid leaving the passphrase on disk or in process state
    /// (like via an env var). Regular files are accepted with a warning.
    #[arg(
        long = "consensus.secret",
        value_name = "PATH",
        requires = "signing_key"
    )]
    secret: Option<PathBuf>,

    /// The file containing a share of the bls12-381 threshold signing key.
    #[arg(long = "consensus.signing-share")]
    pub signing_share: Option<PathBuf>,

    /// Consensus network bls network identity key. Otherwise derived from genesis
    #[arg(
        long = "consensus.network-identity",
        requires = "network_identity_from_epoch"
    )]
    pub(crate) network_identity: Option<NetworkIdentity>,

    /// First epoch where --consensus.network-identity is set after rotation
    #[arg(
        long = "consensus.network-identity-from-epoch",
        requires = "network_identity"
    )]
    pub(crate) network_identity_from_epoch: Option<u64>,

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

    /// The amount of time to wait for a peer to respond to a consensus request.
    #[arg(long = "consensus.wait-for-peer-response", default_value = "2s")]
    pub wait_for_peer_response: PositiveDuration,

    /// The amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    #[arg(long = "consensus.wait-for-notarizations", default_value = "2s")]
    pub wait_for_notarizations: PositiveDuration,

    /// Target wall-clock time between blocks in healthy network conditions.
    ///
    /// Local proposal work is paced against this value minus
    /// `--consensus.network-budget`.
    #[arg(long = "consensus.target-block-time", default_value = "550ms")]
    pub target_block_time: PositiveDuration,

    /// Maximum amount of time to wait for the leader's proposal before timing
    /// out the current view.
    #[arg(long = "consensus.wait-for-proposal", default_value = "1200ms")]
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

    /// Time reserved for proposal propagation before the target block boundary.
    ///
    /// The remaining `target-block-time - network-budget` is the local proposal
    /// return budget used by consensus and the payload builder.
    #[arg(long = "consensus.network-budget", default_value = "50ms")]
    pub network_budget: PositiveDuration,

    /// Deprecated compatibility flag. Ignored by the elastic proposal budget.
    #[arg(
        long = "consensus.time-to-prepare-proposal-transactions",
        value_name = "DURATION",
        help = "Deprecated: no longer has any effect and will be removed in the next release."
    )]
    pub time_to_prepare_proposal_transactions: Option<PositiveDuration>,

    /// Deprecated compatibility flag. Ignored by the elastic proposal budget.
    #[arg(
        long = "consensus.minimum-time-before-propose",
        visible_alias = "consensus.time-to-build-proposal",
        value_name = "DURATION",
        help = "Deprecated: no longer has any effect and will be removed in the next release."
    )]
    pub minimum_time_before_propose: Option<PositiveDuration>,

    /// The amount of time this node will use to construct a subblock before
    /// sending it to the next proposer.
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
    loaded_signing_key: Arc<tokio::sync::OnceCell<Option<SigningKey>>>,

    /// Where to store consensus data. If not set, this will be derived from
    /// `--datadir`.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    pub storage_dir: Option<PathBuf>,

    /// Number of recently finalized blocks the marshal actor keeps in its
    /// prunable archive. Anything older is served from reth's database
    /// through the hybrid finalized blocks store.
    #[arg(
        long = "consensus.finalized-blocks-retention",
        default_value_t = crate::storage::DEFAULT_FINALIZED_BLOCKS_RETENTION,
    )]
    pub finalized_blocks_retention: u64,

    /// Deprecated compatibility flag. Ignored because the legacy immutable
    /// finalized blocks archive has been removed.
    #[arg(
        long = "consensus.no-legacy-archive",
        help = "Deprecated: the legacy finalized blocks archive has been removed, so this flag no longer has any effect."
    )]
    pub no_legacy_archive: bool,
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
    /// Returns the signing key loaded from the configured file.
    ///
    /// When `--consensus.secret` is set, tries to decrypt the signing key.
    /// If not, treats the file contents as plaintext hex.
    pub(crate) async fn signing_key(&self) -> eyre::Result<Option<SigningKey>> {
        Ok(self
            .loaded_signing_key
            .get_or_try_init(|| async { self.load_signing_key().await })
            .await
            .wrap_err("failed reading signing key")?
            .clone())
    }

    async fn load_signing_key(&self) -> eyre::Result<Option<SigningKey>> {
        Ok(match (self.signing_key.as_ref(), self.secret.as_ref()) {
            (Some(path), Some(secret)) => {
                let passphrase = read_secret(secret).await.wrap_err_with(|| {
                    format!("failed reading secret from `{}`", secret.display())
                })?;
                Some(
                    SigningKey::read_from_file_encrypted(path, passphrase).wrap_err_with(|| {
                        format!(
                            "failed reading ed25519 signing key from file `{}`",
                            path.display()
                        )
                    })?,
                )
            }
            (Some(path), None) => Some(
                SigningKey::read_from_file_unencrypted(path).wrap_err_with(|| {
                    format!(
                        "failed reading private ed25519 signing key from file `{}`",
                        path.display()
                    )
                })?,
            ),
            (None, Some(_secret)) => {
                unreachable!(
                    "clap enforces that `--consensus.secret` requires `--consensus.signing-key` to point at the encrypted key file"
                );
            }
            (None, None) => None,
        })
    }

    /// Returns the public key derived from the configured signing key, if any.
    pub async fn public_key(&self) -> eyre::Result<Option<PublicKey>> {
        Ok(self
            .signing_key()
            .await?
            .map(|signing_key| signing_key.public_key()))
    }

    pub fn network_identity(&self) -> Option<tempo_chainspec::NetworkIdentity> {
        let identity = self.network_identity?;
        let from_epoch = self
            .network_identity_from_epoch
            .expect("network identity from epoch required");

        Some(tempo_chainspec::NetworkIdentity {
            from_epoch,
            identity: identity.0,
        })
    }
}

/// Read a single passphrase from `path` via blocking std I/O.
async fn read_secret<P: AsRef<Path>>(path: P) -> eyre::Result<SigningKeyPassphrase> {
    let path = path.as_ref().to_path_buf();
    let task_path = path.clone();
    let mut read =
        tokio::task::spawn_blocking(move || tempo_commonware_node_config::read_secret(&task_path));
    let mut warning_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + PASSPHRASE_SECRET_WAIT_WARNING_INTERVAL,
        PASSPHRASE_SECRET_WAIT_WARNING_INTERVAL,
    );

    loop {
        tokio::select! {
            result = &mut read => {
                let (passphrase, is_fifo) =
                    result
                        .map_err(eyre::Report::new)
                        .and_then(|res| res.map_err(eyre::Report::new))
                        .wrap_err("failed reading secret")?;
                    warn_if_not_fifo(is_fifo, &path);
                return Ok(passphrase);
            }
            _ = warning_interval.tick() => {
                tracing::warn_span!(
                    "signing_key_passphrase_secret",
                    path = %path.display(),
                )
                .in_scope(|| {
                    tracing::warn!(
                        "still waiting for signing-key passphrase from secret path; if this is a FIFO, write the passphrase and close the writer"
                    );
                });
            }
        }
    }
}

fn warn_if_not_fifo(is_fifo: bool, path: &Path) {
    if !is_fifo {
        tracing::warn_span!(
        "signing_key_passphrase_secret",
        path = %path.display(),
    )
    .in_scope(|| {
        tracing::warn!(
            "signing-key passphrase was read from a non-FIFO path; prefer a FIFO to avoid persisting the passphrase on disk"
        );
    });
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, process::Command, thread, time::Duration};

    use clap::Parser as _;
    use commonware_codec::Encode as _;

    use super::Args;

    const SIGNING_KEY_HEX: &str =
        "0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
    const PASSPHRASE: &str = "correct horse battery staple";

    fn raw_private_key_bytes() -> Vec<u8> {
        tempo_commonware_node_config::SigningKey::try_from_hex(SIGNING_KEY_HEX)
            .unwrap()
            .into_inner()
            .encode()
            .to_vec()
    }

    #[derive(Debug, clap::Parser)]
    struct TestCli {
        // Stubs for the `required_unless_present_any = ["follow", "dev"]`
        // gate on `--consensus.signing-key`. These args live in the outer
        // binary's CLI struct; we re-declare them here just so clap can
        // resolve the references during parse-time validation.
        #[arg(long = "follow")]
        #[allow(dead_code)]
        follow: Option<String>,
        #[arg(long = "dev")]
        #[allow(dead_code)]
        dev: bool,

        #[command(flatten)]
        consensus: Args,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(std::iter::once("test").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn deprecated_proposal_timing_flags_parse() {
        for flag in [
            "--consensus.time-to-prepare-proposal-transactions",
            "--consensus.minimum-time-before-propose",
            "--consensus.time-to-build-proposal",
        ] {
            parse(&["--dev", flag, "1ms"]);
        }
    }

    fn encrypt(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        let mut ct = Vec::new();
        let mut w = age::Encryptor::with_user_passphrase(
            tempo_commonware_node_config::SigningKeyPassphrase::from(passphrase),
        )
        .wrap_output(&mut ct)
        .unwrap();
        w.write_all(plaintext).unwrap();
        w.finish().unwrap();
        ct
    }

    fn mkfifo(path: &std::path::Path) {
        let status = Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(path)
            .status()
            .expect("mkfifo must be available");
        assert!(status.success(), "mkfifo failed: {status}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn encrypted_signing_key_via_fifo_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("signing-key.age");
        std::fs::write(&key_file, encrypt(&raw_private_key_bytes(), PASSPHRASE)).unwrap();

        let fifo = dir.path().join("passphrase.fifo");
        mkfifo(&fifo);

        let fifo_writer = fifo.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_writer)
                .unwrap();
            writeln!(f, "{PASSPHRASE}").unwrap();
        });

        let cli = parse(&[
            "--consensus.signing-key",
            key_file.to_str().unwrap(),
            "--consensus.secret",
            fifo.to_str().unwrap(),
        ]);

        let key = cli
            .consensus
            .signing_key()
            .await
            .expect("signing key must load")
            .expect("signing key must be Some when --consensus.signing-key is set");
        writer.join().unwrap();

        let expected =
            tempo_commonware_node_config::SigningKey::try_from_hex(SIGNING_KEY_HEX).unwrap();
        assert_eq!(key.public_key(), expected.public_key());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn encrypted_signing_key_via_regular_secret_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("signing-key.age");
        let secret_file = dir.path().join("passphrase.txt");
        std::fs::write(&key_file, encrypt(&raw_private_key_bytes(), PASSPHRASE)).unwrap();
        std::fs::write(&secret_file, format!("{PASSPHRASE}\n")).unwrap();

        let cli = parse(&[
            "--consensus.signing-key",
            key_file.to_str().unwrap(),
            "--consensus.secret",
            secret_file.to_str().unwrap(),
        ]);

        let key = cli
            .consensus
            .signing_key()
            .await
            .expect("signing key must load")
            .expect("signing key must be Some when --consensus.signing-key is set");

        let expected =
            tempo_commonware_node_config::SigningKey::try_from_hex(SIGNING_KEY_HEX).unwrap();
        assert_eq!(key.public_key(), expected.public_key());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn encrypted_signing_key_concurrent_calls_share_fifo_read() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("signing-key.age");
        std::fs::write(&key_file, encrypt(&raw_private_key_bytes(), PASSPHRASE)).unwrap();

        let fifo = dir.path().join("passphrase.fifo");
        mkfifo(&fifo);

        let fifo_writer = fifo.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_writer)
                .unwrap();
            writeln!(f, "{PASSPHRASE}").unwrap();
        });

        let cli = parse(&[
            "--consensus.signing-key",
            key_file.to_str().unwrap(),
            "--consensus.secret",
            fifo.to_str().unwrap(),
        ]);

        let consensus_a = cli.consensus.clone();
        let consensus_b = cli.consensus.clone();
        let (key_a, key_b) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(consensus_a.signing_key(), consensus_b.signing_key())
        })
        .await
        .expect("concurrent signing-key loads must not wait for a second pipe write");
        writer.join().unwrap();

        let key_a = key_a
            .expect("first signing key must load")
            .expect("first signing key must be Some");
        let key_b = key_b
            .expect("second signing key must load")
            .expect("second signing key must be Some");

        let expected =
            tempo_commonware_node_config::SigningKey::try_from_hex(SIGNING_KEY_HEX).unwrap();
        assert_eq!(key_a.public_key(), expected.public_key());
        assert_eq!(key_b.public_key(), expected.public_key());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn encrypted_signing_key_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("signing-key.age");
        std::fs::write(&key_file, encrypt(&raw_private_key_bytes(), PASSPHRASE)).unwrap();

        let fifo = dir.path().join("passphrase.fifo");
        mkfifo(&fifo);

        let fifo_writer = fifo.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_writer)
                .unwrap();
            writeln!(f, "wrong-passphrase").unwrap();
        });

        let cli = parse(&[
            "--consensus.signing-key",
            key_file.to_str().unwrap(),
            "--consensus.secret",
            fifo.to_str().unwrap(),
        ]);

        let _ = cli
            .consensus
            .signing_key()
            .await
            .expect_err("loading with a wrong passphrase must fail");
        writer.join().unwrap();
    }
}
