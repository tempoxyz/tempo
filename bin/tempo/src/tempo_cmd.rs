use std::{fs::OpenOptions, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use alloy_primitives::Address;
use alloy_provider::Provider;

use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_utils::NZU64;
use eyre::{OptionExt as _, Report, WrapErr as _, eyre};
use reth_cli_runner::CliRunner;
use reth_ethereum_cli::ExtendedCommand;
use serde::Serialize;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_commonware_node_config::SigningKey;
use tempo_contracts::precompiles::{IValidatorConfig, VALIDATOR_CONFIG_ADDRESS};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

/// Tempo-specific subcommands that extend the reth CLI.
#[derive(Debug, Subcommand)]
pub(crate) enum TempoSubcommand {
    /// Consensus-related commands.
    #[command(subcommand)]
    Consensus(ConsensusSubcommand),
}

impl ExtendedCommand for TempoSubcommand {
    fn execute(self, _runner: CliRunner) -> eyre::Result<()> {
        match self {
            Self::Consensus(cmd) => cmd.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConsensusSubcommand {
    /// Generates an ed25519 signing key pair to be used in consensus.
    GeneratePrivateKey(GeneratePrivateKey),
    /// Calculates the public key from an ed25519 signing key.
    CalculatePublicKey(CalculatePublicKey),
    /// Query validator info from the previous epoch's DKG outcome and current contract state.
    ValidatorsInfo(ValidatorsInfo),
    /// Diagnose P2P connectivity to all validators in the active set.
    CheckPeers(CheckPeers),
}

impl ConsensusSubcommand {
    fn run(self) -> eyre::Result<()> {
        match self {
            Self::GeneratePrivateKey(args) => args.run(),
            Self::CalculatePublicKey(args) => args.run(),
            Self::ValidatorsInfo(args) => args.run(),
            Self::CheckPeers(args) => args.run(),
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct GeneratePrivateKey {
    /// Destination of the generated signing key.
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,

    /// Whether to override `output`, if it already exists.
    #[arg(long, short)]
    force: bool,
}

impl GeneratePrivateKey {
    fn run(self) -> eyre::Result<()> {
        let Self { output, force } = self;
        let signing_key = PrivateKey::random(&mut rand_08::thread_rng());
        let public_key = signing_key.public_key();
        let signing_key = SigningKey::from(signing_key);
        OpenOptions::new()
            .write(true)
            .create_new(!force)
            .create(force)
            .truncate(force)
            .open(&output)
            .map_err(Report::new)
            .and_then(|f| signing_key.to_writer(f).map_err(Report::new))
            .wrap_err_with(|| format!("failed writing private key to `{}`", output.display()))?;
        eprintln!(
            "wrote private key to: {}\npublic key: {public_key}",
            output.display()
        );
        Ok(())
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct CalculatePublicKey {
    /// Private key to calculate the public key from.
    #[arg(long, short, value_name = "FILE")]
    private_key: PathBuf,
}

impl CalculatePublicKey {
    fn run(self) -> eyre::Result<()> {
        let Self { private_key } = self;
        let private_key = SigningKey::read_from_file(&private_key).wrap_err_with(|| {
            format!(
                "failed reading private key from `{}`",
                private_key.display()
            )
        })?;
        let validating_key = private_key.public_key();
        println!("public key: {validating_key}");
        Ok(())
    }
}

/// Validator info output structure
#[derive(Debug, Serialize)]
struct ValidatorInfoOutput {
    /// The current epoch (at the time of query)
    current_epoch: u64,
    /// The current height (at the time of query)
    current_height: u64,
    // The boundary height from which the DKG outcome was read
    last_boundary: u64,
    // The epoch length as set in the chain spec
    epoch_length: u64,
    /// Whether this is a full DKG (new polynomial) or reshare
    is_next_full_dkg: bool,
    /// The epoch at which the next full DKG ceremony will be triggered (from contract)
    next_full_dkg_epoch: u64,
    /// List of validators participating in the DKG
    validators: Vec<ValidatorEntry>,
}

/// Individual validator entry
#[derive(Debug, Serialize)]
struct ValidatorEntry {
    /// onchain address of the validator
    onchain_address: Address,
    /// ed25519 public key (hex)
    public_key: String,
    /// Inbound IP address for p2p connections
    inbound_address: String,
    /// Outbound IP address
    outbound_address: String,
    /// Whether the validator is active in the current contract state
    active: bool,
    // Whether the validator is a dealer in th ecurrent epoch.
    is_dkg_dealer: bool,
    /// Whether the validator is a player in the current epoch.
    is_dkg_player: bool,
    /// Whether the validator is in the committee for the given epoch.
    in_committee: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorsInfo {
    /// Chain to query (presto, testnet, moderato, or path to chainspec file)
    #[arg(long, short, default_value = "mainnet", value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC URL to query. Defaults to <https://rpc.presto.tempo.xyz>
    #[arg(long, default_value = "https://rpc.presto.tempo.xyz")]
    rpc_url: String,

    /// Whethr to include historic validators (deactivated and not in the current committee).
    #[arg(long)]
    with_historic: bool,
}

impl ValidatorsInfo {
    fn run(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("failed constructing async runtime")?
            .block_on(self.run_async())
    }

    async fn run_async(self) -> eyre::Result<()> {
        use alloy_consensus::BlockHeader;
        use alloy_provider::ProviderBuilder;

        let epoch_length = self
            .chain
            .info
            .epoch_length()
            .ok_or_eyre("epochLength not found in chainspec")?;

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let latest_block_number = provider
            .get_block_number()
            .await
            .wrap_err("failed to get latest block number")?;

        let epoch_strategy = FixedEpocher::new(NZU64!(epoch_length));
        let current_height = Height::new(latest_block_number);
        let current_epoch_info = epoch_strategy
            .containing(current_height)
            .ok_or_else(|| eyre!("failed to determine epoch for height {latest_block_number}"))?;

        let current_epoch = current_epoch_info.epoch();
        let boundary_height = current_epoch
            .previous()
            .map(|epoch| epoch_strategy.last(epoch).expect("valid epoch"))
            .unwrap_or_default();

        let boundary_block = provider
            .get_block_by_number(boundary_height.get().into())
            .hashes()
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to get block header at height {}",
                    boundary_height.get()
                )
            })?
            .ok_or_eyre("boundary block not found")?;

        let extra_data = boundary_block.header.extra_data();
        if extra_data.is_empty() {
            return Err(eyre!(
                "boundary block at height {} has no DKG outcome in extra_data",
                boundary_height.get()
            ));
        }

        let dkg_outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())
            .wrap_err("failed to decode DKG outcome from extra_data")?;

        let validators_result = provider
            .call(
                TransactionRequest::default()
                    .to(VALIDATOR_CONFIG_ADDRESS)
                    .input(IValidatorConfig::getValidatorsCall {}.abi_encode().into())
                    .into(),
            )
            .await
            .wrap_err("failed to call getValidators")?;

        let decoded_validators =
            IValidatorConfig::getValidatorsCall::abi_decode_returns(&validators_result)
                .wrap_err("failed to decode getValidators response")?;

        let next_dkg_result = provider
            .call(
                TransactionRequest::default()
                    .to(VALIDATOR_CONFIG_ADDRESS)
                    .input(
                        IValidatorConfig::getNextFullDkgCeremonyCall {}
                            .abi_encode()
                            .into(),
                    )
                    .into(),
            )
            .await
            .wrap_err("failed to call getNextFullDkgCeremony")?;
        let decoded_next_dkg =
            IValidatorConfig::getNextFullDkgCeremonyCall::abi_decode_returns(&next_dkg_result)
                .wrap_err("failed to decode getNextFullDkgCeremony response")?;

        let mut validator_entries = Vec::with_capacity(decoded_validators.len());
        for validator in decoded_validators.into_iter() {
            let pubkey_bytes = validator.publicKey.0;
            let key = PublicKey::decode(&mut &validator.publicKey.0[..])
                .wrap_err("failed decoding on-chain ed25519 key")?;

            let in_committee = dkg_outcome.players().position(&key).is_some();

            if self.with_historic || (validator.active || in_committee) {
                validator_entries.push(ValidatorEntry {
                    onchain_address: validator.validatorAddress,
                    public_key: alloy_primitives::hex::encode(pubkey_bytes),
                    inbound_address: validator.inboundAddress,
                    outbound_address: validator.outboundAddress,
                    active: validator.active,
                    is_dkg_dealer: dkg_outcome.players().position(&key).is_some(),
                    is_dkg_player: dkg_outcome.next_players().position(&key).is_some(),
                    in_committee,
                });
            }
        }

        let output = ValidatorInfoOutput {
            current_epoch: current_epoch.get(),
            current_height: current_height.get(),
            last_boundary: boundary_height.get(),
            epoch_length,
            is_next_full_dkg: dkg_outcome.is_next_full_dkg,
            next_full_dkg_epoch: decoded_next_dkg,
            validators: validator_entries,
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// check-peers: P2P connectivity diagnostic using encrypted handshake
// ---------------------------------------------------------------------------

/// Per-validator connectivity result.
#[derive(Debug, Serialize)]
struct PeerCheckResult {
    public_key: String,
    inbound_address: String,
    active: bool,
    in_committee: bool,
    /// Whether the peer was reachable at the TCP level.
    reachable: bool,
    /// Whether the ed25519 P2P handshake completed, proving the correct
    /// validator key is behind the endpoint (not just a proxy).
    identity_verified: bool,
    handshake_latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Aggregate output of the check-peers command.
#[derive(Debug, Serialize)]
struct CheckPeersOutput {
    chain: String,
    current_epoch: u64,
    total_validators: usize,
    reachable: usize,
    unreachable: usize,
    verified: usize,
    peers: Vec<PeerCheckResult>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct CheckPeers {
    /// Chain to query.
    #[arg(
        long,
        short,
        default_value = "mainnet",
        value_parser = tempo_chainspec::spec::chain_value_parser,
    )]
    chain: Arc<TempoChainSpec>,

    /// RPC URL to query for on-chain validator data.
    #[arg(long, default_value = "https://rpc.presto.tempo.xyz")]
    rpc_url: String,

    /// Path to the operator's ed25519 signing key. Required for the P2P
    /// handshake — the key must be in the active validator set so that remote
    /// peers accept the connection.
    #[arg(long, value_name = "FILE")]
    signing_key: PathBuf,

    /// Timeout per handshake attempt in seconds.
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,

    /// Only check a specific validator (hex-encoded ed25519 public key).
    #[arg(long)]
    validator: Option<String>,
}

/// Stream-level namespace used by Tempo's P2P layer. The lookup network
/// constructs this as `union(union_unique(NAMESPACE, b"_P2P"), b"_STREAM")`
/// where `NAMESPACE = b"TEMPO"`. Must match `commonware-node/src/config.rs`.
fn stream_namespace() -> Vec<u8> {
    const NAMESPACE: &[u8] = b"TEMPO";
    commonware_utils::union(
        &commonware_utils::union_unique(NAMESPACE, b"_P2P"),
        b"_STREAM",
    )
}

impl CheckPeers {
    fn run(self) -> eyre::Result<()> {
        use commonware_runtime::Runner as _;

        // Load the operator's signing key before entering the runtime so that
        // file-system errors surface immediately.
        let signing_key = SigningKey::read_from_file(&self.signing_key)
            .wrap_err_with(|| {
                format!(
                    "failed reading signing key from `{}`",
                    self.signing_key.display()
                )
            })?;
        let private_key = signing_key.into_inner();

        let cfg = commonware_runtime::tokio::Config::default()
            .with_worker_threads(2);

        commonware_runtime::tokio::Runner::new(cfg).start(|ctx| async move {
            match self.run_async(ctx, private_key).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(1);
                }
            }
        });

        Ok(())
    }

    async fn run_async(
        self,
        ctx: commonware_runtime::tokio::Context,
        signing_key: PrivateKey,
    ) -> eyre::Result<()> {
        use alloy_consensus::BlockHeader;
        use alloy_provider::ProviderBuilder;
        use commonware_runtime::Spawner as _;
        use reth_ethereum::chainspec::EthChainSpec as _;

        let handshake_timeout = Duration::from_secs(self.timeout_secs);

        // Resolve chain metadata.
        let epoch_length = self
            .chain
            .info
            .epoch_length()
            .ok_or_eyre("epochLength not found in chainspec")?;

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let latest_block_number = provider
            .get_block_number()
            .await
            .wrap_err("failed to get latest block number")?;

        let epoch_strategy = FixedEpocher::new(NZU64!(epoch_length));
        let current_height = Height::new(latest_block_number);
        let current_epoch_info = epoch_strategy
            .containing(current_height)
            .ok_or_else(|| eyre!("failed to determine epoch for height {latest_block_number}"))?;
        let current_epoch = current_epoch_info.epoch();

        let own_pubkey = signing_key.public_key();
        eprintln!(
            "using signing key with public key: {own_pubkey}\n\
             chain: {}\n\
             epoch: {}",
            self.chain.chain(),
            current_epoch.get(),
        );

        // Read DKG outcome from the boundary block.
        let boundary_height = current_epoch
            .previous()
            .map(|epoch| epoch_strategy.last(epoch).expect("valid epoch"))
            .unwrap_or_default();

        let boundary_block = provider
            .get_block_by_number(boundary_height.get().into())
            .hashes()
            .await
            .wrap_err("failed to fetch boundary block")?
            .ok_or_eyre("boundary block not found")?;

        let extra_data = boundary_block.header.extra_data();
        let dkg_outcome = if extra_data.is_empty() {
            None
        } else {
            OnchainDkgOutcome::read(&mut extra_data.as_ref()).ok()
        };

        // Fetch on-chain validator set.
        let validators_result = provider
            .call(
                TransactionRequest::default()
                    .to(VALIDATOR_CONFIG_ADDRESS)
                    .input(IValidatorConfig::getValidatorsCall {}.abi_encode().into())
                    .into(),
            )
            .await
            .wrap_err("failed to call getValidators")?;

        let decoded =
            IValidatorConfig::getValidatorsCall::abi_decode_returns(&validators_result)
                .wrap_err("failed to decode getValidators response")?;

        // Build the list of validators to check.
        let mut targets: Vec<(PublicKey, String, String, bool, bool)> = Vec::new();
        for v in decoded.into_iter() {
            let key = PublicKey::decode(&mut &v.publicKey.0[..])
                .wrap_err("failed decoding on-chain ed25519 key")?;
            let key_hex = alloy_primitives::hex::encode(v.publicKey.0);

            let in_committee = dkg_outcome
                .as_ref()
                .is_some_and(|o| o.players().position(&key).is_some());

            // Skip inactive validators not in committee.
            if !v.active && !in_committee {
                continue;
            }

            // If a specific validator was requested, filter.
            if let Some(ref filter) = self.validator {
                if !key_hex.contains(filter.trim_start_matches("0x")) {
                    continue;
                }
            }

            targets.push((key, key_hex, v.inboundAddress, v.active, in_committee));
        }

        eprintln!("checking {} validator(s)...\n", targets.len());

        // Run handshake checks concurrently via the commonware spawner.
        let namespace = stream_namespace();
        let mut handles = Vec::with_capacity(targets.len());
        for (peer_key, key_hex, addr_str, active, in_committee) in targets {
            let signing_key = signing_key.clone();
            let namespace = namespace.clone();
            handles.push(ctx.clone().spawn(move |inner_ctx| async move {
                check_handshake(
                    inner_ctx,
                    &signing_key,
                    &namespace,
                    &peer_key,
                    &key_hex,
                    &addr_str,
                    active,
                    in_committee,
                    handshake_timeout,
                )
                .await
            }));
        }

        let mut peers = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => peers.push(result),
                Err(e) => {
                    eprintln!("warning: task failed: {e}");
                }
            }
        }

        let reachable = peers.iter().filter(|p| p.reachable).count();
        let unreachable = peers.len() - reachable;
        let verified = peers.iter().filter(|p| p.identity_verified).count();

        let output = CheckPeersOutput {
            chain: self.chain.chain().to_string(),
            current_epoch: current_epoch.get(),
            total_validators: peers.len(),
            reachable,
            unreachable,
            verified,
            peers,
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

/// Performs a full P2P handshake against a single validator using the
/// `commonware-stream` encrypted transport. A successful handshake proves
/// that the node behind the address holds the expected ed25519 private key.
async fn check_handshake(
    ctx: commonware_runtime::tokio::Context,
    signing_key: &PrivateKey,
    namespace: &[u8],
    peer_key: &PublicKey,
    key_hex: &str,
    addr_str: &str,
    active: bool,
    in_committee: bool,
    handshake_timeout: Duration,
) -> PeerCheckResult {
    use commonware_runtime::Network as _;
    use commonware_stream::encrypted;

    let result = async {
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| eyre!("invalid address `{addr_str}`: {e}"))?;

        // Phase 1: TCP connect (measures raw reachability).
        let start = std::time::Instant::now();
        let (sink, stream) = ctx.dial(addr).await.map_err(|e| eyre!("dial failed: {e}"))?;

        // Phase 2: Encrypted handshake — proves the peer holds the correct key.
        let stream_config = encrypted::Config {
            signing_key: signing_key.clone(),
            namespace: namespace.to_vec(),
            max_message_size: 16 * 1024 * 1024, // 16 MiB, generous upper bound
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout,
        };

        let _connection = encrypted::dial(
            ctx.clone(),
            stream_config,
            peer_key.clone(),
            stream,
            sink,
        )
        .await
        .map_err(|e| eyre!("handshake failed: {e}"))?;

        // Connection established — the peer's SynAck signature verified.
        // We can drop the channel immediately; the diagnostic is complete.
        Ok::<_, Report>(start.elapsed())
    }
    .await;

    match result {
        Ok(elapsed) => PeerCheckResult {
            public_key: key_hex.to_string(),
            inbound_address: addr_str.to_string(),
            active,
            in_committee,
            reachable: true,
            identity_verified: true,
            handshake_latency_ms: Some(elapsed.as_millis() as u64),
            error: None,
        },
        Err(e) => {
            let err_str = format!("{e:#}");
            // Distinguish between TCP-level and handshake-level failures.
            let reachable = !err_str.contains("dial failed");
            PeerCheckResult {
                public_key: key_hex.to_string(),
                inbound_address: addr_str.to_string(),
                active,
                in_committee,
                reachable,
                identity_verified: false,
                handshake_latency_ms: None,
                error: Some(err_str),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_runtime::{Listener as _, Network as _, Runner as _, Spawner as _};
    use commonware_stream::encrypted;

    /// Spin up a real TCP listener that performs `encrypted::listen` with
    /// `listener_key`, then run `check_handshake` against it using
    /// `dialer_key`. Returns the `PeerCheckResult`.
    fn run_handshake_test(
        listener_key: PrivateKey,
        dialer_key: PrivateKey,
        expected_peer_key: &PublicKey,
        accept_dialer: bool,
    ) -> PeerCheckResult {
        let namespace = stream_namespace();
        let key_hex = alloy_primitives::hex::encode(expected_peer_key.encode());
        let ns = namespace.clone();

        commonware_runtime::tokio::Runner::default().start(|ctx| async move {
            // Bind a TCP listener on an ephemeral port.
            let mut tcp_listener = ctx
                .bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("bind failed");
            let addr = tcp_listener.local_addr().expect("local_addr failed");
            let addr_str = addr.to_string();

            let listener_ns = ns.clone();
            let dialer_pub = dialer_key.public_key();

            // Spawn the listener side: accept one TCP connection, then run
            // the encrypted handshake as if we were a validator node.
            let listener_handle = ctx.clone().spawn(move |inner_ctx| async move {
                let (_peer_addr, sink, stream) = tcp_listener.accept().await.unwrap();
                let cfg = encrypted::Config {
                    signing_key: listener_key,
                    namespace: listener_ns,
                    max_message_size: 16 * 1024 * 1024,
                    synchrony_bound: Duration::from_secs(5),
                    max_handshake_age: Duration::from_secs(10),
                    handshake_timeout: Duration::from_secs(5),
                };
                let accept = accept_dialer;
                let expected = dialer_pub;
                encrypted::listen(
                    inner_ctx,
                    move |peer: PublicKey| {
                        let expected = expected.clone();
                        async move { accept && peer == expected }
                    },
                    cfg,
                    stream,
                    sink,
                )
                .await
            });

            // Run the dialer (our check_handshake function) against the listener.
            let result = check_handshake(
                ctx.clone(),
                &dialer_key,
                &namespace,
                expected_peer_key,
                &key_hex,
                &addr_str,
                true,  // active
                true,  // in_committee
                Duration::from_secs(5),
            )
            .await;

            // Wait for listener to finish (ignore its result; we only care
            // about the dialer's perspective).
            let _ = listener_handle.await;

            result
        })
    }

    /// Happy path: the listener holds the expected key and accepts us.
    /// The handshake must complete with `identity_verified = true`.
    #[test]
    fn test_handshake_success() {
        let dialer_key = PrivateKey::from_seed(1);
        let listener_key = PrivateKey::from_seed(2);
        let listener_pub = listener_key.public_key();

        let result = run_handshake_test(listener_key, dialer_key, &listener_pub, true);

        assert!(result.reachable, "peer should be TCP-reachable");
        assert!(
            result.identity_verified,
            "handshake should verify the listener's identity"
        );
        assert!(
            result.handshake_latency_ms.is_some(),
            "latency should be recorded on success"
        );
        assert!(result.error.is_none(), "no error expected on success");
    }

    /// The listener holds the expected key but its bouncer rejects us.
    /// The dialer should report `reachable = true` (TCP connected) but
    /// `identity_verified = false` (handshake rejected).
    #[test]
    fn test_handshake_rejected_by_bouncer() {
        let dialer_key = PrivateKey::from_seed(3);
        let listener_key = PrivateKey::from_seed(4);
        let listener_pub = listener_key.public_key();

        let result = run_handshake_test(listener_key, dialer_key, &listener_pub, false);

        assert!(result.reachable, "peer should be TCP-reachable");
        assert!(
            !result.identity_verified,
            "handshake should fail when bouncer rejects"
        );
        assert!(result.error.is_some(), "error expected when rejected");
    }

    /// The endpoint is completely unreachable (nothing listening).
    /// Should report `reachable = false`, `identity_verified = false`.
    #[test]
    fn test_handshake_unreachable() {
        let dialer_key = PrivateKey::from_seed(5);
        let fake_peer_key = PrivateKey::from_seed(6).public_key();
        let namespace = stream_namespace();
        let key_hex = alloy_primitives::hex::encode(fake_peer_key.encode());
        // Port 1 on localhost is almost certainly not listening.
        let addr_str = "127.0.0.1:1".to_string();

        let result =
            commonware_runtime::tokio::Runner::default().start(|ctx| async move {
                check_handshake(
                    ctx,
                    &dialer_key,
                    &namespace,
                    &fake_peer_key,
                    &key_hex,
                    &addr_str,
                    true,
                    false,
                    Duration::from_secs(2),
                )
                .await
            });

        assert!(!result.reachable, "unreachable addr should not be reachable");
        assert!(
            !result.identity_verified,
            "cannot verify identity of unreachable peer"
        );
        assert!(
            result.error.as_ref().unwrap().contains("dial failed"),
            "error should mention dial failure"
        );
    }

    /// When the listener holds a DIFFERENT key than what the dialer expects,
    /// the handshake should fail because the ed25519 signature in the SynAck
    /// won't match the expected public key.
    #[test]
    fn test_handshake_wrong_key() {
        let dialer_key = PrivateKey::from_seed(7);
        let actual_listener_key = PrivateKey::from_seed(8);
        // The dialer expects a different key than what the listener holds.
        let wrong_expected_key = PrivateKey::from_seed(9).public_key();

        let namespace = stream_namespace();
        let key_hex = alloy_primitives::hex::encode(wrong_expected_key.encode());

        let result =
            commonware_runtime::tokio::Runner::default().start(|ctx| async move {
                // Start a listener with actual_listener_key.
                let mut tcp_listener = ctx
                    .bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .expect("bind failed");
                let addr = tcp_listener.local_addr().expect("local_addr failed");
                let addr_str = addr.to_string();
                let ns = namespace.clone();

                let listener_handle =
                    ctx.clone().spawn(move |inner_ctx| async move {
                        let (_peer_addr, sink, stream) =
                            tcp_listener.accept().await.unwrap();
                        let cfg = encrypted::Config {
                            signing_key: actual_listener_key,
                            namespace: ns,
                            max_message_size: 16 * 1024 * 1024,
                            synchrony_bound: Duration::from_secs(5),
                            max_handshake_age: Duration::from_secs(10),
                            handshake_timeout: Duration::from_secs(5),
                        };
                        // Accept anyone at the bouncer level.
                        encrypted::listen(
                            inner_ctx,
                            |_: PublicKey| async { true },
                            cfg,
                            stream,
                            sink,
                        )
                        .await
                    });

                let result = check_handshake(
                    ctx.clone(),
                    &dialer_key,
                    &namespace,
                    &wrong_expected_key,
                    &key_hex,
                    &addr_str,
                    true,
                    true,
                    Duration::from_secs(5),
                )
                .await;

                let _ = listener_handle.await;
                result
            });

        assert!(result.reachable, "TCP should connect fine");
        assert!(
            !result.identity_verified,
            "wrong key should NOT verify identity"
        );
        assert!(result.error.is_some(), "should report handshake error");
    }
}
