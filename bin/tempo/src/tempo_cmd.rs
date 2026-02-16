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
// check-peers: P2P connectivity diagnostic
// ---------------------------------------------------------------------------

/// Per-validator connectivity result.
#[derive(Debug, Serialize)]
struct PeerCheckResult {
    public_key: String,
    inbound_address: String,
    active: bool,
    in_committee: bool,
    tcp_reachable: bool,
    tcp_latency_ms: Option<u64>,
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

    /// Timeout per TCP connection attempt.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,

    /// Only check a specific validator (hex-encoded ed25519 public key).
    #[arg(long)]
    validator: Option<String>,
}

impl CheckPeers {
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

        let timeout = Duration::from_secs(self.timeout_secs);

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
        let mut targets: Vec<(String, String, bool, bool)> = Vec::new();
        for v in decoded.into_iter() {
            let key = PublicKey::decode(&mut &v.publicKey.0[..])
                .wrap_err("failed decoding on-chain ed25519 key")?;
            let key_hex = alloy_primitives::hex::encode(v.publicKey.0);

            let in_committee = dkg_outcome
                .as_ref()
                .is_some_and(|o| o.players().position(&key).is_some());

            // Skip inactive validators not in committee unless explicitly requested.
            if !v.active && !in_committee {
                continue;
            }

            // If a specific validator was requested, filter.
            if let Some(ref filter) = self.validator {
                if !key_hex.contains(filter.trim_start_matches("0x")) {
                    continue;
                }
            }

            targets.push((key_hex, v.inboundAddress, v.active, in_committee));
        }

        // Run connectivity checks concurrently.
        let mut handles = Vec::with_capacity(targets.len());
        for (key_hex, addr_str, active, in_committee) in &targets {
            let addr_str = addr_str.clone();
            let key_hex = key_hex.clone();
            let active = *active;
            let in_committee = *in_committee;
            handles.push(tokio::spawn(async move {
                check_tcp(&key_hex, &addr_str, active, in_committee, timeout).await
            }));
        }

        let mut peers = Vec::with_capacity(handles.len());
        for handle in handles {
            peers.push(handle.await.wrap_err("task join error")?);
        }

        let reachable = peers.iter().filter(|p| p.tcp_reachable).count();
        let unreachable = peers.len() - reachable;

        let output = CheckPeersOutput {
            chain: self.chain.info.chain_name().to_string(),
            current_epoch: current_epoch.get(),
            total_validators: peers.len(),
            reachable,
            unreachable,
            peers,
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

/// Attempts a TCP connection to a validator's inbound address and measures
/// latency.
async fn check_tcp(
    key_hex: &str,
    addr_str: &str,
    active: bool,
    in_committee: bool,
    timeout: Duration,
) -> PeerCheckResult {
    let result = async {
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| eyre!("invalid address `{addr_str}`: {e}"))?;

        let start = std::time::Instant::now();
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| eyre!("connection timed out after {timeout:?}"))?
            .map_err(|e| eyre!("tcp connect failed: {e}"))?;
        Ok::<_, Report>(start.elapsed())
    }
    .await;

    match result {
        Ok(elapsed) => PeerCheckResult {
            public_key: key_hex.to_string(),
            inbound_address: addr_str.to_string(),
            active,
            in_committee,
            tcp_reachable: true,
            tcp_latency_ms: Some(elapsed.as_millis() as u64),
            error: None,
        },
        Err(e) => PeerCheckResult {
            public_key: key_hex.to_string(),
            inbound_address: addr_str.to_string(),
            active,
            in_committee,
            tcp_reachable: false,
            tcp_latency_ms: None,
            error: Some(e.to_string()),
        },
    }
}
