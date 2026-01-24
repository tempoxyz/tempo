use std::{collections::HashMap, fs::OpenOptions, path::PathBuf, sync::Arc};

use alloy_primitives::Address;
use alloy_provider::Provider;

use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use commonware_codec::ReadExt as _;
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
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
}

impl ConsensusSubcommand {
    fn run(self) -> eyre::Result<()> {
        match self {
            Self::GeneratePrivateKey(args) => args.run(),
            Self::CalculatePublicKey(args) => args.run(),
            Self::ValidatorsInfo(args) => args.run(),
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
        let signing_key = PrivateKey::random(&mut rand::thread_rng());
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
    /// Whether the validator is a player in the current epoch.
    is_player: bool,
    // Whether the validator is a dealer in th ecurrent epoch.
    is_dealer: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorsInfo {
    /// Chain to query (presto, testnet, moderato, or path to chainspec file)
    #[arg(long, short, default_value = "mainnet", value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC URL to query. Defaults to <https://rpc.presto.tempo.xyz>
    #[arg(long, default_value = "https://rpc.presto.tempo.xyz")]
    rpc_url: String,
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

        let contract_validators: HashMap<[u8; 32], IValidatorConfig::Validator> =
            decoded_validators
                .into_iter()
                .map(|v| (v.publicKey.0, v))
                .collect();

        let players = dkg_outcome.players().clone();

        let mut validator_entries = Vec::new();
        for player in players.into_iter() {
            let pubkey_bytes: [u8; 32] = player.as_ref().try_into().wrap_err("invalid pubkey")?;

            let (onchain_address, active, inbound, outbound) =
                if let Some(v) = contract_validators.get(&pubkey_bytes) {
                    (
                        v.validatorAddress,
                        v.active,
                        v.inboundAddress.clone(),
                        v.outboundAddress.clone(),
                    )
                } else {
                    (Address::ZERO, false, String::new(), String::new())
                };

            validator_entries.push(ValidatorEntry {
                onchain_address,
                public_key: alloy_primitives::hex::encode(pubkey_bytes),
                inbound_address: inbound,
                outbound_address: outbound,
                active,
                is_dealer: dkg_outcome.players().position(&player).is_some(),
                is_player: dkg_outcome.next_players().position(&player).is_some(),
            });
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
