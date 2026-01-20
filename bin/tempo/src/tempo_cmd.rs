use std::{collections::HashMap, path::PathBuf};

use alloy_provider::Provider;
use alloy_rpc_types_eth::BlockNumberOrTag;
use clap::Subcommand;
use commonware_codec::ReadExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use commonware_utils::NZU64;
use eyre::{Context, OptionExt as _, eyre};
use reth_cli_runner::CliRunner;
use reth_ethereum_cli::ExtendedCommand;
use serde::Serialize;
use tempo_alloy::TempoNetwork;
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
}

impl GeneratePrivateKey {
    fn run(self) -> eyre::Result<()> {
        let Self { output } = self;
        let signing_key = PrivateKey::random(&mut rand::thread_rng());
        let public_key = signing_key.public_key();
        let signing_key = SigningKey::from(signing_key);
        signing_key
            .write_to_file(&output)
            .wrap_err_with(|| format!("failed writing private key to `{}`", output.display()))?;
        println!(
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
    /// The epoch of the DKG outcome
    epoch: u64,
    /// Block height of the epoch boundary where the DKG outcome was read
    boundary_height: u64,
    /// Block height at which the smart contract state was read
    contract_read_height: u64,
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
    /// ed25519 public key (hex)
    public_key: String,
    /// Inbound IP address for p2p connections
    inbound_address: String,
    /// Outbound IP address
    outbound_address: String,
    /// Whether the validator is active in the current contract state
    active: bool,
    /// Whether this validator was a player (received shares) in the DKG ceremony
    was_player: bool,
    /// Whether this validator was a dealer (generated dealings) in the DKG ceremony
    was_dealer: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorsInfo {
    /// RPC URL to query (e.g., https://rpc.presto.tempo.xyz)
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Epoch length (blocks per epoch). If not provided, will be read from genesis.
    #[arg(long)]
    epoch_length: Option<u64>,
}

impl ValidatorsInfo {
    fn run(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.run_async())
    }

    async fn run_async(self) -> eyre::Result<()> {
        use alloy_consensus::BlockHeader;
        use alloy_provider::ProviderBuilder;

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let latest_block_number = provider
            .get_block_number()
            .await
            .wrap_err("failed to get latest block number")?;

        let genesis_block = provider
            .get_block_by_number(BlockNumberOrTag::Number(0))
            .await
            .wrap_err("failed to get genesis block")?
            .ok_or_eyre("genesis block not found")?;

        let epoch_length = if let Some(len) = self.epoch_length {
            len
        } else {
            let genesis_extra: serde_json::Value = serde_json::from_str(
                &serde_json::to_string(&genesis_block.header.inner.inner)
                    .wrap_err("failed to serialize genesis header")?,
            )
            .wrap_err("failed to parse genesis header")?;

            genesis_extra
                .get("epochLength")
                .and_then(|v| v.as_u64())
                .ok_or_eyre("epoch_length not found in genesis, please provide --epoch-length")?
        };

        let epoch_strategy = FixedEpocher::new(NZU64!(epoch_length));
        let current_height = Height::new(latest_block_number);
        let current_epoch_info = epoch_strategy
            .containing(current_height)
            .ok_or_else(|| eyre!("failed to determine epoch for height {latest_block_number}"))?;

        let previous_epoch = if current_epoch_info.epoch().get() == 0 {
            Epoch::new(0)
        } else {
            Epoch::new(current_epoch_info.epoch().get() - 1)
        };

        let prev_epoch_info = epoch_strategy.epoch(previous_epoch).ok_or_else(|| {
            eyre!(
                "failed to get epoch info for epoch {}",
                previous_epoch.get()
            )
        })?;
        let boundary_height = prev_epoch_info.last();

        let boundary_block = provider
            .get_block_by_number(BlockNumberOrTag::Number(boundary_height.get()))
            .await
            .wrap_err_with(|| format!("failed to get block at height {}", boundary_height.get()))?
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

        let validators_call = IValidatorConfig::getValidatorsCall {};
        let validators_calldata = alloy_sol_types::SolCall::abi_encode(&validators_call);

        let next_dkg_call = IValidatorConfig::getNextFullDkgCeremonyCall {};
        let next_dkg_calldata = alloy_sol_types::SolCall::abi_encode(&next_dkg_call);

        let validators_result = provider
            .call(
                alloy_rpc_types_eth::TransactionRequest::default()
                    .to(VALIDATOR_CONFIG_ADDRESS)
                    .input(validators_calldata.into()),
            )
            .await
            .wrap_err("failed to call getValidators")?;

        let next_dkg_result = provider
            .call(
                alloy_rpc_types_eth::TransactionRequest::default()
                    .to(VALIDATOR_CONFIG_ADDRESS)
                    .input(next_dkg_calldata.into()),
            )
            .await
            .wrap_err("failed to call getNextFullDkgCeremony")?;

        let decoded_validators: IValidatorConfig::getValidatorsReturn =
            alloy_sol_types::SolCall::abi_decode_returns(&validators_result, true)
                .wrap_err("failed to decode getValidators response")?;

        let decoded_next_dkg: IValidatorConfig::getNextFullDkgCeremonyReturn =
            alloy_sol_types::SolCall::abi_decode_returns(&next_dkg_result, true)
                .wrap_err("failed to decode getNextFullDkgCeremony response")?;

        let contract_validators: HashMap<[u8; 32], IValidatorConfig::Validator> =
            decoded_validators
                .validators
                .into_iter()
                .map(|v| (v.publicKey.0, v))
                .collect();

        let players = dkg_outcome.players();
        let dealers = dkg_outcome.dealers();

        let mut validator_entries = Vec::new();
        for player in players.iter() {
            let pubkey_bytes: [u8; 32] = player.as_ref().try_into().wrap_err("invalid pubkey")?;

            let (active, inbound, outbound) =
                if let Some(v) = contract_validators.get(&pubkey_bytes) {
                    (
                        v.active,
                        v.inboundAddress.clone(),
                        v.outboundAddress.clone(),
                    )
                } else {
                    (false, String::new(), String::new())
                };

            validator_entries.push(ValidatorEntry {
                public_key: alloy_primitives::hex::encode(pubkey_bytes),
                inbound_address: inbound,
                outbound_address: outbound,
                active,
                was_player: true,
                was_dealer: dealers.contains(player),
            });
        }

        let output = ValidatorInfoOutput {
            epoch: dkg_outcome.epoch.get(),
            boundary_height: boundary_height.get(),
            contract_read_height: latest_block_number,
            is_next_full_dkg: dkg_outcome.is_next_full_dkg,
            next_full_dkg_epoch: decoded_next_dkg._0,
            validators: validator_entries,
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}
