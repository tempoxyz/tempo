use std::{
    fs::OpenOptions,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use commonware_codec::{DecodeExt as _, Encode as _, ReadExt as _};
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
use tempo_commonware_node_config::{
    SigningKey,
    validator::{self as validator, ValidatorConfig},
};
use tempo_contracts::precompiles::{
    IValidatorConfig, IValidatorConfigV2, VALIDATOR_CONFIG_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS,
};
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
    /// Add a new validator to the validator config contract.
    AddValidator(AddValidator),
    /// Rotate a validator to a new identity.
    RotateValidator(RotateValidator),
    /// Create an ed25519 signature for `addValidator`.
    CreateAddValidatorSignature(CreateSignatureArgs),
    /// Create an ed25519 signature for `rotateValidator`.
    CreateRotateValidatorSignature(CreateSignatureArgs),
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
            Self::AddValidator(args) => args.run(),
            Self::RotateValidator(args) => args.run(),
            Self::CreateAddValidatorSignature(args) => args.run(validator::ADD_VALIDATOR_NAMESPACE),
            Self::CreateRotateValidatorSignature(args) => {
                args.run(validator::ROTATE_VALIDATOR_NAMESPACE)
            }
            Self::GeneratePrivateKey(args) => args.run(),
            Self::CalculatePublicKey(args) => args.run(),
            Self::ValidatorsInfo(args) => args.run(),
        }
    }
}

/// Shared validator identity arguments used across add/rotate/sign commands.
#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorIdentityArgs {
    /// The validator address.
    #[arg(long, value_name = "ETHEREUM_ADDRESS")]
    validator_address: Address,

    /// The identity key of the validator (0x-prefixed hex).
    #[arg(long, value_name = "IDENTITY_KEY")]
    public_key: B256,

    /// The inbound address for the validator.
    #[arg(long, value_name = "IP:PORT")]
    ingress: SocketAddr,

    /// The outbound address for the validator.
    #[arg(long, value_name = "IP")]
    egress: IpAddr,
}

impl ValidatorIdentityArgs {
    fn to_config(&self, chain_id: u64) -> ValidatorConfig {
        ValidatorConfig {
            chain_id,
            validator_address: self.validator_address,
            public_key: self.public_key,
            ingress: self.ingress,
            egress: self.egress,
        }
    }
}

/// Shared arguments for commands that update the validator config contract.
#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorTransactionArgs {
    /// The ed25519 signature proving validator key ownership and validity over
    /// the validator identity.
    #[arg(long, value_name = "SIGNATURE")]
    signature: Bytes,

    /// Path to the file holding the Ethereum private key.
    #[arg(long, value_name = "FILE")]
    private_key: PathBuf,

    /// The RPC URL to submit the transaction to.
    #[arg(long, value_name = "RPC_URL")]
    rpc_url: String,
}

#[derive(Debug, clap::Args)]
pub(crate) struct AddValidator {
    #[command(flatten)]
    identity: ValidatorIdentityArgs,

    #[command(flatten)]
    submit: ValidatorTransactionArgs,
}

impl AddValidator {
    fn run(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("failed constructing async runtime")?
            .block_on(self.run_async())
    }

    async fn run_async(self) -> eyre::Result<()> {
        let private_key_bytes =
            std::fs::read(&self.submit.private_key).wrap_err("failed reading private key")?;
        let private_key =
            B256::try_from(private_key_bytes.as_slice()).wrap_err("invalid private key")?;

        let signer = PrivateKeySigner::from_bytes(&private_key)?;
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .fetch_chain_id()
            .with_gas_estimation()
            .wallet(signer)
            .connect(&self.submit.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let chain_id = provider
            .get_chain_id()
            .await
            .wrap_err("failed to get chain id")?;

        self.identity
            .to_config(chain_id)
            .check_add_validator_signature(self.submit.signature.as_ref())
            .wrap_err("add-validator signature check failed")?;

        let calldata = IValidatorConfigV2::addValidatorCall {
            validatorAddress: self.identity.validator_address,
            publicKey: self.identity.public_key,
            ingress: self.identity.ingress.to_string(),
            egress: self.identity.egress.to_string(),
            signature: self.submit.signature,
        };

        let tx = TransactionRequest::default()
            .to(VALIDATOR_CONFIG_V2_ADDRESS)
            .input(calldata.abi_encode().into());

        let pending = provider
            .send_transaction(tx.into())
            .await
            .wrap_err("failed to send transaction")?;

        let tx_hash = pending.tx_hash();
        println!("transaction submitted: {tx_hash}");

        Ok(())
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct RotateValidator {
    #[command(flatten)]
    identity: ValidatorIdentityArgs,

    #[command(flatten)]
    submit: ValidatorTransactionArgs,
}

impl RotateValidator {
    fn run(self) -> eyre::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("failed constructing async runtime")?
            .block_on(self.run_async())
    }

    async fn run_async(self) -> eyre::Result<()> {
        let private_key_bytes =
            std::fs::read(&self.submit.private_key).wrap_err("failed reading private key")?;
        let private_key =
            B256::try_from(private_key_bytes.as_slice()).wrap_err("invalid private key")?;

        let signer = PrivateKeySigner::from_bytes(&private_key)?;
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .fetch_chain_id()
            .with_gas_estimation()
            .wallet(EthereumWallet::from(signer))
            .connect(&self.submit.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let chain_id = provider
            .get_chain_id()
            .await
            .wrap_err("failed to get chain id")?;

        self.identity
            .to_config(chain_id)
            .check_rotate_validator_signature(self.submit.signature.as_ref())
            .wrap_err("rotate-validator signature check failed")?;

        let calldata = IValidatorConfigV2::rotateValidatorCall {
            validatorAddress: self.identity.validator_address,
            publicKey: self.identity.public_key,
            ingress: self.identity.ingress.to_string(),
            egress: self.identity.egress.to_string(),
            signature: self.submit.signature,
        };

        let tx = TransactionRequest::default()
            .to(VALIDATOR_CONFIG_V2_ADDRESS)
            .input(calldata.abi_encode().into());

        let pending = provider
            .send_transaction(tx.into())
            .await
            .wrap_err("failed to send transaction")?;

        let tx_hash = pending.tx_hash();
        println!("transaction submitted: {tx_hash}");

        Ok(())
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct CreateSignatureArgs {
    #[command(flatten)]
    identity: ValidatorIdentityArgs,

    /// The chain ID of the network.
    #[arg(long, value_name = "CHAIN_ID")]
    chain_id: u64,

    /// Path to the ed25519 signing key file.
    #[arg(long, value_name = "FILE")]
    signing_key: PathBuf,
}

impl CreateSignatureArgs {
    fn run(self, namespace: &[u8]) -> eyre::Result<()> {
        let signing_key =
            SigningKey::read_from_file(&self.signing_key).wrap_err("failed reading signing key")?;

        let network = match self.chain_id {
            4217 => "presto (mainnet)",
            42429 => "andantino (testnet)",
            42431 => "moderato",
            _ => "unknown",
        };

        eprintln!("Detected Network: {network}");

        let config = self.identity.to_config(self.chain_id);
        let message = config.message_hash();

        let private_key = signing_key.into_inner();
        let signature = private_key.sign(namespace, message.as_slice());
        let encoded = signature.encode();
        println!("{}", alloy_primitives::hex::encode_prefixed(encoded));
        Ok(())
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
