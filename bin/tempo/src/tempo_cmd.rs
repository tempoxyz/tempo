use std::{path::PathBuf, sync::Arc};

use clap::Subcommand;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use eyre::Context;
use reth_cli_runner::CliRunner;
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    evm::revm::primitives::{Address, U256},
    node::EthereumNode,
    provider::{
        ProviderFactory,
        db::{ClientVersion, DatabaseEnv, mdbx::DatabaseArguments, open_db_read_only},
        providers::{RocksDBProvider, StaticFileProvider},
    },
};
use reth_ethereum_cli::ExtendedCommand;
use reth_node_builder::NodeTypesWithDBAdapter;
use tempo_commonware_node_config::SigningKey;

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
    /// Debugs the storage layer.
    StorageDebug(StorageDebug),
}

impl ConsensusSubcommand {
    fn run(self) -> eyre::Result<()> {
        match self {
            Self::GeneratePrivateKey(args) => args.run(),
            Self::CalculatePublicKey(args) => args.run(),
            Self::StorageDebug(args) => args.run(),
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct StorageDebug {
    /// Path to the database directory.
    #[clap(long, default_value = "data")]
    pub db_path: PathBuf,

    #[clap(long)]
    pub address: Address,

    #[clap(long)]
    pub block_number: u64,
}

impl StorageDebug {
    fn run(self) -> eyre::Result<()> {
        // Open database read-only
        let db = Arc::new(open_db_read_only(
            self.db_path.join("db").as_path(),
            DatabaseArguments::new(ClientVersion::default()),
        )?);

        let spec = Arc::new(ChainSpecBuilder::mainnet().build());

        let factory =
            ProviderFactory::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(
                db,
                spec,
                StaticFileProvider::read_only(self.db_path.join("static_files"), true)?,
                RocksDBProvider::builder(self.db_path.join("rocksdb")).build()?,
            )?;

        // Get historical state provider at the specified block
        let state = factory.history_by_block_number(self.block_number)?;

        // Query slots 0, 1, and the keccak slot
        let slot_0 = state.storage(self.address, U256::ZERO.into())?;
        let slot_1 = state.storage(self.address, U256::from(1).into())?;
        let slot_keccak = state.storage(
            self.address,
            U256::from_str_radix(
                "b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
                16,
            )
            .unwrap()
            .into(),
        )?;

        println!("Address: {:?}", self.address);
        println!("Block:   {:?}", self.block_number);
        println!("Slot 0:  {:?}", slot_0.unwrap_or_default());
        println!("Slot 1:  {:?}", slot_1.unwrap_or_default());
        println!("Slot 0xb10e...0cf6: {:?}", slot_keccak.unwrap_or_default());

        Ok(())
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
