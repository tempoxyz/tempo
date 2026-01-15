use std::path::PathBuf;

use clap::Subcommand;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use eyre::Context;
use reth_cli_runner::CliRunner;
use reth_ethereum_cli::ExtendedCommand;
use tempo_commonware_node_config::SigningKey;
use commonware_runtime::Runner; // Import Runner trait

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
    /// Deletes a consensus signing share file.
    DeleteSigningShare(DeleteSigningShare),
}

impl ConsensusSubcommand {
    fn run(self) -> eyre::Result<()> {
        match self {
            Self::GeneratePrivateKey(args) => args.run(),
            Self::CalculatePublicKey(args) => args.run(),
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

#[derive(Debug, clap::Args)]
struct DeleteSigningShare {
    //// Path to the consensus data directory (e.g. .../data/consensus).
    #[arg(long, short, value_name = "DIR")]
    data_dir: PathBuf,

    /// Partition prefix used by the node.
    #[arg(long, default_value = "tempo")]
    prefix: String,
}

impl DeleteSigningShare {
    fn run(self) -> eyre::Result<()> {
        let Self { data_dir, prefix } = self;

        // Configure runtime to open the database
        let config = commonware_runtime::tokio::Config::default()
            .with_storage_directory(data_dir);

        // Initialize Runner (simulation environment)
        let runner = commonware_runtime::tokio::Runner::new(config);

        println!("Opening database to prune signing share...");

        // Execute share deletion logic within the async environment
        runner.start(async move |context| -> eyre::Result<()> {
            // Actual partition name in engine code is "{prefix}_dkg_manager"
            let dkg_prefix = format!("{}_dkg_manager", prefix);

            match tempo_commonware_node::dkg::manager::prune_share(context, dkg_prefix).await {
                Ok(true) => println!("✅ Successfully deleted signing share from node state."),
                Ok(false) => println!("⚠️ No signing share found to delete (already deleted?)."),
                Err(e) => eprintln!("❌ Failed to delete signing share: {:?}", e),
            }
            Ok(())
        }).wrap_err("failed to execute database operation")?;

        Ok(())
    }
}

pub(crate) fn try_run_tempo_subcommand() -> Option<eyre::Result<()>> {
    match TempoCli::try_parse() {
        Ok(cli) => match cli.command {
            TempoCommand::Consensus(cmd) => match cmd.command {
                ConsensusSubcommand::GeneratePrivateKey(args) => Some(args.run()),
                ConsensusSubcommand::CalculatePublicKey(args) => Some(args.run()),
                ConsensusSubcommand::DeleteSigningShare(args) => Some(args.run()),
            },
        },
        Err(e) => match e.kind() {
            ErrorKind::InvalidSubcommand => None,
            _ => {
                e.print().expect("should be able to write to STDOUT");
                Some(Ok(()))
            }
        },
    }
}
