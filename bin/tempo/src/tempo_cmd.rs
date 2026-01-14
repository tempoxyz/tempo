use std::path::PathBuf;

use clap::{Parser, Subcommand, error::ErrorKind};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use eyre::Context;
use tempo_commonware_node_config::SigningKey;

#[derive(Debug, Parser)]
#[command(name = "tempo")]
struct TempoCli {
    #[command(subcommand)]
    command: TempoCommand,
}

#[derive(Debug, Subcommand)]
enum TempoCommand {
    /// Consensus-related commands.
    Consensus(ConsensusCommand),
}

#[derive(Debug, clap::Args)]
struct ConsensusCommand {
    #[command(subcommand)]
    command: ConsensusSubcommand,
}

#[derive(Debug, Subcommand)]
enum ConsensusSubcommand {
    /// Generates an ed25519 signing key pair to be used in consensus.
    GeneratePrivateKey(GeneratePrivateKey),
    /// Calculates the public key from an ed25519 signing key.
    CalculatePublicKey(CalculatePublicKey),
    /// Deletes a consensus signing share file.
    DeleteSigningShare(DeleteSigningShare),
}

#[derive(Debug, clap::Args)]
struct GeneratePrivateKey {
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
struct CalculatePublicKey {
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
    /// Path to the signing share file to delete.
    #[arg(long, short, value_name = "FILE")]
    path: PathBuf,
}

impl DeleteSigningShare {
    fn run(self) -> eyre::Result<()> {
        let Self { path } = self;

        if !path.exists() {
            println!("Signing share file does not exist at: {}", path.display());
            return Ok(());
        }

        std::fs::remove_file(&path).wrap_err_with(|| {
            format!("failed deleting signing share at `{}`", path.display())
        })?;

        println!("Successfully deleted signing share at: {}", path.display());
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
