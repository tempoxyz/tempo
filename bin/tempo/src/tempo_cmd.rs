use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use eyre::Context;
use tempo_commonware_node_config::SigningKey;

#[derive(Debug, Parser)]
#[command(name = "tempo", version)]
struct TempoCli {
    #[command(subcommand)]
    command: Option<TempoCommand>,
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

/// Returns true if the first CLI argument is a tempo-specific subcommand.
fn is_tempo_subcommand() -> bool {
    let Some(first_arg) = std::env::args().nth(1) else {
        return false;
    };

    TempoCli::command()
        .get_subcommands()
        .any(|cmd| cmd.get_name() == first_arg)
}

pub(crate) fn try_run_tempo_subcommand() -> Option<eyre::Result<()>> {
    // Only attempt to parse if the first argument is a tempo-specific subcommand.
    // This lets reth CLI handle everything else (including top-level -h/-V).
    if !is_tempo_subcommand() {
        return None;
    }

    match TempoCli::try_parse() {
        Ok(cli) => match cli.command {
            Some(TempoCommand::Consensus(cmd)) => match cmd.command {
                ConsensusSubcommand::GeneratePrivateKey(args) => Some(args.run()),
                ConsensusSubcommand::CalculatePublicKey(args) => Some(args.run()),
            },
            None => None,
        },
        Err(e) => {
            // Handle help/version for tempo subcommands
            e.print().expect("should be able to write to stdout");
            Some(Ok(()))
        }
    }
}
