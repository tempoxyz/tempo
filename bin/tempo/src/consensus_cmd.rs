//! Custom `consensus` subcommand for the tempo CLI.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use commonware_cryptography::{PrivateKeyExt as _, Signer, ed25519::PrivateKey};
use eyre::Context;
use rand::SeedableRng as _;
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
    GenerateSigningKey(GenerateSigningKey),
}

#[derive(Debug, clap::Args)]
struct GenerateSigningKey {
    /// Destination of the generated signing key.
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,
    /// AVOID IN PRODUCTION.
    /// Optional seed for the random generator used when generating the key.
    /// Use this only in environments that require reproducible keys.
    #[arg(long, value_name = "NUMBER")]
    seed: Option<u64>,
}

impl GenerateSigningKey {
    fn run(self) -> eyre::Result<()> {
        let Self { output, seed } = self;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
        let signing_key = PrivateKey::from_rng(&mut rng);
        let validating_key = signing_key.public_key();
        let signing_key = SigningKey::from(signing_key);
        signing_key
            .write_to_file(&output)
            .wrap_err_with(|| format!("failed writing signing key to `{}`", output.display()))?;
        println!(
            "wrote signing key to: {}\nvalidating/public key: {validating_key}",
            output.display()
        );
        Ok(())
    }
}

pub(crate) fn try_run_consensus_command() -> Option<eyre::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "consensus" {
        Some(run_consensus_command())
    } else {
        None
    }
}

fn run_consensus_command() -> eyre::Result<()> {
    let cli = TempoCli::parse();
    match cli.command {
        TempoCommand::Consensus(cmd) => match cmd.command {
            ConsensusSubcommand::GenerateSigningKey(args) => args.run(),
        },
    }
}
