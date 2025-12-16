use std::path::PathBuf;

use clap::{Parser, Subcommand, error::ErrorKind};
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
}

impl GenerateSigningKey {
    fn run(self) -> eyre::Result<()> {
        let Self { output } = self;
        let signing_key = PrivateKey::from_rng(&mut rand::thread_rng());
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

pub(crate) fn try_run_tempo_subcommand() -> Option<eyre::Result<()>> {
    match TempoCli::try_parse() {
        Ok(cli) => match cli.command {
            TempoCommand::Consensus(cmd) => match cmd.command {
                ConsensusSubcommand::GenerateSigningKey(args) => Some(args.run()),
            },
        },
        Err(e) => match e.kind() {
            ErrorKind::InvalidSubcommand => None,
            _ => {
                e.print().expect("failed to print error");
                Some(Ok(()))
            }
        },
    }
}
