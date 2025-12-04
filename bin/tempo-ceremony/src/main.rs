//! Tempo DKG Ceremony Tool.
//!
//! A standalone binary for running the initial DKG ceremony with external
//! validators before mainnet/testnet genesis.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tempo_ceremony::{ceremony, keygen, network};

#[derive(Parser)]
#[command(name = "tempo-ceremony")]
#[command(about = "Tempo DKG Ceremony Tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate ED25519 keypair for ceremony participation.
    Keygen {
        /// Output directory for key files.
        #[arg(long, default_value = "./keygen-output")]
        output_dir: PathBuf,

        /// Overwrite existing key files.
        #[arg(long)]
        force: bool,
    },

    /// Test connectivity with all participants (dry run).
    TestConnectivity {
        /// Path to ceremony configuration file.
        #[arg(long)]
        config: PathBuf,

        /// Path to signing key file (from keygen step).
        #[arg(long)]
        signing_key: PathBuf,

        /// Log level (trace, debug, info, warn, error).
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Run the DKG ceremony.
    Ceremony {
        /// Path to ceremony configuration file.
        #[arg(long)]
        config: PathBuf,

        /// Path to signing key file (from keygen step).
        #[arg(long)]
        signing_key: PathBuf,

        /// Output directory for ceremony results.
        #[arg(long, default_value = "./ceremony-output")]
        output_dir: PathBuf,

        /// Log level (trace, debug, info, warn, error).
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output_dir, force } => {
            keygen::run(keygen::KeygenArgs { output_dir, force })
        }
        Commands::TestConnectivity {
            config,
            signing_key,
            log_level,
        } => ceremony::run_connectivity_test(network::ConnectivityArgs {
            config,
            signing_key,
            log_level,
        }),
        Commands::Ceremony {
            config,
            signing_key,
            output_dir,
            log_level,
        } => ceremony::run(ceremony::CeremonyArgs {
            config,
            signing_key,
            output_dir,
            log_level,
        }),
    }
}
