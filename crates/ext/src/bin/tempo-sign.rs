//! Generates signed release manifests for `tempo` extensions.

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use tempo_ext::sign::{self, ManifestOptions, SignError};

/// Generate signed release manifests for Tempo CLI extensions.
#[derive(Parser)]
#[command(name = "tempo-sign")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new minisign keypair
    GenerateKey {
        /// Path to write the secret key file
        path: PathBuf,
    },
    /// Print the public key from a secret key file
    PrintPublicKey {
        /// Path to the secret key file
        path: PathBuf,
    },
    /// Sign release artifacts and generate a manifest
    Sign {
        /// Path to the minisign secret key file
        #[arg(long)]
        key_file: PathBuf,
        /// Directory containing release artifacts to sign
        #[arg(long)]
        artifacts_dir: PathBuf,
        /// Release version (e.g., "0.1.0")
        #[arg(long)]
        version: String,
        /// Base URL for download links
        #[arg(long, default_value = "https://cli.tempo.xyz/extensions/tempo-wallet")]
        base_url: String,
        /// Extension description
        #[arg(long)]
        description: Option<String>,
        /// URL for the SKILL.md file
        #[arg(long, requires = "skill_file")]
        skill: Option<String>,
        /// SHA256 hash of the SKILL.md file
        #[arg(long)]
        skill_sha256: Option<String>,
        /// Local path to the SKILL.md file for signing
        #[arg(long, requires = "skill")]
        skill_file: Option<PathBuf>,
        /// Output path for the manifest JSON
        #[arg(long, default_value = "manifest.json")]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), SignError> {
    match command {
        Command::GenerateKey { path } => {
            let pk = sign::generate_key(&path)?;
            println!("Generated minisign keypair");
            println!("  Secret key box: {}", path.display());
            println!("  Public key (base64): {pk}");
            println!();
            println!("Bake this public key into the verifying application's PUBLIC_KEY constant.");
            println!(
                "Keep {} secret — it signs release binaries.",
                path.display()
            );
        }
        Command::PrintPublicKey { path } => {
            println!("{}", sign::public_key(&sign::load_secret_key(&path)?)?);
        }
        Command::Sign {
            key_file,
            artifacts_dir,
            version,
            base_url,
            description,
            skill,
            skill_sha256,
            skill_file,
            output,
        } => {
            let sk = sign::load_secret_key(&key_file)?;
            println!("Signing release {version}");
            println!("  Public key: {}", sign::public_key(&sk)?);
            println!("  Artifacts: {}", artifacts_dir.display());

            let manifest = sign::build_manifest(
                &ManifestOptions {
                    artifacts_dir,
                    version,
                    base_url,
                    description,
                    skill,
                    skill_sha256,
                    skill_file,
                },
                &sk,
            )?;

            let binaries = manifest["binaries"].as_object().map_or(0, |b| b.len());
            for name in manifest["binaries"]
                .as_object()
                .into_iter()
                .flat_map(|b| b.keys())
            {
                println!("  signed {name}");
            }
            std::fs::write(
                &output,
                format!("{}\n", serde_json::to_string_pretty(&manifest)?),
            )
            .map_err(|source| SignError::Io {
                operation: "write manifest",
                path: output.display().to_string(),
                source,
            })?;
            println!("Wrote {} ({binaries} binaries)", output.display());
        }
    }
    Ok(())
}
