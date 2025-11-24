use std::path::PathBuf;

use alloy_primitives::Address;
use eyre::{Context, ensure};
use rand::SeedableRng as _;
use reth_network_peers::pk2id;
use secp256k1::SECP256K1;
use serde::Serialize;

use crate::{generate_consensus_config::ConsensusArgs, genesis_args::GenesisArgs};

/// Generates a config file to run a bunch of validators locally.
///
/// This includes generating a genesis.
#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateDevnet {
    /// The target directory that will be populated with the
    ///
    /// If this directory exists but is not empty the operation will fail unless `--force`
    /// is specified. In this case the target directory will be first cleaned.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Whether to overwrite `output`.
    #[arg(long)]
    force: bool,

    #[arg(long)]
    image_tag: String,

    /// The URL at which genesis will be found.
    #[arg(long)]
    genesis_url: String,

    #[clap(flatten)]
    genesis_args: Option<GenesisArgs>,

    #[clap(flatten)]
    consensus_args: ConsensusArgs,
}

impl GenerateDevnet {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            output,
            force,
            image_tag,
            genesis_url,
            genesis_args,
            consensus_args,
        } = self;

        let genesis = if let Some(genesis_args) = genesis_args {
            Some(
                genesis_args
                    .generate_genesis()
                    .await
                    .wrap_err("failed to generate genesis")?,
            )
        } else {
            None
        };

        std::fs::create_dir_all(&output).wrap_err_with(|| {
            format!("failed creating target directory at `{}`", output.display())
        })?;

        if force {
            eprintln!(
                "--force was specified: deleting all files in target directory `{}`",
                output.display()
            );
            // XXX: this first removes the directory and then recreates it. Small workaround
            // so that one doesn't have to iterate through the entire thing recursively.
            std::fs::remove_dir_all(&output)
                .and_then(|_| std::fs::create_dir(&output))
                .wrap_err_with(|| {
                    format!("failed clearing target directory at `{}`", output.display())
                })?;
        } else {
            let target_is_empty = std::fs::read_dir(&output)
                .wrap_err_with(|| {
                    format!(
                        "failed reading target directory `{}` to determine if it is empty",
                        output.display()
                    )
                })?
                .next()
                .is_none();
            ensure!(
                target_is_empty,
                "target directory `{}` is not empty; delete all its contents or rerun command with --force",
                output.display(),
            );
        }

        let seed = consensus_args.seed;
        let consensus_config = consensus_args
            .generate_consensus_config()
            .wrap_err("failed generating consensus config")?;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
        let mut execution_peers = vec![];

        let devmode = consensus_config.validators.len() == 1;

        let mut all_configs = vec![];
        for validator in consensus_config.validators {
            let (execution_p2p_signing_key, execution_p2p_identity) = {
                let (sk, pk) = SECP256K1.generate_keypair(&mut rng);
                (sk, pk2id(&pk))
            };

            let consensus_p2p_port = validator.addr.port();
            let execution_p2p_port = consensus_p2p_port + 1;
            let consensus_metrics_port = consensus_p2p_port + 2;

            execution_peers.push(format!(
                "enode://{execution_p2p_identity:x}@{}",
                validator.addr.clone().with_port(execution_p2p_port),
            ));

            all_configs.push((
                validator.clone(),
                ConfigOutput {
                    execution_genesis_url: genesis_url.clone(),

                    devmode,
                    node_image_tag: image_tag.clone(),

                    consensus_on_disk_signing_key: validator.signing_key.to_string(),
                    consensus_on_disk_signing_share: validator.signing_share.to_string(),

                    // FIXME(janis): this should not be zero
                    consensus_fee_recipient: Address::ZERO,

                    consensus_p2p_port,
                    consensus_metrics_port,
                    execution_p2p_port,

                    execution_p2p_disc_key: execution_p2p_signing_key.display_secret().to_string(),

                    // set in next loop, before writing.
                    execution_peers: vec![],
                },
            ));

            println!("created a config for validator `{}`", validator.addr);
        }

        for (validator, mut config) in all_configs {
            config.execution_peers = execution_peers.clone();
            let config_json = serde_json::to_string_pretty(&config)
                .wrap_err("failed to convert config to json")?;
            // TODO: use Path::with_added_extension once we are on 1.91
            let dst = output.join(format!("{}.json", validator.addr));
            std::fs::write(&dst, config_json).wrap_err_with(|| {
                format!("failed to write deployment config to `{}`", dst.display())
            })?;
            println!("wrote config to `{}`", dst.display());
        }
        eprintln!("config files written");

        if let Some(genesis) = genesis {
            let genesis_ser = serde_json::to_string_pretty(&genesis)
                .wrap_err("failed serializing genesis as json")?;
            let dst = output.join("genesis.json");
            std::fs::write(&dst, &genesis_ser)
                .wrap_err_with(|| format!("failed writing genesis to `{}`", dst.display()))?;
            println!("wrote genesis to `{}`", dst.display());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigOutput {
    devmode: bool,
    consensus_on_disk_signing_key: String,
    consensus_on_disk_signing_share: String,
    consensus_p2p_port: u16,
    consensus_fee_recipient: Address,
    consensus_metrics_port: u16,
    node_image_tag: String,
    execution_genesis_url: String,
    execution_p2p_port: u16,
    execution_peers: Vec<String>,
    execution_p2p_disc_key: String,
}
