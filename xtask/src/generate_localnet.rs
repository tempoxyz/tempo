use std::{net::SocketAddr, path::PathBuf};

use alloy_primitives::Address;
use eyre::{Context, ensure};
use rand::SeedableRng as _;
use reth_network_peers::pk2id;
use secp256k1::SECP256K1;
use serde::Serialize;

use crate::genesis_args::GenesisArgs;

/// Generates a config file to run a bunch of validators locally.
///
/// This includes generating a genesis.
#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateLocalnet {
    /// The target directory that will be populated with the
    ///
    /// If this directory exists but is not empty the operation will fail unless `--force`
    /// is specified. In this case the target directory will be first cleaned.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Whether to overwrite `output`.
    #[arg(long)]
    force: bool,

    #[clap(flatten)]
    genesis_args: GenesisArgs,
}

impl GenerateLocalnet {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            output,
            force,
            genesis_args,
        } = self;

        // Copy the seed here before genesis_args are consumed.
        let seed = genesis_args.seed;

        let (genesis, consensus_config) = genesis_args
            .generate_genesis()
            .await
            .wrap_err("failed to generate genesis")?;

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

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
        let mut trusted_peers = vec![];

        let mut all_configs = vec![];
        for validator in &consensus_config.validators {
            let (execution_p2p_signing_key, execution_p2p_identity) = {
                let (sk, pk) = SECP256K1.generate_keypair(&mut rng);
                (sk, pk2id(&pk))
            };

            let consensus_p2p_port = validator.addr.port();
            let execution_p2p_port = consensus_p2p_port + 1;

            trusted_peers.push(format!(
                "enode://{execution_p2p_identity:x}@{}",
                SocketAddr::new(validator.addr.ip(), execution_p2p_port),
            ));

            all_configs.push((
                validator.clone(),
                ConfigOutput {
                    consensus_on_disk_signing_key: validator.signing_key.to_string(),
                    consensus_on_disk_signing_share: validator.signing_share.to_string(),

                    consensus_p2p_port,
                    execution_p2p_port,

                    execution_p2p_disc_key: execution_p2p_signing_key.display_secret().to_string(),
                },
            ));
        }

        let genesis_ser = serde_json::to_string_pretty(&genesis)
            .wrap_err("failed serializing genesis as json")?;
        let genesis_dst = output.join("genesis.json");
        std::fs::write(&genesis_dst, &genesis_ser)
            .wrap_err_with(|| format!("failed writing genesis to `{}`", genesis_dst.display()))?;

        for (validator, config) in all_configs.into_iter() {
            let target_dir = validator.dst_dir(&output);
            std::fs::create_dir(&target_dir).wrap_err_with(|| {
                format!(
                    "failed creating target directory to store validator specifici keys at `{}`",
                    &target_dir.display()
                )
            })?;

            let signing_key_dst = validator.dst_signing_key(&output);
            std::fs::write(&signing_key_dst, config.consensus_on_disk_signing_key).wrap_err_with(
                || {
                    format!(
                        "failed writing signing key to `{}`",
                        signing_key_dst.display()
                    )
                },
            )?;
            let signing_share_dst = validator.dst_signing_share(&output);
            std::fs::write(&signing_share_dst, config.consensus_on_disk_signing_share)
                .wrap_err_with(|| {
                    format!(
                        "failed writing signing share to `{}`",
                        signing_share_dst.display()
                    )
                })?;
            let enode_key_dst = validator.dst_dir(&output).join("enode.key");
            std::fs::write(&enode_key_dst, config.execution_p2p_disc_key).wrap_err_with(|| {
                format!(
                    "failed writing signing share to `{}`",
                    enode_key_dst.display()
                )
            })?;

            println!("run the node with the following command:\n");
            let cmd = format!(
                "cargo run --bin tempo -- node \
                \\\n--consensus.signing-key {signing_key} \
                \\\n--consensus.signing-share {signing_share} \
                \\\n--consensus.listen-address 127.0.0.1:{listen_port} \
                \\\n--consensus.metrics-address 127.0.0.1:{metrics_port} \
                \\\n--chain {genesis} \
                \\\n--datadir {datadir} \
                \\\n--trusted-peers {trusted_peers} \
                \\\n--port {execution_p2p_port} \
                \\\n--discovery.port {execution_p2p_port} \
                \\\n--p2p-secret-key {execution_p2p_secret_key} \
                \\\n--authrpc.port {authrpc_port} \
                \\\n--consensus.fee-recipient {fee_recipient}",
                signing_key = signing_key_dst.display(),
                signing_share = signing_share_dst.display(),
                listen_port = config.consensus_p2p_port,
                metrics_port = config.consensus_p2p_port + 2,
                genesis = genesis_dst.display(),
                datadir = target_dir.display(),
                trusted_peers = trusted_peers.join(","),
                execution_p2p_port = config.execution_p2p_port,
                execution_p2p_secret_key = enode_key_dst.display(),
                fee_recipient = Address::ZERO,
                authrpc_port = config.execution_p2p_port + 2,
            );
            println!("{cmd}\n\n");
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigOutput {
    consensus_on_disk_signing_key: String,
    consensus_on_disk_signing_share: String,
    consensus_p2p_port: u16,
    execution_p2p_port: u16,
    execution_p2p_disc_key: String,
}
