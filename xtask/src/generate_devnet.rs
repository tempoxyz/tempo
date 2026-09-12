use std::{net::SocketAddr, path::PathBuf};

use alloy_primitives::Address;
use eyre::{Context, OptionExt as _, ensure};
use rand_08::SeedableRng as _;
use reth_network_peers::pk2id;
use secp256k1::SECP256K1;
use serde::Serialize;

use crate::genesis_args::GenesisArgs;

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
    genesis_args: GenesisArgs,
}

impl GenerateDevnet {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            output,
            force,
            image_tag,
            genesis_url,
            genesis_args,
        } = self;

        let seed = genesis_args.seed;
        let fee_recipients = genesis_args.validator_onchain_addresses()?;
        let (genesis, consensus_config) = genesis_args
            .generate_genesis()
            .await
            .wrap_err("failed to generate genesis")?;

        let consensus_config = consensus_config
            .ok_or_eyre("no consensus config generated; did you provide --validators?")?;

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

        let mut rng =
            rand_08::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand_08::random::<u64>));
        let mut execution_peers = vec![];

        let devmode = consensus_config.validators.len() == 1;

        let mut all_configs = vec![];
        for (idx, validator) in consensus_config.validators.into_iter().enumerate() {
            let (execution_p2p_signing_key, execution_p2p_identity) = {
                let (sk, pk) = SECP256K1.generate_keypair(&mut rng);
                (sk, pk2id(&pk))
            };

            let consensus_p2p_port = validator.addr.port();
            let execution_p2p_port = consensus_p2p_port + 1;
            let consensus_metrics_port = consensus_p2p_port + 2;

            execution_peers.push(format!(
                "enode://{execution_p2p_identity:x}@{}",
                SocketAddr::new(validator.addr.ip(), execution_p2p_port),
            ));

            all_configs.push((
                validator.clone(),
                ConfigOutput {
                    execution_genesis_url: genesis_url.clone(),

                    devmode,
                    node_image_tag: image_tag.clone(),

                    consensus_on_disk_signing_key: signing_key_to_hex(&validator.signing_key),
                    consensus_on_disk_signing_share: validator.signing_share.to_string(),

                    consensus_fee_recipient: fee_recipients[idx],

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

        let genesis_ser = serde_json::to_string_pretty(&genesis)
            .wrap_err("failed serializing genesis as json")?;
        let dst = output.join("genesis.json");
        std::fs::write(&dst, &genesis_ser)
            .wrap_err_with(|| format!("failed writing genesis to `{}`", dst.display()))?;
        println!("wrote genesis to `{}`", dst.display());
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

/// Stopgap: serialize the signing key to its on-disk hex representation
/// via [`tempo_consensus_config::SigningKey::to_writer_unencrypted`].
fn signing_key_to_hex(key: &tempo_consensus_config::SigningKey) -> String {
    let mut buf = Vec::new();
    key.to_writer_unencrypted(&mut buf)
        .expect("writing to Vec cannot fail");
    String::from_utf8(buf).expect("hex output is valid utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use clap::Parser as _;

    #[tokio::test]
    async fn generated_configs_use_validator_fee_recipients() {
        let default_recipients = [
            address!("70997970c51812dc3a010c7d01b50e0d17dc79c8"),
            address!("3c44cdddb6a900fa2b585dd299e03d12fa4293bc"),
            address!("90f79bf6eb2c4f870365e785982e1f101e93b906"),
            address!("15d34aaf54267db7d7c367839aaf71a00a2c6a65"),
        ];
        let custom_recipients = [0x11, 0x22, 0x33, 0x44].map(Address::repeat_byte);

        for (custom, expected) in [(false, default_recipients), (true, custom_recipients)] {
            let output = tempfile::tempdir().unwrap();
            let addresses = expected
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let mut args = vec![
                "generate-devnet",
                "--output",
                output.path().to_str().unwrap(),
                "--image-tag",
                "test",
                "--genesis-url",
                "http://localhost/genesis.json",
                "--accounts",
                "5",
                "--validators",
                "127.0.0.1:8000,127.0.0.1:8010,127.0.0.1:8020,127.0.0.1:8030",
                "--seed",
                "1",
                "--no-extra-tokens",
                "--no-pairwise-liquidity",
            ];
            if custom {
                args.extend(["--validator-addresses", &addresses]);
            }
            GenerateDevnet::try_parse_from(args)
                .unwrap()
                .run()
                .await
                .unwrap();

            for (port, recipient) in [8000, 8010, 8020, 8030].into_iter().zip(expected) {
                let config: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(output.path().join(format!("127.0.0.1:{port}.json"))).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    config["consensus_fee_recipient"],
                    serde_json::json!(recipient)
                );
            }
        }
    }
}
