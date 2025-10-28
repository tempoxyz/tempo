use alloy_primitives::address;
use commonware_cryptography::{PrivateKeyExt as _, Signer as _};
use eyre::{Context, ensure};
use indexmap::IndexMap;
use itertools::multizip;
use rand::SeedableRng;
use reth_network_peers::pk2id;
use secp256k1::SECP256K1;
use serde::Serialize;
use tempo_commonware_node_config::Config;
use tempo_commonware_node_cryptography::PrivateKey;

/// Generates a config file to run a bunch of validators locally.
#[derive(Debug, clap::Parser)]
pub(crate) struct DevnetConfig {
    /// The target directory that will be populated with validator configurations.
    ///
    /// If this directory exists but is not empty the operation will fail unless `--force`
    /// is specified. In this case the target directory will be first cleaned.
    #[arg(long, short, value_name = "DIR")]
    output: camino::Utf8PathBuf,

    /// Whether to overwrite `output`.
    #[arg(long)]
    force: bool,

    #[arg(long, default_value_t = camino::Utf8PathBuf::from("/data/tempo/"))]
    storage_directory: camino::Utf8PathBuf,

    #[arg(long("node"))]
    nodes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigOutput {
    commonware_config: String,
    reth_peers: Vec<String>,
    reth_disc_key: String,
}

pub(crate) fn generate_devnet_configs(
    DevnetConfig {
        output,
        force,
        storage_directory,
        nodes,
    }: DevnetConfig,
) -> eyre::Result<()> {
    let output = camino::absolute_utf8(&output).wrap_err_with(|| {
        format!("failed determining absolute directory given --output `{output}`")
    })?;

    std::fs::create_dir_all(&output)
        .wrap_err_with(|| format!("failed creating target directory at `{output}`"))?;

    if force {
        eprintln!("--force was specified: deleting all files in target directory `{output}`");
        // XXX: this first removes the directory and then recreates it. Small workaround
        // so that one doesn't have to iterate through the entire thing recursively.
        std::fs::remove_dir_all(&output)
            .and_then(|_| std::fs::create_dir(&output))
            .wrap_err_with(|| format!("failed clearing target directory at `{output}`"))?;
    } else {
        let target_is_empty = std::fs::read_dir(&output)
            .wrap_err_with(|| {
                format!("failed reading target directory `{output}` to determine if it is empty")
            })?
            .next()
            .is_none();
        ensure!(
            target_is_empty,
            "target directory `{output}` is not empty; delete all its contents or rerun command with --force",
        );
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(rand::random::<u64>());
    let mut signers = (0..nodes.len())
        .map(|_| PrivateKey::from_rng(&mut rng))
        .collect::<Vec<_>>();
    signers.sort_by_key(|signer| signer.public_key());

    let all_peers: Vec<_> = signers.iter().map(|signer| signer.public_key()).collect();

    // generate consensus key
    let threshold = commonware_utils::quorum(nodes.len() as u32);
    let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        tempo_commonware_node_cryptography::BlsScheme,
    >(&mut rng, None, nodes.len() as u32, threshold);

    // Generate instance configurations
    let mut these_will_be_peers = IndexMap::new();
    let mut commonware_configs = Vec::new();

    for (signer, share, url) in multizip((signers, shares, nodes.clone())) {
        // Create peer config
        these_will_be_peers.insert(signer.public_key(), url.to_string());
        let peer_config = Config {
            signer,
            share,
            polynomial: polynomial.clone(),
            listen_port: 8000,
            metrics_port: Some(8002),
            p2p: Default::default(),
            storage_directory: storage_directory.clone(),
            worker_threads: 3,
            // this will be updated after we have collected all peers
            peers: IndexMap::new(),
            bootstrappers: all_peers.clone().into(),
            message_backlog: 0,
            mailbox_size: 0,
            deque_size: 0,
            fee_recipient: address!("0x0000000000000000000000000000000000000000"),
            timeouts: Default::default(),
        };

        commonware_configs.push(peer_config);
    }

    commonware_configs
        .iter_mut()
        .for_each(|cfg| cfg.peers = these_will_be_peers.clone());

    let reth_identities = (0..nodes.len())
        .map(|_| {
            let (sk, pk) = SECP256K1.generate_keypair(&mut rand::thread_rng());
            (sk, pk2id(&pk))
        })
        .collect::<Vec<_>>();

    let enodes = reth_identities
        .clone()
        .iter()
        .zip(nodes.clone())
        .map(|((_, id), node)| {
            let enode = format!("enode://{:x}@{}", id, node);
            enode
        })
        .collect::<Vec<_>>();

    for (commonware_config, reth_identity, node) in
        multizip((commonware_configs, reth_identities, nodes.clone()))
    {
        let serialized_commonware_config = toml::to_string_pretty(&commonware_config)
            .wrap_err("failed to convert commonware config to toml")?;

        let output_config = ConfigOutput {
            commonware_config: serialized_commonware_config,
            reth_disc_key: format!("{}", reth_identity.0.display_secret()),
            reth_peers: enodes.clone(),
        };
        let config_json =
            serde_json::to_string(&output_config).expect("failed to convert config to json");

        let dst = {
            let mut p = output.join(&node);
            p.set_extension("json");
            p
        };

        std::fs::write(dst, config_json).expect("failed to write config file");
    }

    eprintln!("Config files written");
    Ok(())
}
