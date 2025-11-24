use std::{fmt::Display, net::SocketAddr, str::FromStr};

use alloy_primitives::address;
use commonware_cryptography::{PrivateKeyExt as _, Signer as _, ed25519::PrivateKey};
use eyre::{Context, ensure};
use indexmap::IndexMap;
use itertools::multizip;
use reth_network_peers::pk2id;
use secp256k1::SECP256K1;
use serde::Serialize;
use tempo_commonware_node_config::Config;

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

    #[arg(long)]
    image_tag: String,

    #[arg(long)]
    genesis_url: String,

    /// Nodes in host:port format. The port will be used for both consensus and execution,
    /// so please make sure that there's a difference of at least 2 ports between each node
    /// if running in Kubernetes.
    /// If there is only one node, then consensus configuration will be empty.
    #[arg(long("node"))]
    nodes: Vec<HostPort>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigOutput {
    devmode: bool,
    consensus_config: String,
    consensus_p2p_port: u16,
    node_image_tag: String,
    execution_genesis_url: String,
    execution_p2p_port: u16,
    execution_peers: Vec<String>,
    execution_p2p_disc_key: String,
}

#[derive(Debug, Clone)]
struct HostPort {
    host: String,
    port: u16,
}

impl Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl FromStr for HostPort {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        ensure!(parts.len() == 2, "invalid host:port format");
        let host = parts[0].to_string();
        let port = parts[1]
            .parse::<u16>()
            .wrap_err_with(|| format!("invalid port `{}`", parts[1]))?;
        Ok(Self { host, port })
    }
}

pub(crate) fn generate_devnet_configs(
    DevnetConfig {
        output,
        image_tag,
        genesis_url,
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

    let mut consensus_configs = Vec::new();

    if nodes.len() > 1 {
        consensus_configs = generate_consensus_configs(nodes.clone(), storage_directory);
    } else {
        consensus_configs.push(None);
    }

    let execution_p2p_identities = (0..nodes.len())
        .map(|_| {
            let (sk, pk) = SECP256K1.generate_keypair(&mut rand::thread_rng());
            (sk, pk2id(&pk))
        })
        .collect::<Vec<_>>();

    let enodes = execution_p2p_identities
        .iter()
        .zip(nodes.clone())
        .map(|((_, id), node)| {
            let mut execution_node = node;
            execution_node.port += 1;
            let enode = format!("enode://{id:x}@{execution_node}");
            enode
        })
        .collect::<Vec<_>>();

    for (consensus_config, execution_p2p_identity, node) in
        multizip((consensus_configs, execution_p2p_identities, nodes.clone()))
    {
        let serialized_consensus_config = if let Some(config) = consensus_config {
            toml::to_string_pretty(&config)
                .wrap_err("failed to convert consensus config to toml")?
        } else {
            String::new()
        };

        let output_config = ConfigOutput {
            execution_genesis_url: genesis_url.clone(),
            devmode: nodes.len() == 1,
            node_image_tag: image_tag.clone(),
            consensus_config: serialized_consensus_config,
            consensus_p2p_port: node.port,
            execution_p2p_port: node.port + 1,
            execution_p2p_disc_key: format!("{}", execution_p2p_identity.0.display_secret()),
            execution_peers: enodes.clone(),
        };
        let config_json =
            serde_json::to_string(&output_config).expect("failed to convert config to json");

        let dst = {
            let mut p = output.join(&node.host);
            p.set_extension("json");
            p
        };

        std::fs::write(dst, config_json).expect("failed to write config file");
    }

    eprintln!("Config files written");
    Ok(())
}

fn generate_consensus_configs(
    nodes: Vec<HostPort>,
    storage_directory: camino::Utf8PathBuf,
) -> Vec<Option<Config>> {
    let mut signers = (0..nodes.len())
        .map(|_| PrivateKey::from_rng(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    signers.sort_by_key(|signer| signer.public_key());

    // generate consensus key
    let threshold = commonware_utils::quorum(nodes.len() as u32);
    let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        commonware_cryptography::bls12381::primitives::variant::MinSig,
    >(&mut rand::thread_rng(), None, nodes.len() as u32, threshold);

    // Generate instance configurations
    let mut these_will_be_peers = IndexMap::new();
    let mut consensus_configs = Vec::new();

    for (signer, share, url) in multizip((signers, shares, nodes)) {
        // Create peer config
        these_will_be_peers.insert(signer.public_key(), url.to_string());
        let peer_config = Config {
            signer,
            share,
            polynomial: polynomial.clone(),
            epoch_length: 302_400,
            metrics_port: Some(8002),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], url.port)),
            p2p: Default::default(),
            storage_directory: storage_directory.clone(),
            worker_threads: 3,
            // this will be updated after we have collected all peers
            peers: IndexMap::new(),
            message_backlog: 16384,
            mailbox_size: 16384,
            deque_size: 10,
            fee_recipient: address!("0x0000000000000000000000000000000000000000"),
            timeouts: Default::default(),
        };

        consensus_configs.push(Some(peer_config));
    }

    consensus_configs.iter_mut().for_each(|cfg| {
        cfg.as_mut().expect("this should always be Some").peers = these_will_be_peers.clone()
    });

    consensus_configs
}
