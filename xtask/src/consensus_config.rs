use commonware_cryptography::{PrivateKeyExt as _, Signer as _, ed25519::PrivateKey};
use eyre::{WrapErr as _, ensure};
use indexmap::IndexMap;
use rand::SeedableRng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tempo_commonware_node_config::Config;

/// Generates a config file to run a bunch of validators locally.
#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateConfig {
    /// The target directory that will be populated with validator configurations.
    ///
    /// If this directory exists but is not empty the operation will fail unless `--force`
    /// is specified. In this case the target directory will be first cleaned.
    #[arg(long, short, value_name = "DIR")]
    output: camino::Utf8PathBuf,
    /// Whether to overwrite `output`.
    #[arg(long)]
    force: bool,
    /// The number of peers to generate.
    #[arg(long)]
    peers: usize,
    #[arg(long)]
    mailbox_size: usize,
    #[arg(long)]
    message_backlog: usize,
    #[arg(long)]
    deque_size: usize,
    /// The starting port from which addresses will be assigned to peers.
    #[arg(long)]
    from_port: u16,
    /// The suggested fee recipient in payload builder args.
    #[arg(long)]
    fee_recipient: alloy_primitives::Address,
    /// A fixed seed to generate all signing keys and group shares. This is
    /// intended for use in development and testing. Use at your own peril.
    #[arg(long)]
    seed: Option<u64>,
}

pub(crate) fn generate_config(
    GenerateConfig {
        output,
        force,
        peers,
        mailbox_size,
        deque_size,
        from_port,
        fee_recipient,
        message_backlog,
        seed,
    }: GenerateConfig,
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

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
    let mut signers = (0..peers)
        .map(|_| PrivateKey::from_rng(&mut rng))
        .collect::<Vec<_>>();
    signers.sort_by_key(|signer| signer.public_key());

    // generate consensus key
    let threshold = commonware_utils::quorum(peers as u32);
    let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        commonware_cryptography::bls12381::primitives::variant::MinSig,
    >(&mut rng, None, peers as u32, threshold);

    // Generate instance configurations
    let mut port = from_port;
    let mut these_will_be_peers = IndexMap::new();
    let mut configurations = Vec::new();

    for (signer, share) in signers.into_iter().zip(shares) {
        // Create peer config
        let name = signer.public_key().to_string();
        these_will_be_peers.insert(
            signer.public_key(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).to_string(),
        );
        let dst = {
            let mut p = output.join(&name);
            p.set_extension("toml");
            p
        };
        let peer_config = Config {
            signer,
            share,
            // 1 week worth of blocks, assuming 2s per block
            epoch_length: 302_400,
            polynomial: polynomial.clone(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            metrics_port: Some(port + 1),
            p2p: Default::default(),
            storage_directory: output.join(&name).join("storage"),
            worker_threads: 3,
            // this will be updated after we have collected all peers
            peers: IndexMap::new(),
            message_backlog,
            mailbox_size,
            deque_size,
            fee_recipient,
            timeouts: Default::default(),
        };
        configurations.push((name, dst, peer_config));
        port += 2;
    }

    configurations
        .iter_mut()
        .for_each(|(_, _, cfg)| cfg.peers = these_will_be_peers.clone());

    // Write configuration files
    for (_, dst, cfg) in &configurations {
        let pretty = toml::to_string_pretty(&cfg).wrap_err("failed to convert config to toml")?;
        std::fs::write(dst, &pretty)
            .wrap_err_with(|| format!("failed writing config to file `{dst}`"))?;
        eprintln!("wrote config to file: `{dst}`");
    }

    eprintln!("Config files written");
    eprintln!("To start validators, run:");
    for (instance, (name, dst, cfg)) in (1u32..).zip(&configurations) {
        let eth_dst = cfg.storage_directory.with_file_name("reth_storage");
        let command = format!(
            "cargo run --release --bin tempo -- \
                \\\nnode \
                \\\n--consensus-config {dst} \
                \\\n--datadir {eth_dst} \
                \\\n--chain dev \
                \\\n--instance {instance} \
                \\\n--http"
        );
        println!("{name}: {command}");
    }
    println!("\nTo view metrics, run:");
    for (name, _, peer_config) in &configurations {
        let cmd = match peer_config.metrics_port {
            None => "<metrics port not set>".to_string(),
            Some(metrics_port) => format!("curl http://localhost:{metrics_port}/metrics",),
        };
        println!("{name}: {cmd}");
    }
    Ok(())
}
