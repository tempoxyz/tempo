//! xtask is a Swiss army knife of tools that help with running and testing tempo.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clap::Parser;
use commonware_cryptography::{PrivateKeyExt as _, Signer as _};
use eyre::{Context, ensure};
use indexmap::IndexMap;
use rand::{rngs::OsRng, seq::IteratorRandom as _};
use tempo_commonware_node_config::Config;
use tempo_commonware_node_cryptography::PrivateKey;

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    match args.action {
        Action::GenerateConfig(cfg) => generate_config(cfg).wrap_err("failed generating config"),
    }
}

#[derive(Debug, clap::Parser)]
#[command(author)]
#[command(version)]
#[command(about)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
    GenerateConfig(GenerateConfig),
}

/// Generates a config file to run a bunch of validators locally.
#[derive(Debug, clap::Parser)]
struct GenerateConfig {
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
    /// The number of bootstrappers to generate.
    #[arg(long)]
    bootstrappers: usize,
    #[arg(long)]
    mailbox_size: usize,
    #[arg(long)]
    message_backlog: usize,
    #[arg(long)]
    deque_size: usize,
    /// The starting port from which addresses will be assigned to peers.
    #[arg(long)]
    from_port: u16,
    #[arg(long)]
    fee_recipient: alloy_primitives::Address,
}

fn generate_config(
    GenerateConfig {
        output,
        force,
        peers,
        bootstrappers,
        mailbox_size,
        deque_size,
        from_port,
        fee_recipient,
        message_backlog,
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

    ensure!(
        bootstrappers <= peers,
        "requested `{bootstrappers}` bootstrappers but only `{peers}` peers; there must be at least as many peers as bootstrappers",
    );

    let mut signers = std::iter::repeat_n(OsRng, peers)
        .map(|mut r| PrivateKey::from_rng(&mut r))
        .collect::<Vec<_>>();

    signers.sort_by_key(|signer| signer.public_key());

    let all_peers: Vec<_> = signers.iter().map(|signer| signer.public_key()).collect();

    let bootstrappers = all_peers
        .iter()
        .choose_multiple(&mut OsRng, bootstrappers)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();

    // generate consensus key
    let threshold = commonware_utils::quorum(peers as u32);
    let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        tempo_commonware_node_cryptography::BlsScheme,
    >(&mut OsRng, None, peers as u32, threshold);

    // Generate instance configurations
    let mut port = from_port;
    let mut these_will_be_peers = IndexMap::new();
    let mut configurations = Vec::new();

    for (signer, share) in signers.into_iter().zip(shares) {
        // Create peer config
        let name = signer.public_key().to_string();
        these_will_be_peers.insert(
            signer.public_key(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        );
        let dst = {
            let mut p = output.join(&name);
            p.set_extension("toml");
            p
        };
        let peer_config = Config {
            signer,
            share,
            polynomial: polynomial.clone(),
            listen_port: port,
            metrics_port: port + 1,
            storage_directory: output.join(&name).join("storage"),
            worker_threads: 3,
            // this will be updated after we have collected all peers
            peers: IndexMap::new(),
            bootstrappers: bootstrappers.clone().into(),
            message_backlog,
            mailbox_size,
            deque_size,
            fee_recipient,
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
    eprint!("Bootstrappers:");
    for bootstrapper in bootstrappers {
        eprintln!("\t{bootstrapper}");
    }
    eprintln!("To start validators, run:");
    for (instance, (name, dst, cfg)) in configurations.iter().enumerate() {
        let eth_dst = cfg.storage_directory.with_file_name("reth_storage");
        let command = format!(
            "cargo run --release --bin tempo-commonware -- \
                \\\n--filter-directives \"debug,net=warn,reth_ecies=warn\" \
                \\\nnode \
                \\\n--consensus-config {dst} \
                \\\n--datadir {eth_dst} \
                \\\n--chain dev \
                \\\n--instance {instance} \
                \\\n--http"
        );
        println!("{name}: {command}");
    }
    // println!("To view metrics, run:");
    // for (name, _, peer_config) in configurations {
    //     println!(
    //         "{}: curl http://localhost:{}/metrics",
    //         name, peer_config.metrics_port
    //     );
    // }
    Ok(())
}
