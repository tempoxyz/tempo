//! Main executable for the Reth-Commonware node.
//!
//! This binary launches a blockchain node that combines:
//! - Reth's execution layer for transaction processing and state management
//! - Commonware's consensus engine for block agreement
//!
//! The node operates by:
//! 1. Starting the Reth node infrastructure (database, networking, RPC)
//! 2. Creating the application state that bridges Reth and Commonware
//! 3. Launching the Commonware consensus engine via a separate task and a separate tokio runtime.
//! 4. Running both components until shutdown
//!
//! Configuration can be provided via command-line arguments or configuration files.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

// tracy-client is an optional dependency activated by the `tracy` feature.
// It is not used directly but must be present for the `ondemand` feature flag.
#[cfg(feature = "tracy")]
use tracy_client as _;

// opentelemetry-otlp is an optional dependency activated by the `otlp` feature.
// It is not used directly but must be present to enable reqwest rustls support.
#[cfg(feature = "otlp")]
use opentelemetry_otlp as _;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// Compile-time jemalloc configuration for heap profiling.
///
/// tikv-jemallocator uses prefixed symbols, so the runtime `MALLOC_CONF` env var is ignored.
/// This exported symbol is read by jemalloc at init time to enable profiling unconditionally
/// when the `jemalloc-prof` feature is active.
///
/// See <https://github.com/jemalloc/jemalloc/wiki/Getting-Started>
#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

mod defaults;
mod init_state;
mod p2p_proxy;
mod tempo_cmd;

use clap::{CommandFactory, FromArgMatches};
use commonware_runtime::{Metrics, Runner};
use eyre::WrapErr as _;
use futures::{FutureExt as _, future::FusedFuture as _};
use reth_ethereum::{chainspec::EthChainSpec as _, cli::Commands, evm::revm::primitives::B256};
use reth_ethereum_cli::Cli;
use reth_network_api::Peers;
use reth_network_peers::pk2id;
use reth_node_builder::{NodeHandle, WithLaunchContext};
use reth_rpc_server_types::{RethRpcModule, RpcModuleSelection, RpcModuleValidator};
use std::{sync::Arc, thread, time::Duration};
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_commonware_node::{feed as consensus_feed, run_consensus_stack};
use tempo_consensus::TempoConsensus;
use tempo_evm::TempoEvmConfig;
use tempo_faucet::{
    args::FaucetArgs,
    faucet::{TempoFaucetExt, TempoFaucetExtApiServer},
};
use tempo_node::{
    TempoFullNode, TempoNodeArgs,
    node::TempoNode,
    rpc::consensus::{TempoConsensusApiServer, TempoConsensusRpc},
    telemetry::{PrometheusMetricsConfig, install_prometheus_metrics},
};
use tokio::sync::oneshot;
use tracing::{debug, info, info_span, warn};

type TempoCli =
    Cli<TempoChainSpecParser, TempoArgs, TempoRpcModuleValidator, tempo_cmd::TempoSubcommand>;

const TEMPO_CUSTOM_RPC_MODULES: &[&str] = &["consensus", "operator", "tempo", "token"];

#[derive(Debug, Clone, Copy)]
struct TempoRpcModuleValidator;

impl RpcModuleValidator for TempoRpcModuleValidator {
    fn parse_selection(s: &str) -> Result<RpcModuleSelection, String> {
        let selection = s
            .parse::<RpcModuleSelection>()
            .map_err(|e| format!("Failed to parse RPC modules: {e}"))?;

        if let RpcModuleSelection::Selection(modules) = &selection {
            for module in modules {
                let RethRpcModule::Other(name) = module else {
                    continue;
                };

                if !TEMPO_CUSTOM_RPC_MODULES.contains(&name.as_str()) {
                    return Err(format!("Unknown RPC module: '{name}'"));
                }
            }
        }

        Ok(selection)
    }
}

// TODO: migrate this to tempo_node eventually.
#[derive(Debug, Clone, clap::Args)]
struct TempoArgs {
    /// Follow this specific RPC node for block hashes.
    /// If provided without a value, defaults to the RPC URL for the selected chain.
    #[arg(long, value_name = "URL", default_missing_value = "auto", num_args(0..=1), env = "TEMPO_FOLLOW")]
    pub follow: Option<String>,

    /// HTTP endpoint that returns a JSON object mapping chain IDs to bootnode lists.
    ///
    /// The endpoint must return JSON in the format:
    /// `{ "<chain_id>": ["enode://...", ...] }`
    ///
    /// Bootnodes for the current chain are added as peer hints to the discovery service.
    #[arg(
        long = "tempo.bootnodes-endpoint",
        value_name = "URL",
        env = "TEMPO_BOOTNODES_ENDPOINT"
    )]
    pub bootnodes_endpoint: Option<String>,

    #[command(flatten)]
    pub telemetry: defaults::TelemetryArgs,

    #[command(flatten)]
    pub consensus: tempo_commonware_node::Args,

    #[command(flatten)]
    pub faucet_args: FaucetArgs,

    #[command(flatten)]
    pub node_args: TempoNodeArgs,

    #[command(flatten)]
    #[cfg(feature = "pyroscope")]
    pub pyroscope_args: PyroscopeArgs,
}

/// Command line arguments for configuring Pyroscope continuous profiling.
#[cfg(feature = "pyroscope")]
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
struct PyroscopeArgs {
    /// Enable Pyroscope continuous profiling
    #[arg(long = "pyroscope.enabled", default_value_t = false)]
    pub pyroscope_enabled: bool,

    /// Pyroscope server URL
    #[arg(long = "pyroscope.server-url", default_value = "http://localhost:4040")]
    pub server_url: String,

    /// Application name for Pyroscope
    #[arg(long = "pyroscope.application-name", default_value = "tempo")]
    pub application_name: String,

    /// Sample rate for profiling (default: 100 Hz)
    #[arg(long = "pyroscope.sample-rate", default_value_t = 100)]
    pub sample_rate: u32,
}

/// Force-install the default crypto provider.
///
/// This is necessary in case there are more than one available backends enabled in rustls (ring,
/// aws-lc-rs).
///
/// This should be called high in the main fn.
///
/// See also:
///   <https://github.com/snapview/tokio-tungstenite/issues/353#issuecomment-2455100010>
///   <https://github.com/awslabs/aws-sdk-rust/discussions/1257>
fn install_crypto_provider() {
    // https://github.com/snapview/tokio-tungstenite/issues/353
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default rustls crypto provider");
}

trait NodeCommandExt {
    /// Derive the peer id from the p2p secret key without starting the network.
    fn peer_id(&self) -> reth_network_peers::PeerId;
}

impl NodeCommandExt for reth_cli_commands::node::NodeCommand<TempoChainSpecParser, TempoArgs> {
    fn peer_id(&self) -> reth_network_peers::PeerId {
        let data_dir = self.datadir.clone().resolve_datadir(self.chain.chain());
        let sk = self
            .network
            .secret_key(data_dir.p2p_secret())
            .expect("unable to derive peer id from p2p secret");

        pk2id(&sk.public_key(secp256k1::SECP256K1))
    }
}

/// Print installed extensions as a footer after root help output.
/// Skips printing when help is for a subcommand (e.g. `tempo node --help`).
fn print_extensions_footer() {
    let is_subcommand_help = std::env::args()
        .skip(1)
        .any(|a| !a.starts_with('-') && a != "help");
    if is_subcommand_help {
        return;
    }

    let extensions = match tempo_ext::installed_extensions() {
        Ok(e) => e,
        Err(_) => return,
    };
    if extensions.is_empty() {
        return;
    }
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let (b, bu, r) = if use_color {
        ("\x1b[1m", "\x1b[1m\x1b[4m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    println!("\n{bu}Extensions:{r}");
    for (name, desc) in &extensions {
        if desc.is_empty() {
            println!("  {b}{name}{r}");
        } else {
            println!("  {b}{name:<22}{r} {desc}");
        }
    }
}

/// Fetches bootnodes from the given endpoint for the specified chain ID.
///
/// The endpoint must return JSON in the format:
/// `{ "<chain_id>": ["enode://...", ...] }`
async fn fetch_bootnodes(
    endpoint: &str,
    chain_id: u64,
) -> eyre::Result<Vec<reth_network_peers::NodeRecord>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .wrap_err("failed to build HTTP client")?;

    let resp: std::collections::HashMap<String, Vec<String>> = client
        .get(endpoint)
        .send()
        .await
        .wrap_err("request failed")?
        .error_for_status()
        .wrap_err("endpoint returned error status")?
        .json()
        .await
        .wrap_err("failed to parse response as JSON")?;

    let key = chain_id.to_string();
    let enodes = match resp.get(&key) {
        Some(enodes) => enodes,
        None => return Ok(Vec::new()),
    };

    Ok(reth_network_peers::parse_nodes(enodes))
}

fn main() -> eyre::Result<()> {
    install_crypto_provider();

    reth_cli_util::sigsegv_handler::install();

    // XXX: ensures that the error source chain is preserved in
    // tracing-instrument generated error events. That is, this hook ensures
    // that functions instrumented like `#[instrument(err)]` will emit an event
    // that contains the entire error source chain.
    //
    // TODO: Can remove this if https://github.com/tokio-rs/tracing/issues/2648
    // ever gets addressed.
    tempo_eyre::install()
        .expect("must install the eyre error hook before constructing any eyre reports");

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    tempo_node::init_version_metadata();
    defaults::init_defaults();

    let mut cli = match TempoCli::command()
        .about("Tempo")
        .try_get_matches_from(std::env::args_os())
        .and_then(|matches| TempoCli::from_arg_matches(&matches))
    {
        Ok(cli) => cli,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::InvalidSubcommand {
                // Unknown subcommand — try the extension launcher.
                let code = match tempo_ext::run(std::env::args_os()) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
                std::process::exit(code);
            }

            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                let _ = err.print();
                print_extensions_footer();
                std::process::exit(0);
            }

            err.exit();
        }
    };

    if let Commands::Node(node_cmd) = &cli.command
        && node_cmd.engine.share_sparse_trie_with_payload_builder
        && node_cmd.builder.max_payload_tasks != 1
    {
        eyre::bail!(
            "--engine.share-sparse-trie-with-payload-builder requires --builder.max-tasks to be 1 (got {})",
            node_cmd.builder.max_payload_tasks
        );
    }

    // If telemetry is enabled, set logs OTLP (conflicts_with in TelemetryArgs prevents both being set)
    let mut telemetry_config = None;
    if let Commands::Node(node_cmd) = &cli.command
        && let Some(config) = node_cmd
            .ext
            .telemetry
            .try_to_config()
            .wrap_err("failed to parse telemetry config")?
    {
        let consensus_pubkey = node_cmd
            .ext
            .consensus
            .public_key()
            .wrap_err("failed parsing consensus key")?
            .map(|k| k.to_string());

        let peer_id = format!("{:x}", node_cmd.peer_id());

        // VictoriaMetrics does not support merging `extra_fields` query args like `extra_labels` for
        // metrics. A workaround for now is to directly hook into the `OTEL_RESOURCE_ATTRIBUTES` env var
        // used at startup to capture contextual information.
        let mut extra_attrs = vec![format!("peer_id={peer_id}")];
        if let Some(pubkey) = &consensus_pubkey {
            extra_attrs.push(format!("consensus_pubkey={pubkey}"));
        }

        if !extra_attrs.is_empty() {
            let current = std::env::var("OTEL_RESOURCE_ATTRIBUTES").unwrap_or_default();
            let new_attrs = if current.is_empty() {
                extra_attrs.join(",")
            } else {
                format!("{current},{}", extra_attrs.join(","))
            };

            // SAFETY: called at startup before the OTEL SDK is initialised
            unsafe {
                std::env::set_var("OTEL_RESOURCE_ATTRIBUTES", &new_attrs);
            }
        }

        // Set Reth logs OTLP. Consensus logs are exported as well via the same tracing system.
        cli.traces.logs_otlp = Some(config.logs_otlp_url.clone());
        cli.traces.logs_otlp_filter = config
            .logs_otlp_filter
            .parse()
            .wrap_err("invalid default logs filter")?;

        telemetry_config.replace(config);
    }

    let is_node = matches!(cli.command, Commands::Node(_));

    let (args_and_node_handle_tx, args_and_node_handle_rx) =
        oneshot::channel::<(TempoFullNode, TempoArgs)>();
    let (consensus_dead_tx, mut consensus_dead_rx) = oneshot::channel();

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let cl_feed_state = consensus_feed::FeedStateHandle::new();

    let shutdown_token_clone = shutdown_token.clone();
    let cl_feed_state_clone = cl_feed_state.clone();
    let consensus_handle = thread::spawn(move || {
        // Exit early if we are not executing `tempo node` command.
        if !is_node {
            return Ok(());
        }

        let (node, args) = args_and_node_handle_rx.blocking_recv().wrap_err(
            "channel closed before consensus-relevant command line args \
                and a handle to the execution node could be received",
        )?;

        let ret = if node.config.dev.dev || args.follow.is_some() {
            // When --follow is used (with or without a URL), skip consensus stack
            futures::executor::block_on(async move {
                shutdown_token_clone.cancelled().await;
                Ok(())
            })
        } else {
            let consensus_storage = args.consensus.storage_dir.clone().unwrap_or_else(|| {
                node.config
                    .datadir
                    .clone()
                    .resolve_datadir(node.chain_spec().chain())
                    .data_dir()
                    .join("consensus")
            });

            info_span!("prepare_consensus").in_scope(|| {
                info!(
                    path = %consensus_storage.display(),
                    "determined directory for consensus data",
                )
            });

            let runtime_config = commonware_runtime::tokio::Config::default()
                .with_tcp_nodelay(Some(true))
                .with_worker_threads(args.consensus.worker_threads)
                .with_storage_directory(consensus_storage)
                .with_catch_panics(true);

            let runner = commonware_runtime::tokio::Runner::new(runtime_config);

            runner.start(async move |ctx| {
                // Ensure all consensus metrics are prefixed. Shadow `ctx` to
                // not forget.
                let ctx = ctx.with_label("consensus");

                let mut metrics_server = tempo_commonware_node::metrics::install(
                    ctx.with_label("metrics"),
                    args.consensus.metrics_address,
                )
                .fuse();

                // Start the unified metrics exporter if configured
                if let Some(config) = telemetry_config {
                    let consensus_pubkey = args
                        .consensus
                        .public_key()
                        .wrap_err("failed parsing consensus key")?
                        .map(|k| k.to_string());

                    let prometheus_config = PrometheusMetricsConfig {
                        endpoint: config.metrics_prometheus_url,
                        interval: config.metrics_prometheus_interval,
                        auth_header: config.metrics_auth_header,
                        consensus_pubkey,
                        peer_id: format!("{:x}", node.network.peer_id()),
                    };

                    install_prometheus_metrics(
                        ctx.with_label("telemetry_metrics"),
                        prometheus_config,
                    )
                    .wrap_err("failed to start Prometheus metrics exporter")?;
                }

                if args.consensus.fee_recipient.is_some() {
                    warn!(
                        "`--consensus.fee-recipient` is deprecated and will be \
                         removed. It is only used pre-T2 hardfork, if validator \
                         config v2 is not yet activated, or if the on-chain fee \
                         recipient is set to the zero address",
                    );
                }

                let consensus_stack =
                    run_consensus_stack(&ctx, args.consensus, node, cl_feed_state_clone);
                tokio::pin!(consensus_stack);
                loop {
                    tokio::select!(
                        biased;

                        () = shutdown_token_clone.cancelled() => {
                            break Ok(());
                        }

                        ret = &mut consensus_stack => {
                            break ret.and_then(|()| Err(eyre::eyre!(
                                "consensus stack exited unexpectedly"))
                            )
                            .wrap_err("consensus stack failed");
                        }

                        ret = &mut metrics_server, if !metrics_server.is_terminated() => {
                            let reason = match ret.wrap_err("task_panicked") {
                                Ok(Ok(())) => "unexpected regular exit".to_string(),
                                Ok(Err(err)) | Err(err) => format!("{err}"),
                            };
                            tracing::warn!(reason, "the metrics server exited");
                        }
                    )
                }
            })
        };
        let _ = consensus_dead_tx.send(());
        ret
    });

    let components =
        |spec: Arc<TempoChainSpec>| (TempoEvmConfig::new(spec.clone()), TempoConsensus::new(spec));

    cli.run_with_components::<TempoNode>(components, async move |builder, args| {
        let faucet_args = args.faucet_args.clone();
        let validator_key = args
            .consensus
            .public_key()?
            .map(|key| B256::from_slice(key.as_ref()));

        // Initialize Pyroscope profiling if enabled
        #[cfg(feature = "pyroscope")]
        let pyroscope_agent = if args.pyroscope_args.pyroscope_enabled {
            let agent = pyroscope::PyroscopeAgent::builder(
                &args.pyroscope_args.server_url,
                &args.pyroscope_args.application_name,
            )
            .backend(pyroscope_pprofrs::pprof_backend(
                pyroscope_pprofrs::PprofConfig::new()
                    .sample_rate(args.pyroscope_args.sample_rate)
                    .report_thread_id()
                    .report_thread_name(),
            ))
            .build()
            .wrap_err("failed to build Pyroscope agent")?;

            let agent = agent.start().wrap_err("failed to start Pyroscope agent")?;
            info!(
                server_url = %args.pyroscope_args.server_url,
                application_name = %args.pyroscope_args.application_name,
                "Pyroscope profiling enabled"
            );

            Some(agent)
        } else {
            None
        };
        let chain_id = builder.config().chain.chain().id();

        let NodeHandle {
            node,
            node_exit_future,
        } = builder
            .node(TempoNode::new(&args.node_args, validator_key))
            .apply(|mut builder: WithLaunchContext<_>| {
                // Enable discv5 peer discovery
                builder
                    .config_mut()
                    .network
                    .discovery
                    .enable_discv5_discovery = true;

                // Resolve the follow URL:
                // --follow or --follow=auto -> use chain-specific default
                // --follow=URL -> use provided URL
                if let Some(follow) = &args.follow {
                    let follow_url = if follow == "auto" {
                        builder
                            .config()
                            .chain
                            .default_follow_url()
                            .map(|s| s.to_string())
                    } else {
                        Some(follow.clone())
                    };
                    builder.config_mut().debug.rpc_consensus_url = follow_url;
                }

                builder
            })
            .extend_rpc_modules(move |ctx| {
                if faucet_args.enabled {
                    let ext = TempoFaucetExt::new(
                        faucet_args.addresses(),
                        faucet_args.amount(),
                        faucet_args.provider(),
                    );

                    ctx.modules.merge_configured(ext.into_rpc())?;
                }

                if validator_key.is_some() {
                    ctx.modules
                        .merge_configured(TempoConsensusRpc::new(cl_feed_state).into_rpc())?;
                }

                Ok(())
            })
            .launch_with_debug_capabilities()
            .await
            .wrap_err("failed launching execution node")?;

        // Fetch bootnodes from the endpoint in a background task and inject
        // them into the already-running discovery services.
        if let Some(endpoint) = args.bootnodes_endpoint.clone() {
            let network = node.network.clone();
            node.tasks().spawn_task(async move {
                match fetch_bootnodes(&endpoint, chain_id).await {
                    Ok(nodes) if nodes.is_empty() => {}
                    Ok(nodes) => {
                        info!(
                            chain_id,
                            count = nodes.len(),
                            endpoint,
                            "fetched bootnodes from endpoint"
                        );
                        for node in &nodes {
                            if let Some(discv4) = network.discv4() {
                                discv4.add_node(*node);
                            }
                            network.add_peer_kind(
                                node.id,
                                None,
                                node.tcp_addr(),
                                Some(node.udp_addr()),
                            );
                        }
                        if let Some(discv5) = network.discv5() {
                            let enr_requests = nodes.iter().filter_map(|node| {
                                match reth_discv5::BootNode::from_unsigned(*node) {
                                    Ok(boot_node) => Some(async move {
                                        if let Err(err) = discv5
                                            .with_discv5(|d| {
                                                d.request_enr(boot_node.to_string())
                                            })
                                            .await
                                        {
                                            debug!(%err, %node, "failed adding boot node to discv5");
                                        }
                                    }),
                                    Err(err) => {
                                        warn!(%err, %node, "failed converting boot node for discv5");
                                        None
                                    }
                                }
                            });
                            futures::future::join_all(enr_requests).await;
                        }
                    }
                    Err(err) => {
                        warn!(%err, endpoint, "failed to fetch bootnodes from endpoint");
                    }
                }
            });
        }

        let _ = args_and_node_handle_tx.send((node, args));

        // TODO: emit these inside a span
        tokio::select! {
            _ = node_exit_future => {
                tracing::info!("execution node exited");
            }
            _ = &mut consensus_dead_rx => {
                tracing::info!("consensus node exited");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received shutdown signal");
            }
        }

        #[cfg(feature = "pyroscope")]
        if let Some(agent) = pyroscope_agent {
            agent.shutdown();
        }

        Ok(())
    })
    .wrap_err("execution node failed")?;

    shutdown_token.cancel();

    match consensus_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("consensus task exited with error:\n{err:?}"),
        Err(unwind) => std::panic::resume_unwind(unwind),
    }
    Ok(())
}
