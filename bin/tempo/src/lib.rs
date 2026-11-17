//! Main library for the Reth-Commonware node.
//!
//! This crate launches a blockchain node that combines:
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

// Links Antithesis's coverage runtime shim into binaries built with its sancov flags.
#[cfg(all(target_os = "linux", feature = "antithesis-coverage"))]
use antithesis_instrumentation as _;

pub mod cli;
#[cfg(feature = "corpus")]
pub mod corpus;
mod defaults;
mod follow;
mod overrides;
pub mod p2p_proxy;
pub mod payload_bench;
pub mod regenesis;
pub mod shadow_replay;
mod snapshot_download;
mod snapshot_manifest;
pub mod tempo_cmd;
mod utils;

pub use crate::{
    cli::{TempoArgs, TempoCli, TempoRpcModuleValidator},
    overrides::{TempoNodeMapper, TempoOverrides},
};
pub use reth_cli_util as cli_util;
pub use tempo_node;
pub use tempo_node as node;
pub use tempo_state_bloat as init_state;

use crate::utils::{
    block_on_consensus_public_key, fetch_bootnodes, install_crypto_provider,
    print_extensions_footer,
};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256};
use alloy_signer_local::MnemonicBuilder;
use clap::{CommandFactory, FromArgMatches};
use commonware_runtime::{Runner, Supervisor as _};
use eyre::{OptionExt, WrapErr as _};
use futures::{
    FutureExt as _,
    future::{Either, FusedFuture as _},
};
use reth_cli_runner::CliRunner;
use reth_ethereum::{chainspec::EthChainSpec as _, cli::Commands};
use reth_network_api::Peers;
use reth_node_builder::{NodeHandle, WithLaunchContext};
use std::{sync::Arc, thread};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{DEV, TempoChainSpec},
};
use tempo_consensus::{feed as consensus_feed, run_consensus_stack, run_follow_stack};
use tempo_contracts::precompiles::{ZONE_FACTORY_ADDRESS, initial_zone_factory_config};
use tempo_evm::consensus::TempoConsensus;
use tempo_faucet::faucet::{TempoFaucetExt, TempoFaucetExtApiServer};
pub use tempo_node::{
    AccountInfoReader, AddressFilter, InvalidPoolTransactionError, PoolTransaction,
    PoolTransactionError, StatefulValidationFn, StatelessValidationFn, TempoNode, TempoNodeArgs,
    TempoPayloadBuilderBuilder, TempoPoolBuilder, TempoPoolTransactionError,
    TempoPooledTransaction, TransactionOrigin,
};
use tempo_node::{
    ShadowReplayer, TempoFullNode,
    rpc::consensus::{SubscriptionLimits, TempoConsensusApiServer, TempoConsensusRpc},
    telemetry::{
        HardwareMetricsConfig, PrometheusMetricsConfig, install_hardware_metrics,
        install_prometheus_metrics,
    },
};
use tokio::sync::oneshot;
use tracing::{debug, info, info_span, warn, warn_span};

#[cfg(all(feature = "localnet", unix))]
use nix as _;

const DEFAULT_DEV_ZONE_FACTORY_OWNER: Address =
    alloy_primitives::address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

fn apply_tempo_cli_overrides(cli: &mut TempoCli) -> eyre::Result<()> {
    if let Commands::Node(node_cmd) = &mut cli.command
        && node_cmd
            .ext
            .node_args
            .engine_disable_execution_cache_sharing_with_builder
    {
        node_cmd.engine.share_execution_cache_with_payload_builder = false;
    }

    if let Commands::Node(node_cmd) = &mut cli.command
        && node_cmd.dev.dev
        && node_cmd.chain.genesis_hash() == DEV.genesis_hash()
    {
        let owner = MnemonicBuilder::try_from_phrase_first(&node_cmd.dev.dev_mnemonic)
            .wrap_err("failed to derive ZoneFactory owner from --dev.mnemonic")?
            .address();
        if owner != DEFAULT_DEV_ZONE_FACTORY_OWNER {
            let mut genesis = node_cmd.chain.genesis().clone();
            set_zone_factory_genesis_owner(&mut genesis, owner)?;
            node_cmd.chain = Arc::new(TempoChainSpec::from_genesis(genesis));
        }
    }

    Ok(())
}

/// Rejects reth's debug consensus clients (`--debug.rpc-consensus-url`, `--debug.etherscan`)
/// when the Tempo consensus engine is active.
///
/// Reth's debug launcher drives the same beacon engine handle with new payloads and forkchoice
/// updates without any certificate checks, so it must not run next to the Tempo consensus or
/// certified follow stack.
fn ensure_no_debug_forkchoice_driver(cli: &TempoCli) -> eyre::Result<()> {
    if let Commands::Node(node_cmd) = &cli.command
        && node_cmd.ext.has_consensus_engine(node_cmd.dev.dev)
        && (node_cmd.debug.rpc_consensus_url.is_some() || node_cmd.debug.etherscan.is_some())
    {
        eyre::bail!(
            "--debug.rpc-consensus-url and --debug.etherscan drive forkchoice outside the Tempo consensus engine and are only allowed with --dev or --follow.nocertify"
        );
    }

    Ok(())
}

fn set_zone_factory_genesis_owner(genesis: &mut Genesis, owner: Address) -> eyre::Result<()> {
    let factory = genesis
        .alloc
        .get_mut(&ZONE_FACTORY_ADDRESS)
        .ok_or_eyre("DEV genesis is missing ZoneFactory")?;
    let storage = factory
        .storage
        .as_mut()
        .ok_or_eyre("DEV ZoneFactory is missing storage")?;
    storage.insert(B256::ZERO, B256::from(initial_zone_factory_config(owner)));
    Ok(())
}

/// Runs the Tempo node CLI.
pub fn tempo_main() -> eyre::Result<()> {
    tempo_main_with(TempoOverrides::default())
}

/// Runs the Tempo node CLI with programmatic startup overrides.
///
/// This is the embedding entrypoint for binaries that want the standard Tempo
/// CLI behavior plus programmatic hooks for behavior that cannot be expressed
/// through command-line arguments. [`tempo_main`] is equivalent to calling this
/// function with [`TempoOverrides::default`].
///
/// Overrides are applied after CLI parsing and before the execution node is
/// launched. See [`TempoOverrides`] for the currently supported hooks and an
/// example that injects additional transaction pool validation.
pub fn tempo_main_with(mut overrides: TempoOverrides) -> eyre::Result<()> {
    #[cfg(feature = "fuzz-execution")]
    antithesis_sdk::antithesis_init();

    // A JIT backend launches this binary as its out-of-process compiler.
    #[cfg(feature = "jit")]
    if tempo_evm::jit::maybe_run_jit_helper()?.is_break() {
        return Ok(());
    }

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

    tempo_node::init_version_metadata(tempo_node::tempo_version_metadata!());
    defaults::init_defaults();

    // `tempo snapshot-manifest` and `tempo download` wrap the Reth variants, so they
    // cannot be added without colliding. Mutate those subcommands with the wrapped ones.
    let matches = match TempoCli::command()
        .about("Tempo")
        .mut_subcommand("snapshot-manifest", |_| snapshot_manifest::Args::command())
        .mut_subcommand("download", |_| snapshot_download::Args::command())
        .try_get_matches_from(std::env::args_os())
    {
        Ok(matches) => matches,
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

    // Detect overwritten subcommands and directly run them as
    // `from_arg_matches` would map them to their original variants.
    match matches.subcommand() {
        Some(("snapshot-manifest", sub)) => return snapshot_manifest::run(sub),
        Some(("download", sub)) => {
            let runner =
                CliRunner::try_default_runtime().wrap_err("failed to build download runtime")?;
            let mut cli = match TempoCli::from_arg_matches(&matches) {
                Ok(cli) => cli,
                Err(err) => err.exit(),
            };

            if let Some(chain_spec) = cli.command.chain_spec() {
                cli.logs.log_file_directory = cli
                    .logs
                    .log_file_directory
                    .join(chain_spec.chain().to_string());
            }

            let mut tracing_app = cli.configure();
            tracing_app
                .init_tracing(&runner)
                .wrap_err("failed to initialize tracing")?;

            return snapshot_download::run_with_runner(sub, runner);
        }
        _ => {}
    }

    let mut cli = match TempoCli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };

    apply_tempo_cli_overrides(&mut cli)?;
    ensure_no_debug_forkchoice_driver(&cli)?;

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
        let consensus_pubkey = block_on_consensus_public_key(&node_cmd.ext.consensus)
            .wrap_err("failed parsing consensus key")?
            .map(|k| k.to_string());

        let peer_id = format!(
            "{:x}",
            node_cmd.peer_id().wrap_err("failed to derive peer id")?
        );

        // VictoriaMetrics does not support merging `extra_fields` query args like `extra_labels` for
        // metrics. A workaround for now is to directly hook into the `OTEL_RESOURCE_ATTRIBUTES` env var
        // used at startup to capture contextual information.
        let mut extra_attrs = vec![format!("peer_id={peer_id}")];
        if let Some(pubkey) = &consensus_pubkey {
            extra_attrs.push(format!("consensus_pubkey={pubkey}"));
        }

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

        // Set Reth logs OTLP. Consensus logs are exported as well via the same tracing system.
        cli.traces.logs_otlp = Some(config.logs_otlp_url.clone());

        telemetry_config = Some(config);
    }

    let is_node = matches!(cli.command, Commands::Node(_));

    let (consensus_startup_tx, consensus_startup_rx) = oneshot::channel::<(
        TempoFullNode,
        tempo_node::ExecutedState,
        TempoArgs,
        Option<tempo_node::gossip::TransportHandle>,
        tempo_node::Estimator,
    )>();
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

        let startup = receive_consensus_startup(consensus_startup_rx, &shutdown_token_clone)?;
        let Some((node, executed_state, args, gossip_transport, estimator)) = startup else {
            return Ok(());
        };

        let datadir = node
            .config
            .datadir
            .clone()
            .resolve_datadir(node.chain_spec().chain());
        let consensus_storage = args
            .consensus
            .storage_dir
            .clone()
            .unwrap_or_else(|| datadir.data_dir().join("consensus"));

        install_hardware_metrics(HardwareMetricsConfig {
            datadir: datadir.data_dir().to_path_buf(),
            static_files_dir: datadir.static_files(),
            consensus_dir: consensus_storage.clone(),
        });

        if !args.has_consensus_engine(node.config.dev.dev) {
            return futures::executor::block_on(async move {
                shutdown_token_clone.cancelled().await;
                Ok(())
            });
        }

        info_span!("prepare_consensus").in_scope(|| {
            info!(
                path = %consensus_storage.display(),
                "determined directory for consensus data",
            )
        });

        #[expect(
            deprecated,
            reason = "Maintain backward compatibility until all nodes have been updated; \
                      V1 blob creation will be enabled in a followup."
        )]
        let runtime_config = commonware_runtime::tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(args.consensus.worker_threads)
            .with_storage_directory(consensus_storage)
            .with_storage_blob_layouts(
                commonware_runtime::BlobLayout::V0..=commonware_runtime::BlobLayout::V0,
            )
            .with_catch_panics(true);

        let runner = commonware_runtime::tokio::Runner::new(runtime_config);
        let ret = runner.start(async move |ctx| {
            let mut metrics_server = tempo_consensus::metrics::install(
                ctx.child("metrics"),
                args.consensus.metrics_address,
            )
            .fuse();

            // Start the unified metrics exporter if configured
            if let Some(config) = telemetry_config {
                let consensus_pubkey = args
                    .consensus
                    .public_key()
                    .await
                    .wrap_err("failed parsing consensus key")?
                    .map(|k| k.to_string());

                let prometheus_config = PrometheusMetricsConfig {
                    endpoint: config.metrics_prometheus_url,
                    interval: config.metrics_prometheus_interval,
                    auth_header: config.metrics_auth_header,
                    consensus_pubkey,
                    peer_id: format!("{:x}", node.network.peer_id()),
                };

                install_prometheus_metrics(ctx.child("telemetry_metrics"), prometheus_config)
                    .wrap_err("failed to start Prometheus metrics exporter")?;
            }

            let consensus_stack = if let Some(follow) = args.follow {
                let follow_url = follow
                    .resolve_url(&node.chain_spec())
                    .ok_or_eyre("No default follow URL for this chain")?;

                Either::Left(run_follow_stack(
                    ctx.child("follow"),
                    args.consensus,
                    follow_url,
                    args.follow_upstream_request_timeout.into_duration(),
                    Arc::new(node),
                    cl_feed_state_clone,
                    gossip_transport,
                ))
            } else {
                Either::Right(run_consensus_stack(
                    ctx.child("consensus"),
                    args.consensus,
                    Arc::new(node),
                    executed_state,
                    cl_feed_state_clone,
                    gossip_transport,
                    estimator,
                ))
            };

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

                        warn_span!("consensus_metrics").in_scope(|| {
                            warn!(reason, "the metrics server exited");
                        })
                    }
                )
            }
        });

        let _ = consensus_dead_tx.send(());
        ret
    });

    let jit_args = match &cli.command {
        Commands::ReExecute(cmd) => cmd.jit.clone(),
        _ => Default::default(),
    };
    let components = move |spec: Arc<TempoChainSpec>| {
        let (evm_config, _) = tempo_node::node::build_evm_config(spec.clone(), &jit_args, None)
            .expect("failed to build EVM config");
        (evm_config, TempoConsensus::new(spec))
    };

    let mut consensus_result = Ok(Ok(()));
    // Reth drops the launcher before shutting down its execution tasks, including on SIGTERM.
    let consensus_shutdown = ConsensusShutdown {
        shutdown_token,
        handle: Some(consensus_handle),
        result: &mut consensus_result,
    };
    let execution_result = cli.run_with_components::<TempoNode>(components, async move |builder, args| {
        let _consensus_shutdown = consensus_shutdown;
        if let Some(value) = args.consensus.message_backlog {
            warn!(
                flag = "--consensus.message-backlog",
                value,
                "deprecated flag ignored; P2P queue capacities are derived from peer-set limits and channel quotas"
            );
        }
        if let Some(value) = args.consensus.inactive_views_until_leader_skip {
            warn!(
                flag = "--consensus.inactive-views-until-leader-skip",
                value,
                "deprecated flag ignored; leader skipping is driven by --consensus.inactive-time-before-leader-skip"
            );
        }

        // Register before launch because each RLPx session negotiates its
        // subprotocols during the handshake. The startup channel passes the
        // consensus half of the transport to the consensus thread.
        let (gossip_protocol_handler, gossip_transport) =
            if args.has_gossip(builder.config().dev.dev) {
                let (protocol_handler, transport) = tempo_node::gossip::init(
                    args.consensus.gossip_transport(args.follow.is_some()),
                    builder.task_executor(),
                );
                (Some(protocol_handler), Some(transport))
            } else {
                (None, None)
            };

        let faucet_args = args.faucet_args.clone();
        let consensus_subscription_limits = SubscriptionLimits {
            max_subscriptions: args.consensus_max_subscriptions,
            max_subscriptions_per_connection: args.consensus_max_subscriptions_per_connection,
        };
        let validator_key = args
            .consensus
            .public_key()
            .await?
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
        let chain_id = builder.config().chain.chain_id();

        #[cfg(feature = "custom-pcrs")]
        if let Some(policy) = args.custom_pcrs.clone() {
            policy.validate(chain_id)?;
            warn!(?policy, "replacing compiled-in zone verifier PCRs with a custom policy");
            tempo_precompiles::zone_verifier::CUSTOM_PCRS
                .set(policy)
                .map_err(|_| eyre::eyre!("zone verifier PCRs were already set"))?;
        }

        // Resolve the bootnodes endpoint:
        // --tempo.bootnodes-endpoint=none -> disabled
        // otherwise -> use the provided/default URL
        let bootnodes_endpoint = match args.bootnodes_endpoint.trim() {
            value if value.eq_ignore_ascii_case("none") => None,
            url => Some(url.to_string()),
        };

        let tempo_node = overrides.apply_tempo_node({
            let node = TempoNode::new(&args.node_args, validator_key);
            match gossip_protocol_handler {
                Some(protocol_handler) => node.with_finalization_cert_gossip(protocol_handler),
                None => node,
            }
        });
        let estimator = tempo_node
            .payload_builder_builder()
            .resolve_estimator(args.consensus.estimator_config())
            .wrap_err("invalid proposal budget flags")?;
        // Share the overridden settings with both the payload builder and consensus.
        let tempo_node = tempo_node.with_estimator(estimator.clone());
        let executed_state = tempo_node.executed_state();

        let NodeHandle {
            node,
            node_exit_future,
        } = tempo_node_launcher::launch(builder
            .node(tempo_node)
            .apply(|mut builder: WithLaunchContext<_>| {
                // Uncertified follower mode: set debug RPC when certification is off
                if args.is_following_uncertified() {
                    let follow_url = args
                        .follow
                        .as_ref()
                        .and_then(|follow| follow.resolve_url(&builder.config().chain));
                    builder.config_mut().debug.rpc_consensus_url = follow_url;
                }

                let has_consensus_engine =
                    args.has_consensus_engine(builder.config().dev.dev);

                builder.extend_rpc_modules(move |ctx| {
                    if faucet_args.enabled {
                        let faucet_ext = TempoFaucetExt::new(
                            faucet_args.addresses(),
                            faucet_args.amount(),
                            faucet_args.provider(),
                        );

                        ctx.modules.merge_configured(faucet_ext.into_rpc())
                            .wrap_err("failed to register faucet rpc module")?;
                    }

                    if has_consensus_engine {
                        let module_config = ctx.modules.module_config();
                        let mut missing = Vec::new();
                        if cli::selection_lacks_consensus(module_config.http()) {
                            missing.push("--http.api");
                        }
                        if cli::selection_lacks_consensus(module_config.ws()) {
                            missing.push("--ws.api");
                        }
                        if !missing.is_empty() {
                            warn!(
                                flags = %missing.join(", "),
                                "the consensus RPC module (consensus_*) is served on transports \
                                 whose module selection does not list it; this implicit activation \
                                 is deprecated and will be removed in a future release, add \
                                 `consensus` to the listed flags to keep serving it",
                            );
                        }

                        // Registered on HTTP, WS and IPC regardless of selection until the
                        // deprecation above is completed.
                        // Connection IDs are only unique within one server, so the handler with
                        // the per-connection cap serves HTTP and WS only. They share one server
                        // when they share a port, and HTTP never runs subscriptions otherwise.
                        // IPC is a separate server and local, so it only gets the global cap.
                        let consensus_rpc = TempoConsensusRpc::new(cl_feed_state, consensus_subscription_limits);
                        let without_connection_cap = consensus_rpc.without_connection_cap();
                        ctx.modules.merge_http(consensus_rpc.clone().into_rpc())
                            .wrap_err("failed to register consensus rpc module on http")?;
                        ctx.modules.merge_ws(consensus_rpc.into_rpc())
                            .wrap_err("failed to register consensus rpc module on ws")?;
                        ctx.modules.merge_ipc(without_connection_cap.into_rpc())
                            .wrap_err("failed to register consensus rpc module on ipc")?;
                    }

                    Ok(())
                })
            }))
            .await
            .wrap_err("failed launching execution node")?;

        if let Some(hardfork) = args.node_args.shadow_replay {
            let hardfork = hardfork.unwrap_or_else(|| *TempoHardfork::VARIANTS.last().unwrap());
            ShadowReplayer::new(node.provider.clone(), hardfork).spawn(node.tasks().clone());
        }

        // Fetch bootnodes from the endpoint in a background task and inject
        // them into the already-running discovery services.
        if let Some(endpoint) = bootnodes_endpoint {
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

        // The receiver is only dropped when the consensus thread has already
        // exited, which `consensus_dead_rx` below reports.
        let _ = consensus_startup_tx.send((node, executed_state, args, gossip_transport, estimator));

        // TODO: emit these inside a span
        tokio::select! {
            result = node_exit_future => {
                result.wrap_err("execution node exited with error")?;
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
    .wrap_err("execution node failed");

    // A launch failure is primary; aborted consensus startup must not replace it.
    execution_result?;
    match consensus_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err).wrap_err("consensus task exited with error"),
        Err(unwind) => std::panic::resume_unwind(unwind),
    }
    Ok(())
}

// Owns consensus until the launcher's future is dropped, even if it was never polled.
struct ConsensusShutdown<'a> {
    /// Stops the consensus root or its startup wait.
    shutdown_token: tokio_util::sync::CancellationToken,
    /// Taken on drop to join consensus before execution teardown.
    handle: Option<thread::JoinHandle<eyre::Result<()>>>,
    /// Carries the thread's error or panic back across launcher cancellation.
    result: &'a mut thread::Result<eyre::Result<()>>,
}

impl Drop for ConsensusShutdown<'_> {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
        if let Some(handle) = self.handle.take() {
            // Consensus has its own runtime. Drain it while execution workers are still alive.
            *self.result = handle.join();
        }
    }
}

fn receive_consensus_startup<T>(
    startup: oneshot::Receiver<T>,
    shutdown_token: &tokio_util::sync::CancellationToken,
) -> eyre::Result<Option<T>> {
    futures::executor::block_on(async {
        tokio::select! {
            biased;
            () = shutdown_token.cancelled() => Ok(None),
            startup = startup => startup.map(Some).wrap_err(
                "channel closed before consensus-relevant command line args \
                and a handle to the execution node could be received",
            ),
        }
    })
}

/// Creates a temporary directory on tmpfs where available.
///
/// For tests whose runtime is dominated by fsync or syncfs latency on the CI disk, which is
/// shared with node tests, rather than by the behavior they check.
#[cfg(test)]
pub(crate) fn tmpfs_tempdir() -> tempfile::TempDir {
    #[cfg(target_os = "linux")]
    if let Ok(dir) = tempfile::tempdir_in("/dev/shm") {
        return dir;
    }
    tempfile::tempdir().unwrap()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Once,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::Duration,
    };

    use alloy_genesis::GenesisAccount;
    use alloy_primitives::{Address, B256, Bytes, address};
    use clap::{CommandFactory, FromArgMatches, Parser};

    use super::*;
    use crate::follow::FollowMode;
    use reth_ethereum::cli::Commands;
    use tempo_contracts::precompiles::{
        ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS,
        ZONE_VERIFIER_ADDRESS, initial_zone_factory_config,
    };
    use tokio_util::sync::CancellationToken;

    // Use the same independent runtime as production, with a deadline for broken shutdowns.
    fn spawn_consensus_until_shutdown(
        token: CancellationToken,
        drained: Arc<AtomicBool>,
    ) -> thread::JoinHandle<eyre::Result<()>> {
        thread::spawn(move || {
            let storage = tmpfs_tempdir();
            let runner = commonware_runtime::tokio::Runner::new(
                commonware_runtime::tokio::Config::default()
                    .with_worker_threads(1)
                    .with_storage_directory(storage.path().to_path_buf()),
            );
            let result = runner.start(async move |_ctx| {
                tokio::time::timeout(Duration::from_secs(5), token.cancelled())
                    .await
                    .unwrap();
                Ok(())
            });
            drained.store(true, Ordering::SeqCst);
            result
        })
    }

    #[test]
    fn consensus_shutdown_drains_before_execution_shutdown() {
        let runner = CliRunner::try_default_runtime().unwrap();
        let token = CancellationToken::new();
        let drained = Arc::new(AtomicBool::new(false));
        let mut consensus_result = Ok(Ok(()));
        let shutdown = ConsensusShutdown {
            shutdown_token: token.clone(),
            handle: Some(spawn_consensus_until_shutdown(
                token.clone(),
                drained.clone(),
            )),
            result: &mut consensus_result,
        };
        let (observed_tx, observed_rx) = mpsc::channel();
        let execution_result: eyre::Result<()> = runner.run_command_until_exit(|ctx| async move {
            let _shutdown = shutdown;
            ctx.task_executor
                .spawn_with_graceful_shutdown_signal(async move |exit| {
                    let _guard = exit.await;
                    observed_tx
                        .send((token.is_cancelled(), drained.load(Ordering::SeqCst)))
                        .unwrap();
                });
            Ok(())
        });
        execution_result.unwrap();
        consensus_result.unwrap().unwrap();
        assert_eq!(
            observed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            (true, true)
        );
    }

    #[test]
    fn consensus_shutdown_drains_an_unpolled_launcher_before_startup() {
        let token = CancellationToken::new();
        let consensus_token = token.clone();
        let (startup_tx, startup_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        let mut result = Ok(Ok(()));
        let handle = thread::spawn(move || {
            assert_eq!(
                receive_consensus_startup(startup_rx, &consensus_token).unwrap(),
                None
            );
            done_tx.send(()).unwrap();
            Ok(())
        });
        // Keep the sender live until receive completes; release it on timeout to bound a broken join.
        let watchdog = thread::spawn(move || {
            let completed = done_rx.recv_timeout(Duration::from_secs(5));
            drop(startup_tx);
            completed.expect("consensus startup did not stop before the deadline");
        });
        let shutdown = ConsensusShutdown {
            shutdown_token: token.clone(),
            handle: Some(handle),
            result: &mut result,
        };
        let launcher = async move {
            let _shutdown = shutdown;
            std::future::pending::<()>().await;
        };
        drop(launcher);
        assert!(token.is_cancelled());
        result.unwrap().unwrap();
        watchdog.join().unwrap();
    }

    #[test]
    fn consensus_shutdown_preserves_consensus_error() {
        let mut result = Ok(Ok(()));
        drop(ConsensusShutdown {
            shutdown_token: CancellationToken::new(),
            handle: Some(thread::spawn(|| eyre::bail!("genuine consensus failure"))),
            result: &mut result,
        });
        assert_eq!(
            result.unwrap().unwrap_err().to_string(),
            "genuine consensus failure"
        );
    }

    #[test]
    fn consensus_shutdown_preserves_consensus_panic() {
        let mut result = Ok(Ok(()));
        drop(ConsensusShutdown {
            shutdown_token: CancellationToken::new(),
            handle: Some(thread::spawn(|| panic!("genuine consensus panic"))),
            result: &mut result,
        });
        assert_eq!(
            *result.unwrap_err().downcast::<&str>().unwrap(),
            "genuine consensus panic"
        );
    }

    #[test]
    fn consensus_shutdown_preserves_execution_error() {
        let runner = CliRunner::try_default_runtime().unwrap();
        let token = CancellationToken::new();
        let mut consensus_result = Ok(Ok(()));
        let shutdown = ConsensusShutdown {
            shutdown_token: token.clone(),
            handle: Some(thread::spawn(|| eyre::bail!("secondary consensus failure"))),
            result: &mut consensus_result,
        };
        let result: eyre::Result<()> = runner.run_command_until_exit(|_ctx| async move {
            let _shutdown = shutdown;
            eyre::bail!("genuine execution failure")
        });
        assert_eq!(result.unwrap_err().to_string(), "genuine execution failure");
        assert!(token.is_cancelled());
        assert_eq!(
            consensus_result.unwrap().unwrap_err().to_string(),
            "secondary consensus failure"
        );
    }

    #[test]
    fn consensus_startup_preserves_closed_channel_error() {
        let (tx, rx) = oneshot::channel::<()>();
        drop(tx);
        let error = receive_consensus_startup(rx, &CancellationToken::new()).unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "channel closed before consensus-relevant command line args and a handle to the execution node could be received: channel closed"
        );
    }

    #[test]
    fn consensus_startup_receives_before_shutdown() {
        let (tx, rx) = oneshot::channel();
        tx.send(42).unwrap();
        assert_eq!(
            receive_consensus_startup(rx, &CancellationToken::new()).unwrap(),
            Some(42)
        );
    }

    #[test]
    #[cfg(unix)]
    fn consensus_shutdown_on_sigterm() {
        const CHILD_ENV: &str = "TEMPO_CONSENSUS_SHUTDOWN_SIGTERM_TEST";
        if std::env::var_os(CHILD_ENV).is_none() {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::consensus_shutdown_on_sigterm",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let (tx, rx) = mpsc::channel();
            let waiter = thread::spawn(move || tx.send(child.wait_with_output().unwrap()).unwrap());
            let output = match rx.recv_timeout(Duration::from_secs(20)) {
                Ok(output) => {
                    waiter.join().unwrap();
                    output
                }
                Err(error) => {
                    let killed = std::process::Command::new("kill")
                        .args(["-KILL", &pid.to_string()])
                        .status()
                        .unwrap();
                    waiter.join().unwrap();
                    assert!(killed.success());
                    panic!("SIGTERM shutdown test timed out: {error}");
                }
            };
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let runner = CliRunner::try_default_runtime().unwrap();
        let token = CancellationToken::new();
        let drained = Arc::new(AtomicBool::new(false));
        let mut consensus_result = Ok(Ok(()));
        let shutdown = ConsensusShutdown {
            shutdown_token: token.clone(),
            handle: Some(spawn_consensus_until_shutdown(
                token.clone(),
                drained.clone(),
            )),
            result: &mut consensus_result,
        };
        let (observed_tx, observed_rx) = mpsc::channel();
        let execution_result: eyre::Result<()> = runner.run_command_until_exit(|ctx| async move {
            let _shutdown = shutdown;
            ctx.task_executor
                .spawn_with_graceful_shutdown_signal(async move |exit| {
                    let _guard = exit.await;
                    observed_tx
                        .send((token.is_cancelled(), drained.load(Ordering::SeqCst)))
                        .unwrap();
                });
            // Reth registers its signal streams before polling the command.
            assert!(
                std::process::Command::new("kill")
                    .args(["-TERM", &std::process::id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            std::future::pending::<eyre::Result<()>>().await
        });
        execution_result.unwrap();
        consensus_result.unwrap().unwrap();
        assert_eq!(
            observed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            (true, true)
        );
    }

    fn init_defaults_once() {
        static INIT: Once = Once::new();
        INIT.call_once(defaults::init_defaults);
    }

    #[test]
    fn shadow_replay_is_opt_in_and_parses_candidate_hardfork() {
        let args = parse_node_args(&["tempo", "node", "--dev"]);
        assert_eq!(args.node_args.shadow_replay, None);

        let args = parse_node_args(&["tempo", "node", "--dev", "--shadow-replay"]);
        assert_eq!(args.node_args.shadow_replay, Some(None));

        for flag in ["--shadow-replay", "--shadow-replay.hardfork"] {
            let args = parse_node_args(&["tempo", "node", "--dev", flag, "T12"]);
            assert_eq!(args.node_args.shadow_replay, Some(Some(TempoHardfork::T12)));
        }
    }

    #[test]
    fn historical_shadow_replay_subcommand_parses() {
        let cli = TempoCli::try_parse_from([
            "tempo",
            "shadow-replay",
            "--from",
            "100",
            "--to",
            "200",
            "--hardfork",
            "T13",
            "--fail-on-findings",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Ext(crate::tempo_cmd::TempoSubcommand::ShadowReplay(_))
        ));
    }

    #[test]
    fn txpool_filter_defaults_empty_and_parses_address_list_or_file() {
        let cli = TempoCli::try_parse_from(["tempo", "node", "--dev"]).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(node_cmd.ext.node_args.txpool_filter.is_none());

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--txpool.filter",
            "0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        let filter = node_cmd.ext.node_args.txpool_filter.as_ref().unwrap();
        assert_eq!(filter.len(), 2);
        assert!(filter.contains(&Address::with_last_byte(1)));
        assert!(filter.contains(&Address::with_last_byte(2)));

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "0x0000000000000000000000000000000000000003\n\n\
             0x0000000000000000000000000000000000000004, \
             0x0000000000000000000000000000000000000005,\
             0x0000000000000000000000000000000000000003\n",
        )
        .unwrap();
        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--txpool.filter",
            file.path().to_str().unwrap(),
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        let filter = node_cmd.ext.node_args.txpool_filter.as_ref().unwrap();
        assert_eq!(filter.len(), 3);
        assert!(filter.contains(&Address::with_last_byte(3)));
        assert!(filter.contains(&Address::with_last_byte(4)));
        assert!(filter.contains(&Address::with_last_byte(5)));
    }

    #[test]
    fn txpool_filter_reports_invalid_file_entry() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "0x0000000000000000000000000000000000000001\nnot-an-address\n",
        )
        .unwrap();

        let error = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--txpool.filter",
            file.path().to_str().unwrap(),
        ])
        .unwrap_err()
        .to_string();

        assert!(error.contains(file.path().to_str().unwrap()));
        assert!(error.contains("invalid address `not-an-address` on line 2"));
    }

    fn parse_follow(args: &[&str]) -> Option<FollowMode> {
        parse_node_args(args).follow
    }

    fn parse_node_args(args: &[&str]) -> TempoArgs {
        let cli = TempoCli::try_parse_from(args).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        node_cmd.ext
    }

    fn apply_node_overrides(args: &[&str]) -> Arc<TempoChainSpec> {
        init_defaults_once();

        let mut cli = TempoCli::try_parse_from(args).unwrap();
        apply_tempo_cli_overrides(&mut cli).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        node_cmd.chain
    }

    fn assert_zone_factory_alloc(chain_spec: &TempoChainSpec, owner: Address) {
        let expected_factory = GenesisAccount {
            code: Some(Bytes::from_static(&[0xef])),
            storage: Some(BTreeMap::from([(
                B256::ZERO,
                B256::from(initial_zone_factory_config(owner)),
            )])),
            ..Default::default()
        };
        assert_eq!(
            chain_spec.genesis().alloc.get(&ZONE_FACTORY_ADDRESS),
            Some(&expected_factory)
        );

        for address in [
            ZONE_PORTAL_IMPL_ADDRESS,
            ZONE_VERIFIER_ADDRESS,
            ZONE_MESSENGER_ADDRESS,
        ] {
            assert_eq!(
                chain_spec.genesis().alloc.get(&address),
                super::DEV.genesis().alloc.get(&address),
                "dev mnemonic override must not modify shared Zone runtimes"
            );
        }
    }

    #[test]
    fn default_dev_mnemonic_owns_zone_factory_genesis_alloc() {
        let chain_spec = apply_node_overrides(&["tempo", "node", "--dev"]);

        assert_eq!(chain_spec.genesis_hash(), super::DEV.genesis_hash());
        assert_zone_factory_alloc(
            &chain_spec,
            address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        );
    }

    #[test]
    fn custom_dev_mnemonic_owns_zone_factory_genesis_alloc() {
        let chain_spec = apply_node_overrides(&[
            "tempo",
            "node",
            "--dev",
            "--dev.mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ]);

        assert_zone_factory_alloc(
            &chain_spec,
            address!("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        );
    }

    #[test]
    fn non_dev_chains_are_not_modified() {
        init_defaults_once();

        let mut cli =
            TempoCli::try_parse_from(["tempo", "node", "--dev", "--chain=mainnet"]).unwrap();
        let Commands::Node(node_cmd) = &cli.command else {
            panic!("expected node command");
        };
        let original_chain = node_cmd.chain.clone();

        apply_tempo_cli_overrides(&mut cli).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };

        assert_eq!(node_cmd.chain.genesis_hash(), original_chain.genesis_hash());
        assert_eq!(node_cmd.chain.genesis(), original_chain.genesis());
    }

    #[test]
    fn wrapped_download_matches_parse_for_tracing() {
        init_defaults_once();

        let matches = TempoCli::command()
            .mut_subcommand("download", |_| snapshot_download::Args::command())
            .try_get_matches_from([
                "tempo",
                "download",
                "--manifest-url",
                "https://snap/manifest.json",
                "--datadir",
                "/d",
                "--skip-consensus=false",
                "--log.stdout.filter",
                "debug",
            ])
            .unwrap();

        let cli = TempoCli::from_arg_matches(&matches).unwrap();

        assert!(matches!(cli.command, Commands::Download(_)));
        assert_eq!(cli.logs.log_stdout_filter, "debug");
    }

    #[test]
    fn follow_arg_parses_to_expected_mode() {
        init_defaults_once();

        assert_eq!(parse_follow(&["tempo", "node", "--dev"]), None);
        // `--follow` without a value falls back to the `auto` default.
        assert_eq!(
            parse_follow(&["tempo", "node", "--dev", "--follow"]),
            Some(FollowMode::Auto)
        );
        assert_eq!(
            parse_follow(&["tempo", "node", "--dev", "--follow", "auto"]),
            Some(FollowMode::Auto)
        );
        assert_eq!(
            parse_follow(&["tempo", "node", "--dev", "--follow", "ws://upstream:8546"]),
            Some(FollowMode::Url("ws://upstream:8546".to_string()))
        );
    }

    #[test]
    fn follow_certification_defaults() {
        init_defaults_once();

        let cli = TempoCli::try_parse_from(["tempo", "node", "--follow"]).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };

        assert!(!node_cmd.ext.is_following_uncertified());
        assert!(node_cmd.ext.has_consensus_engine(false));
    }

    #[test]
    fn debug_consensus_clients_rejected_with_consensus_engine() {
        init_defaults_once();

        let rejected = [
            // certified follow
            &[
                "tempo",
                "node",
                "--follow",
                "--debug.rpc-consensus-url",
                "ws://127.0.0.1:8546",
            ][..],
            &["tempo", "node", "--follow", "--debug.etherscan"],
            // validator mode
            &[
                "tempo",
                "node",
                "--consensus.signing-key",
                "unused-signing-key",
                "--debug.rpc-consensus-url",
                "ws://127.0.0.1:8546",
            ],
        ];
        for args in rejected {
            let cli = TempoCli::try_parse_from(args).unwrap();
            let err = ensure_no_debug_forkchoice_driver(&cli).unwrap_err();
            assert!(
                err.to_string()
                    .contains("only allowed with --dev or --follow.nocertify"),
                "{args:?}: {err}"
            );
        }
    }

    #[test]
    fn debug_consensus_clients_allowed_without_consensus_engine() {
        init_defaults_once();

        let allowed = [
            &[
                "tempo",
                "node",
                "--follow",
                "--follow.nocertify",
                "--debug.rpc-consensus-url",
                "ws://127.0.0.1:8546",
            ][..],
            &[
                "tempo",
                "node",
                "--dev",
                "--debug.rpc-consensus-url",
                "ws://127.0.0.1:8546",
            ],
            &["tempo", "node", "--follow"],
        ];
        for args in allowed {
            let cli = TempoCli::try_parse_from(args).unwrap();
            ensure_no_debug_forkchoice_driver(&cli).unwrap();
        }
    }

    #[test]
    fn consensus_subscription_limit_args() {
        init_defaults_once();

        let ext = |args: &[&str]| {
            let Commands::Node(node_cmd) = TempoCli::try_parse_from(args).unwrap().command else {
                panic!("expected node command");
            };
            node_cmd.ext
        };

        let defaults = ext(&["tempo", "node", "--dev"]);
        assert_eq!(defaults.consensus_max_subscriptions.get(), 256);
        assert_eq!(defaults.consensus_max_subscriptions_per_connection.get(), 4);

        let custom = ext(&[
            "tempo",
            "node",
            "--dev",
            "--rpc.consensus-max-subscriptions",
            "1024",
            "--rpc.consensus-max-subscriptions-per-connection",
            "8",
        ]);
        assert_eq!(custom.consensus_max_subscriptions.get(), 1024);
        assert_eq!(custom.consensus_max_subscriptions_per_connection.get(), 8);

        assert!(
            TempoCli::try_parse_from([
                "tempo",
                "node",
                "--dev",
                "--rpc.consensus-max-subscriptions",
                "0"
            ])
            .is_err()
        );
    }

    #[test]
    fn gossip_defaults_on_and_requires_a_consensus_engine() {
        init_defaults_once();

        assert!(
            parse_node_args(&[
                "tempo",
                "node",
                "--consensus.signing-key",
                "unused-signing-key",
            ])
            .has_gossip(false)
        );
        assert!(parse_node_args(&["tempo", "node", "--follow"]).has_gossip(false));
        assert!(
            parse_node_args(&[
                "tempo",
                "node",
                "--consensus.signing-key",
                "unused-signing-key",
                "--consensus.devp2p.finalizations",
            ])
            .has_gossip(false)
        );
        assert!(
            parse_node_args(&[
                "tempo",
                "node",
                "--follow",
                "--consensus.devp2p.finalizations",
            ])
            .has_gossip(false)
        );
        assert!(
            !parse_node_args(&[
                "tempo",
                "node",
                "--follow",
                "--follow.nocertify",
                "--consensus.devp2p.finalizations",
            ])
            .has_gossip(false)
        );
        assert!(
            !parse_node_args(&["tempo", "node", "--dev", "--consensus.devp2p.finalizations",])
                .has_gossip(true)
        );
        assert!(
            !parse_node_args(&[
                "tempo",
                "node",
                "--consensus.signing-key",
                "unused-signing-key",
                "--consensus.devp2p.finalizations=false",
            ])
            .has_gossip(false)
        );
    }

    #[test]
    fn gossip_ingest_follows_node_mode() {
        init_defaults_once();

        let validator = parse_node_args(&[
            "tempo",
            "node",
            "--consensus.signing-key",
            "unused-signing-key",
        ]);
        assert!(validator.has_gossip(false));
        assert!(!validator.consensus.gossip_transport(false).ingest);

        let follower = parse_node_args(&["tempo", "node", "--follow"]);
        assert!(follower.has_gossip(false));
        assert!(follower.consensus.gossip_transport(true).ingest);
    }

    #[test]
    fn follow_upstream_request_timeout_is_certified_follow_only() {
        init_defaults_once();

        assert!(
            TempoCli::try_parse_from([
                "tempo",
                "node",
                "--dev",
                "--follow.upstream-request-timeout",
                "750ms",
            ])
            .is_err()
        );
        assert!(
            TempoCli::try_parse_from([
                "tempo",
                "node",
                "--follow",
                "--follow.nocertify",
                "--follow.upstream-request-timeout",
                "750ms",
            ])
            .is_err()
        );

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--follow",
            "--follow.upstream-request-timeout",
            "750ms",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert_eq!(
            node_cmd.ext.follow_upstream_request_timeout.into_duration(),
            Duration::from_millis(750)
        );
    }

    #[test]
    fn follow_certification_disable() {
        init_defaults_once();

        let cli =
            TempoCli::try_parse_from(["tempo", "node", "--follow", "--follow.nocertify"]).unwrap();

        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };

        assert!(node_cmd.ext.is_following_uncertified());
        assert!(!node_cmd.ext.has_consensus_engine(false));
    }

    #[test]
    fn deprecated_follow_certification_flag_is_noop() {
        init_defaults_once();

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--follow",
            "--follow.experimental.certify",
        ])
        .unwrap();

        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };

        assert!(!node_cmd.ext.is_following_uncertified());
        assert!(node_cmd.ext.has_consensus_engine(false));
    }

    #[test]
    fn consensus_block_budget_defaults_are_stable() {
        init_defaults_once();

        let cli = TempoCli::try_parse_from(["tempo", "node", "--dev"]).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(node_cmd.engine.share_sparse_trie_with_payload_builder);
        assert!(
            !node_cmd
                .ext
                .node_args
                .engine_disable_execution_cache_sharing_with_builder
        );
        assert_eq!(node_cmd.builder.max_payload_tasks, 1);
        assert!(node_cmd.ext.node_args.builder_disable_prewarming);
        assert!(node_cmd.ext.node_args.builder_enable_prewarming);
        assert!(!node_cmd.ext.node_args.builder_parallel);
        assert_eq!(
            node_cmd.ext.consensus.target_block_time.into_duration(),
            Duration::from_millis(550)
        );
        assert_eq!(
            node_cmd.ext.consensus.wait_for_proposal.into_duration(),
            Duration::from_millis(1200)
        );
        assert_eq!(
            node_cmd.ext.consensus.network_budget.into_duration(),
            Duration::from_millis(50)
        );
        assert_eq!(
            node_cmd.ext.node_args.builder_build_time_multiplier,
            tempo_node::estimator::BuildTimeMultiplier::default()
        );

        let mut cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--engine.disable-execution-cache-sharing-with-builder",
        ])
        .unwrap();
        apply_tempo_cli_overrides(&mut cli).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(
            node_cmd
                .ext
                .node_args
                .engine_disable_execution_cache_sharing_with_builder
        );
        assert!(!node_cmd.engine.share_execution_cache_with_payload_builder);

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--engine.share-sparse-trie-with-payload-builder",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert_eq!(
            node_cmd.ext.consensus.target_block_time.into_duration(),
            Duration::from_millis(550)
        );
        assert_eq!(
            node_cmd.ext.consensus.wait_for_proposal.into_duration(),
            Duration::from_millis(1200)
        );
        assert_eq!(
            node_cmd.ext.consensus.network_budget.into_duration(),
            Duration::from_millis(50)
        );

        let cli =
            TempoCli::try_parse_from(["tempo", "node", "--dev", "--builder.disable-prewarming"])
                .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(node_cmd.ext.node_args.builder_disable_prewarming);

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--builder.disable-prewarming=false",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(!node_cmd.ext.node_args.builder_disable_prewarming);
        assert!(
            node_cmd
                .ext
                .node_args
                .payload_builder_builder()
                .enable_prewarming
        );

        let cli =
            TempoCli::try_parse_from(["tempo", "node", "--dev", "--builder.parallel"]).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(node_cmd.ext.node_args.builder_parallel);
        assert!(
            node_cmd
                .ext
                .node_args
                .payload_builder_builder()
                .enable_parallel
        );

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--builder.enable-prewarming",
            "--builder.disable-prewarming",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(node_cmd.ext.node_args.builder_enable_prewarming);
        assert!(node_cmd.ext.node_args.builder_disable_prewarming);
        assert!(
            !node_cmd
                .ext
                .node_args
                .payload_builder_builder()
                .enable_prewarming
        );
    }

    #[test]
    fn parses_jit_args() {
        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--jit",
            "--jit.hot-threshold",
            "8",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        assert!(node_cmd.jit.enabled);
        assert_eq!(node_cmd.jit.hot_threshold, 8);
    }
}
