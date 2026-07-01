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

pub mod cli;
mod defaults;
mod follow;
pub mod init_state;
mod overrides;
pub mod p2p_proxy;
pub mod regenesis;
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

use crate::utils::{
    block_on_consensus_public_key, fetch_bootnodes, install_crypto_provider,
    print_extensions_footer,
};
use clap::{CommandFactory, FromArgMatches};
use commonware_runtime::{Metrics, Runner};
use eyre::{OptionExt, WrapErr as _};
use futures::{
    FutureExt as _,
    future::{Either, FusedFuture as _},
};
use reth_cli_runner::CliRunner;
use reth_ethereum::{chainspec::EthChainSpec as _, cli::Commands, evm::revm::primitives::B256};
use reth_network_api::Peers;
use reth_node_builder::{NodeHandle, WithLaunchContext};
use std::{sync::Arc, thread};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_consensus::{feed as consensus_feed, run_consensus_stack, run_follow_stack};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_faucet::faucet::{TempoFaucetExt, TempoFaucetExtApiServer};
pub use tempo_node::{
    AccountInfoReader, InvalidPoolTransactionError, PoolTransaction, PoolTransactionError,
    StatefulValidationFn, StatelessValidationFn, TempoNode, TempoNodeArgs,
    TempoPayloadBuilderBuilder, TempoPoolBuilder, TempoPoolTransactionError,
    TempoPooledTransaction, TransactionOrigin,
};
use tempo_node::{
    TempoFullNode,
    rpc::consensus::{TempoConsensusApiServer, TempoConsensusRpc},
    telemetry::{PrometheusMetricsConfig, install_prometheus_metrics},
};
use tokio::sync::oneshot;
use tracing::{debug, info, info_span, warn, warn_span};

fn apply_tempo_cli_overrides(cli: &mut TempoCli) {
    if let Commands::Node(node_cmd) = &mut cli.command
        && node_cmd
            .ext
            .node_args
            .engine_disable_execution_cache_sharing_with_builder
    {
        node_cmd.engine.share_execution_cache_with_payload_builder = false;
    }
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

    apply_tempo_cli_overrides(&mut cli);

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

        if !args.has_consensus_engine(node.config.dev.dev) {
            return futures::executor::block_on(async move {
                shutdown_token_clone.cancelled().await;
                Ok(())
            });
        }

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
        let ret = runner.start(async move |ctx| {
            let mut metrics_server = tempo_consensus::metrics::install(
                ctx.with_label("metrics"),
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

                install_prometheus_metrics(ctx.with_label("telemetry_metrics"), prometheus_config)
                    .wrap_err("failed to start Prometheus metrics exporter")?;
            }

            let consensus_stack = if let Some(follow) = args.follow {
                let follow_url = follow
                    .resolve_url(&node.chain_spec())
                    .ok_or_eyre("No default follow URL for this chain")?;

                Either::Left(run_follow_stack(
                    ctx.with_label("follow"),
                    args.consensus,
                    follow_url,
                    Arc::new(node),
                    cl_feed_state_clone,
                ))
            } else {
                Either::Right(run_consensus_stack(
                    ctx.with_label("consensus"),
                    args.consensus,
                    Arc::new(node),
                    cl_feed_state_clone,
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

    let components =
        |spec: Arc<TempoChainSpec>| (TempoEvmConfig::new(spec.clone()), TempoConsensus::new(spec));

    cli.run_with_components::<TempoNode>(components, async move |builder, args| {
        let faucet_args = args.faucet_args.clone();
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
        let chain_id = builder.config().chain.chain().id();

        // Resolve the bootnodes endpoint:
        // --tempo.bootnodes-endpoint=none -> disabled
        // otherwise -> use the provided/default URL
        let bootnodes_endpoint = match args.bootnodes_endpoint.trim() {
            value if value.eq_ignore_ascii_case("none") => None,
            url => Some(url.to_string()),
        };

        let NodeHandle {
            node,
            node_exit_future,
        } = builder
            .node(overrides.apply_tempo_node(TempoNode::new(
                &args.node_args,
                validator_key,
            )))
            .apply(|mut builder: WithLaunchContext<_>| {
                // Enable discv5 peer discovery
                builder
                    .config_mut()
                    .network
                    .discovery
                    .enable_discv5_discovery = true;

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
                        let consensus_rpc = TempoConsensusRpc::new(cl_feed_state);
                        ctx.modules.merge_configured(consensus_rpc.into_rpc())
                            .wrap_err("failed to register consensus rpc module")?;
                    }

                    Ok(())
                })
            })
            .launch_with_debug_capabilities()
            .await
            .wrap_err("failed launching execution node")?;

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

#[cfg(test)]
mod tests {
    use std::{sync::Once, time::Duration};

    use clap::{CommandFactory, FromArgMatches, Parser};

    use super::{
        TempoCli, apply_tempo_cli_overrides, defaults, follow::FollowMode, snapshot_download,
    };
    use reth_ethereum::cli::Commands;

    fn init_defaults_once() {
        static INIT: Once = Once::new();
        INIT.call_once(defaults::init_defaults);
    }

    fn parse_follow(args: &[&str]) -> Option<FollowMode> {
        let cli = TempoCli::try_parse_from(args).unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };
        node_cmd.ext.follow
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
        assert!(!node_cmd.ext.node_args.builder_disable_prewarming);
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
        assert_eq!(node_cmd.ext.node_args.builder_build_time_multiplier, 1.35);

        let mut cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--engine.disable-execution-cache-sharing-with-builder",
        ])
        .unwrap();
        apply_tempo_cli_overrides(&mut cli);
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
}
