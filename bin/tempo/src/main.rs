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

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

mod defaults;
mod tempo_cmd;

use clap::Parser;
use commonware_runtime::{Metrics, Runner};
use eyre::WrapErr as _;
use futures::{FutureExt as _, future::FusedFuture as _};
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    cli::{Cli, Commands},
    evm::revm::primitives::B256,
};
use reth_ethereum_cli as _;
use reth_node_builder::{NodeHandle, WithLaunchContext};
use std::{sync::Arc, thread};
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_commonware_node::{feed as consensus_feed, run_consensus_stack};
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, TempoEvmFactory};
use tempo_faucet::{
    args::FaucetArgs,
    faucet::{TempoFaucetExt, TempoFaucetExtApiServer},
};
use tempo_node::{
    TempoFullNode, TempoNodeArgs,
    node::TempoNode,
    rpc::consensus::{TempoConsensusApiServer, TempoConsensusRpc},
};
use tokio::sync::oneshot;
use tracing::{info, info_span};

// TODO: migrate this to tempo_node eventually.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
struct TempoArgs {
    /// Follow this specific RPC node for block hashes.
    /// If provided without a value, defaults to the RPC URL for the selected chain.
    #[arg(long, value_name = "URL", default_missing_value = "auto", num_args(0..=1))]
    pub follow: Option<String>,

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

fn main() -> eyre::Result<()> {
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

    if let Some(result) = tempo_cmd::try_run_tempo_subcommand() {
        return result;
    }

    let cli = Cli::<TempoChainSpecParser, TempoArgs>::parse();
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
            let consensus_storage = &node
                .config
                .datadir
                .clone()
                .resolve_datadir(node.chain_spec().chain())
                .data_dir()
                .join("consensus");
            let runtime_config = commonware_runtime::tokio::Config::default()
                .with_tcp_nodelay(Some(true))
                .with_worker_threads(args.consensus.worker_threads)
                .with_storage_directory(consensus_storage)
                .with_catch_panics(true);

            info_span!("prepare_consensus").in_scope(|| {
                info!(
                    path = %consensus_storage.display(),
                    "determined directory for consensus data",
                )
            });

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

    let components = |spec: Arc<TempoChainSpec>| {
        (
            TempoEvmConfig::new(spec.clone(), TempoEvmFactory::default()),
            TempoConsensus::new(spec),
        )
    };

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

        let NodeHandle {
            node,
            node_exit_future,
        } = builder
            .node(TempoNode::new(&args.node_args, validator_key))
            .apply(|mut builder: WithLaunchContext<_>| {
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
