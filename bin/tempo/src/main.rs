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
use eyre::WrapErr as _;
use reth_ethereum::{cli::Commands, evm::revm::primitives::B256};
use reth_ethereum_cli::Cli;
use reth_node_builder::{NodeHandle, WithLaunchContext};
use reth_rpc_server_types::DefaultRpcModuleValidator;
use std::sync::Arc;
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_commonware_node::{
    ConsensusDeadSignal, ConsensusNodeBuilder, ConsensusNodeHandle, ExecutionNodeInput,
    feed as consensus_feed,
};
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, TempoEvmFactory};
use tempo_faucet::{
    args::FaucetArgs,
    faucet::{TempoFaucetExt, TempoFaucetExtApiServer},
};
use tempo_node::{
    TempoNodeArgs,
    node::TempoNode,
    rpc::consensus::{TempoConsensusApiServer, TempoConsensusRpc},
};
use tokio::sync::oneshot;

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

    let cli = Cli::<
        TempoChainSpecParser,
        TempoArgs,
        DefaultRpcModuleValidator,
        tempo_cmd::TempoSubcommand,
    >::parse();
    let is_node = matches!(cli.command, Commands::Node(_));

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let cl_feed_state = consensus_feed::FeedStateHandle::new();

    // Spawn consensus node (it will wait for execution node input internally)
    let (execution_input_tx, execution_input_rx) = oneshot::channel::<ExecutionNodeInput>();

    // Spawn consensus node and extract the dead signal for use in async code
    let (consensus_handle, consensus_dead_signal): (
        Option<ConsensusNodeHandle>,
        Option<ConsensusDeadSignal>,
    ) = if is_node {
        // Extract consensus args from CLI for the builder
        // We need to parse again to get the args before running
        let cli_for_args = Cli::<
            TempoChainSpecParser,
            TempoArgs,
            DefaultRpcModuleValidator,
            tempo_cmd::TempoSubcommand,
        >::parse();

        let consensus_args = match &cli_for_args.command {
            Commands::Node(node_cmd) => node_cmd.ext.consensus.clone(),
            _ => unreachable!("is_node check ensures this is a Node command"),
        };

        let mut handle = ConsensusNodeBuilder::default()
            .with_args(consensus_args)
            .with_execution_node_receiver(execution_input_rx)
            .with_feed_state(cl_feed_state.clone())
            .with_shutdown_token(shutdown_token.clone())
            .build()
            .wrap_err("failed to build consensus node")?
            .spawn();

        let dead_signal = handle.take_dead_signal();
        (Some(handle), dead_signal)
    } else {
        (None, None)
    };

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

        let is_dev_mode = builder.config().dev.dev;
        let skip_consensus = args.follow.is_some();
        let storage_dir_override = args.consensus.storage_dir.clone();

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

        // Send execution node input to consensus (consensus will handle all logic internally)
        let _ = execution_input_tx.send(ExecutionNodeInput {
            node,
            is_dev_mode,
            skip_consensus,
            storage_dir_override,
        });

        // Wait for shutdown
        tokio::select! {
            _ = node_exit_future => {
                tracing::info!("execution node exited");
            }
            _ = async {
                if let Some(signal) = consensus_dead_signal {
                    signal.wait().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
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

    // Wait for consensus node to complete
    if let Some(handle) = consensus_handle {
        if let Err(err) = handle.join() {
            eprintln!("consensus node exited with error:\n{err:?}");
        }
    }

    Ok(())
}
