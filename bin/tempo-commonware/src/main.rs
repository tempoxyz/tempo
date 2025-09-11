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
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use clap::Parser;
use commonware_runtime::Runner;
use eyre::Context;
use reth_ethereum::cli::Cli;
use reth_node_builder::NodeHandle;
use std::{sync::Arc, thread};
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_commonware_node::run_consensus_stack;
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, TempoEvmFactory};
use tempo_faucet::faucet::{TempoFaucetExt, TempoFaucetExtApiServer};
use tempo_node::{TempoFullNode, args::TempoArgs, node::TempoNode};
use tokio::sync::oneshot;

/// Extra arguments for `tempo-commonware`.
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct TempoCommonwareArgs {
    /// Inner [`TempoArgs`].
    #[command(flatten)]
    pub inner: TempoArgs,
    /// Commonware configuration path.
    #[clap(long, value_name = "FILE")]
    pub consensus_config: camino::Utf8PathBuf,
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

    let (args_and_node_handle_tx, args_and_node_handle_rx) =
        oneshot::channel::<(TempoFullNode, TempoCommonwareArgs)>();
    let (consensus_dead_tx, consensus_dead_rx) = oneshot::channel();
    let consensus_dead_rx = Arc::new(consensus_dead_rx);

    let shutdown_token = tokio_util::sync::CancellationToken::new();

    let shutdown_token_clone = shutdown_token.clone();
    let consensus_handle = thread::spawn(move || {
        let (node, args) = args_and_node_handle_rx.blocking_recv().wrap_err("channel closed before consensus-relevant command line args and a handle to the execution node could be received")?;

        let ret = if node.config.dev.dev || args.inner.no_consensus {
            futures::executor::block_on(async move {
                shutdown_token_clone.cancelled().await;
                Ok(())
            })
        } else {
            let consensus_config =
                tempo_commonware_node_config::Config::from_file(&args.consensus_config)
                    .wrap_err_with(|| {
                        format!(
                            "failed parsing consensus config from provided argument `{}`",
                            args.consensus_config,
                        )
                    })?;
            let runtime_config = commonware_runtime::tokio::Config::default()
                .with_tcp_nodelay(Some(true))
                .with_worker_threads(consensus_config.worker_threads)
                .with_storage_directory(&consensus_config.storage_directory)
                .with_catch_panics(true);

            let runner = commonware_runtime::tokio::Runner::new(runtime_config);

            runner.start(async move |ctx| {
                tokio::select!(
                    ret = run_consensus_stack(&ctx, &consensus_config, node) => {
                        ret.and_then(|()| Err(eyre::eyre!("consensus stack exited unexpectedly")))
                        .wrap_err("consensus stack failed")
                    }
                    () = shutdown_token_clone.cancelled() => {
                        Ok(())
                    }
                )
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

    let mut consensus_read_rx_clone = consensus_dead_rx.clone();
    Cli::<TempoChainSpecParser, TempoCommonwareArgs>::parse()
        .run_with_components::<TempoNode>(components, async move |builder, args| {
            let faucet_args = args.inner.faucet_args.clone();

            let NodeHandle {
                node,
                node_exit_future,
            } = builder
                .node(TempoNode::new(args.inner.clone()))
                .extend_rpc_modules(move |ctx| {
                    if faucet_args.enabled {
                        let txpool = ctx.pool().clone();
                        let ext = TempoFaucetExt::new(
                            txpool,
                            faucet_args.address(),
                            faucet_args.amount(),
                            faucet_args.provider(),
                        );

                        ctx.modules.merge_configured(ext.into_rpc())?;
                    }

                    Ok(())
                })
                // TODO: commented out for now; this can probably go entirely.
                // .apply(|mut ctx| {
                //     let db = ctx.db_mut();
                //     db.create_tables_for::<reth_malachite::store::tables::Tables>()
                //         .expect("Failed to create consensus tables");
                //     ctx
                // })
                .launch_with_debug_capabilities()
                .await
                .wrap_err("failed launching execution node")?;

            let _ = args_and_node_handle_tx.send((node, args));

            // TODO: emit these inside a span
            tokio::select! {
                _ = node_exit_future => {
                    tracing::info!("execution node exited");
                }
                _ = Arc::get_mut(&mut consensus_read_rx_clone)
                    .expect("the dead man switch is only held here and after this future/function completes")
                => {
                    tracing::info!("consensus node exited");
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received shutdown signal");
                }
            }
            shutdown_token.cancel();

            Ok(())
        })
        .wrap_err("execution node failed")?;

    // XXX: join the thread only if consensus is actually dead. We don't
    // want to block this function from exiting
    if consensus_dead_rx.is_terminated() {
        match consensus_handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("consensus task exited with error:\n{err:?}"),
            Err(unwind) => std::panic::resume_unwind(unwind),
        }
    }
    Ok(())
}
