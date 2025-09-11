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
use reth_node_ethereum::EthEvmConfig;
use std::{future, sync::Arc, thread};
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_commonware_node::cli::launch_consensus_stack;
use tempo_consensus::TempoConsensus;
use tempo_faucet::faucet::{TempoFaucetExt, TempoFaucetExtApiServer};
use tempo_node::{TempoFullNode, args::TempoArgs, node::TempoNode};
use tokio::sync::oneshot;
use tracing::info;

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

fn main() {
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

    let components =
        |spec: Arc<TempoChainSpec>| (EthEvmConfig::new(spec.clone()), TempoConsensus::new(spec));

    let (node_tx, node_rx) = oneshot::channel::<(TempoFullNode, TempoCommonwareArgs)>();
    let (consensus_tx, consensus_rx) = oneshot::channel();

    let setup_consenus = thread::spawn(move || {
        let Ok((node, args)) = node_rx.blocking_recv() else {
            return Ok(());
        };

        let consensus_handle = if node.config.dev.dev || args.inner.no_consensus {
            tokio::spawn(async move { future::pending::<()>().await })
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
                launch_consensus_stack(&ctx, &consensus_config, node).await
            })?
        };

        let _ = consensus_tx.send(consensus_handle);

        eyre::Ok(())
    });

    if let Err(err) = Cli::<TempoChainSpecParser, TempoCommonwareArgs>::parse()
        .run_with_components::<TempoNode>(components, async move |builder, args| {
            let faucet_args = args.inner.faucet_args.clone();
            info!(target: "reth::cli", "Launching node");
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
                .apply(|mut ctx| {
                    let db = ctx.db_mut();
                    db.create_tables_for::<reth_malachite::store::tables::Tables>()
                        .expect("Failed to create consensus tables");
                    ctx
                })
                .launch_with_debug_capabilities()
                .await?;

            let _ = node_tx.send((node, args));
            let consensus_handle = consensus_rx.await?;

            tokio::select! {
                _ = node_exit_future => {
                    tracing::info!("Reth node exited");
                }
                _ = consensus_handle => {
                    tracing::info!("Consensus engine exited");
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received shutdown signal");
                }
            }

            Ok(())
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }

    setup_consenus.join().unwrap().unwrap();
}
