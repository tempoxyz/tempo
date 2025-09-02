//! Main executable for the Tempo node.

use clap::Parser;
use reth_ethereum::{cli::Cli, consensus::EthBeaconConsensus};
use reth_node_builder::NodeHandle;
use reth_node_ethereum::EthEvmConfig;
use std::sync::Arc;
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_faucet::faucet::{TempoFaucetExt, TempoFaucetExtApiServer};
use tempo_node::{args::TempoArgs, node::TempoNode};
use tracing::info;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let components = |spec: Arc<TempoChainSpec>| {
        (
            EthEvmConfig::new(spec.clone()),
            EthBeaconConsensus::new(spec),
        )
    };

    if let Err(err) = Cli::<TempoChainSpecParser, TempoArgs>::parse()
        .run_with_components::<TempoNode>(components, async move |builder, args| {
            info!(target: "reth::cli", "Launching node");
            let NodeHandle {
                node: _,
                node_exit_future,
            } = builder
                .node(TempoNode::new(args.clone()))
                .extend_rpc_modules(move |ctx| {
                    if args.faucet_args.enabled {
                        let txpool = ctx.pool().clone();
                        let ext = TempoFaucetExt::new(
                            txpool,
                            args.faucet_args.address(),
                            args.faucet_args.amount(),
                            args.faucet_args.provider(),
                        );

                        ctx.modules.merge_configured(ext.into_rpc())?;
                    }

                    Ok(())
                })
                .launch_with_debug_capabilities()
                .await?;

            tokio::select! {
                _ = node_exit_future => {
                    tracing::info!("Reth node exited");
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
}
