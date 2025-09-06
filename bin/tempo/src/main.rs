//! Main executable for the Reth-Malachite node.
//!
//! This binary launches a blockchain node that combines:
//! - Reth's execution layer for transaction processing and state management
//! - Malachite's BFT consensus engine for block agreement
//!
//! The node operates by:
//! 1. Starting the Reth node infrastructure (database, networking, RPC)
//! 2. Creating the application state that bridges Reth and Malachite
//! 3. Launching the Malachite consensus engine
//! 4. Running both components until shutdown
//!
//! Configuration can be provided via command-line arguments or configuration files.

use clap::Parser;
use reth_ethereum::{chainspec::EthChainSpec, cli::Cli};
use reth_malachite::{
    MalachiteConsensus,
    app::{Config, Genesis, State, ValidatorInfo},
    cli::MalachiteArgs,
    consensus::{EngineConfig, start_consensus_engine},
    context::MalachiteContext,
    types::Address,
};
use reth_node_builder::{
    FullNode, FullNodeComponents, FullNodeTypes, NodeHandle, NodeTypes, PayloadTypes,
    rpc::RethRpcAddOns,
};
use reth_node_ethereum::EthEvmConfig;
use reth_provider::DatabaseProviderFactory;
use std::{fs, future, sync::Arc};
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
            MalachiteConsensus::new(spec),
        )
    };

    if let Err(err) = Cli::<TempoChainSpecParser, TempoArgs>::parse()
        .run_with_components::<TempoNode>(components, async move |builder, args| {
            info!(target: "reth::cli", "Launching node");
            let NodeHandle {
                node,
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
                .apply(|mut ctx| {
                    let db = ctx.db_mut();
                    db.create_tables_for::<reth_malachite::store::tables::Tables>()
                        .expect("Failed to create consensus tables");
                    ctx
                })
                .launch_with_debug_capabilities()
                .await?;

            let malachite_handle = if node.config.dev.dev || args.no_consensus {
                tokio::spawn(async move { future::pending::<()>().await })
            } else {
                spawn_malachite(node.clone(), args.malachite_args)
                    .await?
                    .app
            };

            tokio::select! {
                _ = node_exit_future => {
                    tracing::info!("Reth node exited");
                }
                _ = malachite_handle => {
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
}

/// Spawns malachite consensus
async fn spawn_malachite<N, A>(
    node: FullNode<N, A>,
    args: MalachiteArgs,
) -> eyre::Result<reth_malachite::consensus::AppHandle>
where
    N: FullNodeComponents,
    N::Types: NodeTypes,
    <N::Types as NodeTypes>::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = alloy_rpc_types_engine::ExecutionData,
            BuiltPayload = reth_ethereum_engine_primitives::EthBuiltPayload,
        >,
    A: RethRpcAddOns<N>,
    <<N as FullNodeTypes>::Provider as DatabaseProviderFactory>::ProviderRW: Send,
{
    let ctx = MalachiteContext::default();
    let config = if args.consensus_config.is_some() && args.config_file().exists() {
        tracing::info!("Loading config from: {:?}", args.config_file());
        reth_malachite::app::config_loader::load_config(&args.config_file())?
    } else {
        Config::new()
    };

    let mut genesis = if args.genesis.is_some() && args.genesis_file().exists() {
        tracing::info!("Loading genesis from: {:?}", args.genesis_file());
        reth_malachite::app::config_loader::load_genesis(&args.genesis_file())?
    } else {
        // Create a default genesis with initial validators
        let validator_address = Address::new([1; 20]);
        let validator_info = ValidatorInfo::new(validator_address, 1000, vec![0; 32]);
        Genesis::new(args.chain_id()).with_validators(vec![validator_info])
    };

    let (address, _validator_pubkey, validator_privkey) =
        if args.validator_key.is_some() && args.validator_key_file().exists() {
            tracing::info!(
                "Loading validator key from: {:?}",
                args.validator_key_file()
            );
            let (addr, pubkey, privkey) =
                reth_malachite::app::config_loader::load_validator_key(&args.validator_key_file())?;
            tracing::info!("Loaded validator address: {:?}", addr);
            (addr, Some(pubkey), Some(privkey))
        } else {
            tracing::warn!("No validator key provided, node will run in non-validator mode");
            (Address::new([0; 20]), None, None)
        };

    let app_handle = node.add_ons_handle.beacon_engine_handle.clone();
    let payload_builder_handle = node.payload_builder_handle.clone();
    let provider = node.provider.clone();
    let chain_spec = node.chain_spec();
    genesis.genesis_hash = chain_spec.genesis_hash();

    let signing_provider = if let Some(privkey) = validator_privkey {
        match reth_malachite::provider::Ed25519Provider::from_bytes(&privkey) {
            Ok(provider) => {
                tracing::info!("Created signing provider for validator");
                Some(provider)
            }
            Err(e) => {
                tracing::error!("Failed to create signing provider: {}", e);
                None
            }
        }
    } else {
        None
    };

    let state: State<N::Types> = State::from_provider(
        ctx.clone(),
        config,
        genesis.clone(),
        address,
        Arc::new(provider),
        app_handle,
        payload_builder_handle,
        signing_provider,
    )
    .await?;

    tracing::info!("Application state created successfully");

    let home_dir = args.home_dir();
    fs::create_dir_all(&home_dir)?;
    fs::create_dir_all(home_dir.join("config"))?;
    fs::create_dir_all(home_dir.join("data"))?;

    let config_file_path = args.config_file();
    tracing::info!("Checking for Malachite config at: {:?}", config_file_path);

    let engine_config = if config_file_path.exists() {
        tracing::info!("Loading Malachite config from: {:?}", config_file_path);
        reth_malachite::consensus::config_loader::load_engine_config(
            &config_file_path,
            args.chain_id(),
            args.node_id(),
        )?
    } else {
        EngineConfig::new(args.chain_id(), args.node_id(), "127.0.0.1:26657".parse()?)
    };

    tracing::info!(
        "Starting Malachite consensus engine with chain_id={}, node_id={}, home_dir={:?}",
        args.chain_id(),
        args.node_id(),
        home_dir
    );

    let app_handle = start_consensus_engine(state, engine_config, home_dir).await?;

    Ok(app_handle)
}
