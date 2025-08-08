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
use reth::{args::RessArgs, chainspec::EthereumChainSpecParser, ress::install_ress_subprotocol};
use reth_malachite::{
    app::{Config, Genesis, State, ValidatorInfo},
    cli::{Cli, MalachiteArgs, MalachiteChainSpecParser},
    consensus::{EngineConfig, start_consensus_engine},
    context::MalachiteContext,
    store::tables::Tables,
    types::Address,
};
use reth_node_builder::NodeHandle;
use std::{fs, sync::Arc};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_node::{args::TempoArgs, node::TempoNode};
use tracing::info;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) =
        Cli::<TempoChainSpecParser, TempoArgs>::parse().run(async move |builder, tempo_args| {
            info!(target: "reth::cli", "Launching node");
            let NodeHandle {
                node,
                node_exit_future,
            } = builder
                .node(TempoNode::new(tempo_args.clone()))
                .launch_with_debug_capabilities()
                .await?;

            // Install ress subprotocol.
            if tempo_args.ress_args.enabled {
                install_ress_subprotocol(
                    tempo_args.ress_args,
                    node.provider,
                    node.evm_config,
                    node.network,
                    node.task_executor,
                    node.add_ons_handle.engine_events.new_listener(),
                )?;
            }

            node_exit_future.await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

// fn main() -> eyre::Result<()> {
//     reth_cli_util::sigsegv_handler::install();
//
//     Cli::<MalachiteChainSpecParser, MalachiteArgs>::parse().run(
//         |builder, args: MalachiteArgs| async move {
//
//         // NOTE: something context here
//
//             // Create the context
//             let ctx = MalachiteContext::default();
//
//             // Load configuration from file if provided, otherwise use defaults
//             let config = if args.consensus_config.is_some() && args.config_file().exists() {
//                 tracing::info!("Loading config from: {:?}", args.config_file());
//                 reth_malachite::app::config_loader::load_config(&args.config_file())?
//             } else {
//                 Config::new()
//             };
//
//
//              // NOTE: this is doing something with genesis or building some new validator info?
//
//             // Load genesis from file if provided, otherwise use default
//             let mut genesis = if args.genesis.is_some() && args.genesis_file().exists() {
//                 tracing::info!("Loading genesis from: {:?}", args.genesis_file());
//                 reth_malachite::app::config_loader::load_genesis(&args.genesis_file())?
//             } else {
//                 // Create a default genesis with initial validators
//                 let validator_address = Address::new([1; 20]);
//                 let validator_info = ValidatorInfo::new(validator_address, 1000, vec![0; 32]);
//                 Genesis::new(args.chain_id()).with_validators(vec![validator_info])
//             };
//
//              // NOTE: this is probably just going to be part of the consensus builder
//
//             // Load validator key to derive node address if provided
//             let (address, _validator_pubkey, validator_privkey) = if args.validator_key.is_some()
//                 && args.validator_key_file().exists()
//             {
//                 tracing::info!(
//                     "Loading validator key from: {:?}",
//                     args.validator_key_file()
//                 );
//                 let (addr, pubkey, privkey) =
//                     reth_malachite::app::config_loader::load_validator_key(
//                         &args.validator_key_file(),
//                     )?;
//                 tracing::info!("Loaded validator address: {:?}", addr);
//                 (addr, Some(pubkey), Some(privkey))
//             } else {
//                 tracing::warn!("No validator key provided, node will run in non-validator mode");
//                 (Address::new([0; 20]), None, None)
//             };
//
//      NOTE:: this also creating some table for consensus. again probably part of the consensus
//      builder
//
//
//             // Launch the Reth node first to get the engine handle
//             let NodeHandle {
//                 node,
//                 node_exit_future,
//             } = builder
//                 .node(TempoNode::default())
//                 .apply(|mut ctx| {
//                     // Access the database before launch to create tables
//                     let db = ctx.db_mut();
//                     if let Err(e) = db.create_tables_for::<Tables>() {
//                         tracing::error!("Failed to create consensus tables: {:?}", e);
//                     } else {
//                         tracing::info!("Created consensus tables successfully");
//                     }
//                     ctx
//                 })
//                 .launch()
//                 .await?;
//
//              NOTE: something about getting all the handles
//
//
//             // Get the beacon engine handle
//             let app_handle = node.add_ons_handle.beacon_engine_handle.clone();
//
//             // Get the payload builder handle
//             let payload_builder_handle = node.payload_builder_handle.clone();
//
//             // Get the provider from the node
//             let provider = node.provider.clone();
//
//             // Get the chain spec to extract genesis hash
//             let chain_spec = node.chain_spec();
//
//             // Update genesis with the actual genesis hash from chain spec
//             genesis.genesis_hash = chain_spec.genesis_hash();
//
//             // Create the signing provider if we have a validator key
//             let signing_provider = if let Some(privkey) = validator_privkey {
//                 match reth_malachite::provider::Ed25519Provider::from_bytes(&privkey) {
//                     Ok(provider) => {
//                         tracing::info!("Created signing provider for validator");
//                         Some(provider)
//                     }
//                     Err(e) => {
//                         tracing::error!("Failed to create signing provider: {}", e);
//                         None
//                     }
//                 }
//             } else {
//                 None
//             };
//
//             // Create the application state using the factory method
//             // This encapsulates Store creation and verification
//             let state = State::from_provider(
//                 ctx.clone(),
//                 config,
//                 genesis.clone(),
//                 address,
//                 Arc::new(provider),
//                 app_handle,
//                 payload_builder_handle,
//                 signing_provider,
//             )
//             .await?;
//
//             tracing::info!("Application state created successfully");
//
//             // Get the home directory from args
//             let home_dir = args.home_dir();
//
//             // Create necessary directories
//             fs::create_dir_all(&home_dir)?;
//             fs::create_dir_all(home_dir.join("config"))?;
//             fs::create_dir_all(home_dir.join("data"))?;
//
//             // Create Malachite consensus engine configuration
//             let config_file_path = args.config_file();
//             tracing::info!("Checking for Malachite config at: {:?}", config_file_path);
//
//
//
//              // NOTE: something about engine config
//
//             let engine_config = if config_file_path.exists() {
//                 tracing::info!("Loading Malachite config from: {:?}", config_file_path);
//                 // Load from config file
//                 reth_malachite::consensus::config_loader::load_engine_config(
//                     &config_file_path,
//                     args.chain_id(),
//                     args.node_id(),
//                 )?
//             } else {
//                 // Use defaults
//                 EngineConfig::new(args.chain_id(), args.node_id(), "127.0.0.1:26657".parse()?)
//             };
//
//             tracing::info!(
//                 "Starting Malachite consensus engine with chain_id={}, node_id={}, home_dir={:?}",
//                 args.chain_id(),
//                 args.node_id(),
//                 home_dir
//             );
//
//
//              // NOTE: this shoudl be a part of the consensus builder
//
//             // Start the Malachite consensus engine
//             let app_handle = start_consensus_engine(state, engine_config, home_dir).await?;
//
//              // NOTE: now waiting for everything
//
//             // Wait for the node to exit
//             tokio::select! {
//                 _ = node_exit_future => {
//                     tracing::info!("Reth node exited");
//                 }
//                 _ = app_handle.app => {
//                     tracing::info!("Consensus engine exited");
//                 }
//                 _ = tokio::signal::ctrl_c() => {
//                     tracing::info!("Received shutdown signal");
//                 }
//             }
//
//             Ok(())
//         },
//     )
// }
