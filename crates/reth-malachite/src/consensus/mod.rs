//! # Consensus Module
//!
//! This module contains the Malachite consensus engine integration for reth-malachite.
//! It is responsible for running the Byzantine Fault Tolerant (BFT) consensus protocol
//! that coordinates validators to agree on the order and content of blocks.
//!
//! ## Architecture Overview
//!
//! This module implements the infrastructure needed to run Malachite consensus:
//! - **Node trait implementation**: Provides configuration, genesis data, and cryptographic operations
//! - **Message handler**: Processes consensus messages and bridges them to the application layer
//! - **Engine runner**: Manages the lifecycle of the consensus engine
//!
//! ## Separation of Concerns
//!
//! While the `app` module represents the Tendermint "application" (blockchain execution layer),
//! this module is purely about running the consensus protocol. It:
//! - Does NOT execute transactions or manage blockchain state
//! - Does NOT decide what goes into blocks
//! - DOES coordinate validators to agree on block order
//! - DOES handle consensus-specific networking and state machine
//!
//! ## Communication Flow
//!
//! 1. Consensus engine sends `AppMsg` through channels to request actions:
//!    - `GetValue`: "Please propose a block for this height/round"
//!    - `ReceivedProposalPart`: "Here's a block proposal from another validator"
//!    - `Decided`: "Consensus reached, please commit this block"
//!
//! 2. The message handler in this module:
//!    - Receives these messages from Malachite
//!    - Calls appropriate methods on the app `State`
//!    - Sends responses back through channels
//!
//! ## Key Components
//!
//! - **`MalachiteNode`**: Implements Malachite's `Node` trait for configuration
//! - **`run_consensus_handler`**: The main loop that processes consensus messages
//! - **`ConsensusHandle`**: Manages the consensus engine lifecycle and provides control interface
//! - **Configuration types**: Network, WAL, metrics settings for Malachite
//!
//! ## Integration Points
//!
//! - Uses `malachitebft_app_channel::start_engine` to launch the consensus engine
//! - Communicates with the app layer through the `Channels<MalachiteContext>` type
//! - Integrates with reth's P2P network for consensus message propagation

pub mod config;
pub mod config_loader;
pub mod handler;
pub mod node;

use crate::app::State;
use alloy_rpc_types_engine::ExecutionData;
use eyre::Result;
use malachitebft_app::node::Node;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_builder::{NodeTypes, PayloadTypes};
use std::{net::SocketAddr, path::PathBuf};
use tempo_telemetry_util::error_field;
use tracing::info;

pub use config::{EngineConfig, NetworkConfig, NodeConfig, WalConfig};
pub use node::{ConsensusHandle, MalachiteNode};

/// Starts the Malachite consensus engine
///
/// This function initializes and starts the consensus engine that will:
/// - Coordinate with other validators to agree on blocks
/// - Request block proposals from the application when needed
/// - Notify the application when consensus is reached
///
/// # Arguments
/// * `app_state` - The application state that will handle consensus requests
/// * `config` - Engine configuration including network, WAL, and node settings
/// * `home_dir` - Directory for storing consensus data
///
/// # Returns
/// A handle to the running consensus engine with app handler task
pub async fn start_consensus_engine<N: NodeTypes>(
    app_state: State<N>,
    config: EngineConfig,
    home_dir: PathBuf,
) -> Result<AppHandle>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    info!(
        "Starting Malachite consensus engine for chain {}",
        config.network.chain_id
    );

    // Create the node implementation
    let node = MalachiteNode::new(config, home_dir.clone(), app_state.clone());

    // Start the consensus engine
    let mut handle = node.start().await?;

    info!("Malachite consensus engine started successfully");

    // Spawn the application handler task
    let app_handle = tokio::spawn(async move {
        info!("Starting consensus handler loop");
        if let Err(e) = handler::run_consensus_handler(&app_state, &mut handle.channels).await {
            {
                tracing::error!(error = error_field(&e), "Consensus handler error");
            }
        }
        info!("Consensus handler loop ended");
    });

    Ok(AppHandle {
        app: app_handle,
        engine: handle.engine,
        tx_event: handle.tx_event,
    })
}

/// Handle returned by start_consensus_engine
pub struct AppHandle {
    /// Application task handle
    pub app: tokio::task::JoinHandle<()>,
    /// Engine handle from Malachite
    pub engine: malachitebft_app::node::EngineHandle,
    /// Event transmitter
    pub tx_event: malachitebft_app::events::TxEvent<crate::context::MalachiteContext>,
}

/// Creates a default engine configuration
pub fn default_engine_config(chain_id: String, moniker: String) -> EngineConfig {
    let listen_addr: SocketAddr = "127.0.0.1:26656".parse().unwrap();
    EngineConfig::new(chain_id, moniker, listen_addr)
}
