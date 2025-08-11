//! Node trait implementation for Malachite consensus engine

use crate::{
    app::{Genesis, State},
    consensus::config::{Config, EngineConfig},
    context::{BasePeerAddress, MalachiteContext},
    provider::{Ed25519Provider, PrivateKey, PublicKey},
    types::Address,
};
use alloy_rpc_types_engine::ExecutionData;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use malachitebft_app::{
    events::{RxEvent, TxEvent},
    node::{EngineHandle, Node, NodeHandle},
    types::Keypair,
};
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_builder::{NodeTypes, PayloadTypes};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tempo_telemetry_util::error_field;

/// Tendermint-compatible private validator key file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeyFile {
    pub address: String,
    pub pub_key: TendermintPubKey,
    pub priv_key: TendermintPrivKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintPubKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintPrivKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub value: String,
}

/// Implementation of Malachite's Node trait for reth-malachite
#[derive(Clone)]
pub struct MalachiteNode<N: NodeTypes>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    /// Engine configuration
    pub config: EngineConfig,
    /// Path to the home directory
    pub home_dir: PathBuf,
    /// Path to the private key file
    pub private_key_file: PathBuf,
    /// Application state
    pub app_state: State<N>,
}

impl<N: NodeTypes> MalachiteNode<N>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    /// Create a new node implementation
    pub fn new(config: EngineConfig, home_dir: PathBuf, app_state: State<N>) -> Self {
        let private_key_file = home_dir.join("config").join("priv_validator_key.json");

        Self {
            config,
            home_dir,
            private_key_file,
            app_state,
        }
    }
}

/// Handle for the running consensus node
pub struct ConsensusHandle {
    /// Channels for communicating with consensus
    pub channels: malachitebft_app_channel::Channels<MalachiteContext>,
    /// Engine handle from Malachite
    pub engine: EngineHandle,
    /// Event transmitter
    pub tx_event: TxEvent<MalachiteContext>,
}

#[async_trait]
impl NodeHandle<MalachiteContext> for ConsensusHandle {
    fn subscribe(&self) -> RxEvent<MalachiteContext> {
        self.tx_event.subscribe()
    }

    async fn kill(&self, _reason: Option<String>) -> eyre::Result<()> {
        self.engine.actor.kill_and_wait(None).await?;
        self.engine.handle.abort();
        Ok(())
    }
}

#[async_trait]
impl<N: NodeTypes> Node for MalachiteNode<N>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    type Context = MalachiteContext;
    type Config = Config;
    type Genesis = Genesis;
    type PrivateKeyFile = PrivateKeyFile;
    type SigningProvider = Ed25519Provider;
    type NodeHandle = ConsensusHandle;

    fn get_home_dir(&self) -> PathBuf {
        self.home_dir.clone()
    }

    fn load_config(&self) -> eyre::Result<Self::Config> {
        // Convert NodeConfig to Config for compatibility
        Ok(Config {
            moniker: self.config.node.moniker.clone(),
            logging: self.config.node.logging,
            consensus: self.config.node.consensus.clone(),
            value_sync: self.config.node.value_sync,
            metrics: self.config.node.metrics.clone(),
            runtime: self.config.node.runtime,
        })
    }

    fn get_address(&self, pk: &PublicKey) -> BasePeerAddress {
        // Convert public key to address
        // For now, use a simple derivation - in production this would follow the chain's address scheme
        let pk_bytes = pk.as_bytes();
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&pk_bytes[..20]);
        BasePeerAddress::from(Address::new(addr_bytes))
    }

    fn get_public_key(&self, pk: &PrivateKey) -> PublicKey {
        pk.public_key()
    }

    fn get_keypair(&self, pk: PrivateKey) -> Keypair {
        // Convert our private key to Malachite's Keypair type
        let sk_bytes = pk.inner().to_bytes();
        Keypair::ed25519_from_bytes(sk_bytes).expect("valid ed25519 key")
    }

    fn load_private_key(&self, file: Self::PrivateKeyFile) -> PrivateKey {
        // Decode the private key from base64
        let private_key_full = STANDARD
            .decode(&file.priv_key.value)
            .expect("Invalid base64 in private key");

        // Tendermint format concatenates private key (32 bytes) + public key (32 bytes)
        // Extract just the private key part
        if private_key_full.len() != 64 {
            panic!(
                "Invalid private key length: expected 64 bytes, got {}",
                private_key_full.len()
            );
        }

        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&private_key_full[..32]);

        // Create PrivateKey from the raw bytes
        PrivateKey::from(private_key_bytes)
    }

    fn load_private_key_file(&self) -> eyre::Result<Self::PrivateKeyFile> {
        if !self.private_key_file.exists() {
            return Err(eyre::eyre!(
                "Private validator key file not found at: {:?}",
                self.private_key_file
            ));
        }

        let contents = std::fs::read_to_string(&self.private_key_file)?;
        let key_file: PrivateKeyFile = serde_json::from_str(&contents)?;

        Ok(key_file)
    }

    fn get_signing_provider(
        &self,
        private_key: malachitebft_core_types::PrivateKey<MalachiteContext>,
    ) -> Self::SigningProvider {
        Ed25519Provider::new(private_key)
    }

    fn load_genesis(&self) -> eyre::Result<Self::Genesis> {
        Ok(self.app_state.genesis.clone())
    }

    async fn start(&self) -> eyre::Result<ConsensusHandle> {
        tracing::info!(
            "Starting Malachite consensus engine with chain_id={}, node_id={}, home_dir={:?}",
            self.config.network.chain_id,
            self.config.node.moniker,
            self.home_dir
        );

        let config = self.load_config()?;
        let ctx = self.app_state.ctx.clone();

        let _genesis = self.load_genesis()?;
        let initial_validator_set = self.app_state.get_validator_set(crate::height::Height(1));

        // Start the Malachite consensus engine
        let start_height = self.config.start_height.map(crate::height::Height);
        tracing::info!(
            "Starting Malachite engine with start_height={:?}",
            start_height
        );

        let (channels, engine_handle) = malachitebft_app_channel::start_engine(
            ctx.clone(),
            self.clone(),
            config,                   // Convert to Malachite's config type
            crate::codec::ProtoCodec, // WAL codec
            crate::codec::ProtoCodec, // Network codec
            start_height,
            initial_validator_set,
        )
        .await?;

        tracing::info!("Malachite engine started, channels created");
        let tx_event = channels.events.clone();

        Ok(ConsensusHandle {
            channels,
            engine: engine_handle,
            tx_event,
        })
    }

    async fn run(self) -> eyre::Result<()> {
        let mut handle = self.start().await?;

        // Run the consensus handler
        let app_state = self.app_state.clone();
        if let Err(e) =
            super::handler::run_consensus_handler(&app_state, &mut handle.channels).await
        {
            tracing::error!(error = error_field(&e), "Consensus handler error");
        }

        Ok(())
    }
}
