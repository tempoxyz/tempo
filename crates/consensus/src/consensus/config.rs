//! Configuration types for the Malachite consensus engine

use malachitebft_app_channel::app::{
    config::{
        ConsensusConfig as MalachiteConsensusConfig, DiscoveryConfig, LoggingConfig, MetricsConfig,
        P2pConfig, PubSubProtocol, RuntimeConfig, TimeoutConfig, ValuePayload, ValueSyncConfig,
    },
    node::NodeConfig as MalachiteNodeConfig,
};
use multiaddr::Multiaddr;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

/// Main configuration structure that matches the TOML format
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// A custom human-readable name for this node
    pub moniker: String,

    /// Log configuration options
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Consensus configuration options
    pub consensus: MalachiteConsensusConfig,

    /// ValueSync configuration options
    #[serde(default)]
    pub value_sync: ValueSyncConfig,

    /// Metrics configuration options
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Runtime configuration options
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

impl MalachiteNodeConfig for Config {
    fn moniker(&self) -> &str {
        &self.moniker
    }

    fn consensus(&self) -> &MalachiteConsensusConfig {
        &self.consensus
    }

    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }
}

/// Node configuration for the Malachite consensus engine
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node identifier
    pub moniker: String,
    /// Consensus configuration
    pub consensus: MalachiteConsensusConfig,
    /// Value sync configuration
    pub value_sync: ValueSyncConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Runtime configuration
    pub runtime: RuntimeConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

impl NodeConfig {
    /// Create a new node configuration with defaults
    pub fn new(moniker: String, listen_addr: String, persistent_peers: Vec<String>) -> Self {
        let listen_addr: Multiaddr = listen_addr
            .parse()
            .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/26656".parse().unwrap());

        let persistent_peers: Vec<Multiaddr> = persistent_peers
            .into_iter()
            .filter_map(|peer| peer.parse().ok())
            .collect();

        Self {
            moniker,
            consensus: MalachiteConsensusConfig {
                queue_capacity: Default::default(),
                value_payload: ValuePayload::ProposalAndParts,
                timeouts: TimeoutConfig::default(),
                p2p: P2pConfig {
                    protocol: PubSubProtocol::default(),
                    listen_addr,
                    persistent_peers,
                    discovery: DiscoveryConfig {
                        enabled: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            metrics: MetricsConfig {
                enabled: true,
                listen_addr: "127.0.0.1:9000".parse().unwrap(),
            },
            runtime: RuntimeConfig::default(),
            logging: LoggingConfig::default(),
            value_sync: ValueSyncConfig::default(),
        }
    }
}

impl MalachiteNodeConfig for NodeConfig {
    fn moniker(&self) -> &str {
        &self.moniker
    }

    fn consensus(&self) -> &MalachiteConsensusConfig {
        &self.consensus
    }

    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }
}

/// WAL (Write-Ahead Log) configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalConfig {
    /// Directory path for WAL storage
    pub path: PathBuf,
    /// Maximum size per WAL file
    pub max_file_size: u64,
    /// Whether to retain all WAL files
    pub retain_all: bool,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./wal"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            retain_all: false,
        }
    }
}

/// Network configuration for the consensus engine
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Chain identifier
    pub chain_id: String,
    /// Listen address for consensus
    pub listen_addr: SocketAddr,
    /// Persistent peer addresses
    pub persistent_peers: Vec<String>,
}

impl NetworkConfig {
    /// Create a new network configuration
    pub fn new(chain_id: String, listen_addr: SocketAddr) -> Self {
        Self {
            chain_id,
            listen_addr,
            persistent_peers: Vec::new(),
        }
    }

    /// Add persistent peers
    pub fn with_peers(mut self, peers: Vec<String>) -> Self {
        self.persistent_peers = peers;
        self
    }
}

/// Complete engine configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// WAL configuration
    pub wal: WalConfig,
    /// Node configuration (this will be replaced by the loaded config)
    pub node: NodeConfig,
    /// Optional start height
    pub start_height: Option<u64>,
}

impl EngineConfig {
    /// Create a new engine configuration
    pub fn new(chain_id: String, node_id: String, listen_addr: SocketAddr) -> Self {
        Self {
            network: NetworkConfig::new(chain_id.clone(), listen_addr),
            wal: WalConfig::default(),
            node: NodeConfig::new(node_id, listen_addr.to_string(), Vec::new()),
            start_height: None,
        }
    }
}
