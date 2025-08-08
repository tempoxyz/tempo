//! Configuration loader for Malachite consensus engine.
//!
//! This module provides utilities for loading and parsing consensus configuration
//! from TOML files. It properly deserializes the entire configuration structure,
//! respecting all user settings including discovery, protocol, and timeout configurations.

use crate::consensus::config::{Config, EngineConfig};
use eyre::Result;
use std::{fs, path::Path};

/// Load engine configuration from a TOML file
///
/// This function properly deserializes the entire TOML configuration file,
/// preserving all user settings including discovery configuration, protocol
/// settings, timeouts, and other consensus parameters.
pub fn load_engine_config(
    config_path: &Path,
    chain_id: String,
    _node_id: String,
) -> Result<EngineConfig> {
    // Read and parse the TOML file
    tracing::info!("Reading config file from: {:?}", config_path);
    let config_str = fs::read_to_string(config_path)?;
    tracing::info!("Config file size: {} bytes", config_str.len());

    // Deserialize the entire config structure
    let config: Config = toml::from_str(&config_str)?;

    // Extract the consensus port from listen_addr for backwards compatibility
    let consensus_port = config
        .consensus
        .p2p
        .listen_addr
        .to_string()
        .split('/')
        .next_back()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(26656);

    let socket_addr = format!("127.0.0.1:{consensus_port}").parse()?;

    // Build the engine config using the loaded configuration
    let mut engine_config = EngineConfig::new(chain_id, config.moniker.clone(), socket_addr);

    // Use the fully loaded config as the node config
    // This preserves all user settings from the TOML file
    engine_config.node = crate::consensus::config::NodeConfig {
        moniker: config.moniker,
        consensus: config.consensus,
        value_sync: config.value_sync,
        metrics: config.metrics,
        runtime: config.runtime,
        logging: config.logging,
    };

    // Also update the network config with persistent peers
    let peers: Vec<String> = engine_config
        .node
        .consensus
        .p2p
        .persistent_peers
        .iter()
        .map(|addr| addr.to_string())
        .collect();
    engine_config.network = engine_config.network.with_peers(peers);

    Ok(engine_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_full_config() {
        let config_content = r#"
moniker = "test-node"

[consensus]
timeout_propose = "3s"
timeout_propose_delta = "500ms"
timeout_prevote = "1s"
timeout_prevote_delta = "500ms"
timeout_precommit = "1s"
timeout_precommit_delta = "500ms"
timeout_commit = "1s"
skip_timeout_commit = true
value_payload = "proposal-and-parts"
queue_capacity = 100
timeout_rebroadcast = "5s"

[consensus.p2p]
listen_addr = "/ip4/0.0.0.0/tcp/26656"
persistent_peers = ["/ip4/127.0.0.1/tcp/26657", "/ip4/127.0.0.1/tcp/26658"]
allow_duplicate_ip = true
transport = "tcp"
pubsub_max_size = "4.2 MB"
rpc_max_size = "10.5 MB"

[consensus.p2p.discovery]
enabled = true
bootstrap_protocol = "full"
selector = "random"
num_outbound_peers = 2
num_inbound_peers = 2

[consensus.p2p.protocol]
type = "gossipsub"
mesh_n = 6
mesh_n_high = 12
mesh_n_low = 4
mesh_outbound_min = 2

[metrics]
enabled = true
listen_addr = "0.0.0.0:9000"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let engine_config = load_engine_config(
            temp_file.path(),
            "test-chain".to_string(),
            "node-0".to_string(),
        )
        .unwrap();

        // Verify the config was properly loaded
        assert_eq!(engine_config.node.moniker, "test-node");
        assert!(engine_config.node.consensus.p2p.discovery.enabled);
        assert_eq!(engine_config.node.consensus.p2p.persistent_peers.len(), 2);
        assert!(engine_config.node.metrics.enabled);
    }
}
