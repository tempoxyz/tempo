//! Bridge configuration from TOML.

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

/// Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Tempo chain ID
    pub tempo_chain_id: u64,

    /// Validator's signing key path (uses existing key material)
    pub validator_key_path: Option<String>,

    /// Origin chain configurations
    pub chains: HashMap<String, ChainConfig>,
}

/// Configuration for an origin chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: u64,

    /// RPC URL
    pub rpc_url: String,

    /// WebSocket URL for subscriptions (optional)
    pub ws_url: Option<String>,

    /// Number of confirmations before considering deposit final
    pub confirmations: u64,

    /// Escrow contract address on this chain
    pub escrow_address: Address,

    /// Supported token mappings: origin_token -> tempo_tip20
    pub tokens: HashMap<Address, TokenConfig>,

    /// Polling interval in seconds
    pub poll_interval_secs: u64,

    /// Start block for syncing (0 = latest)
    pub start_block: u64,
}

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Human-readable name
    pub name: String,

    /// Token symbol
    pub symbol: String,

    /// Decimals on origin chain
    pub decimals: u8,

    /// Corresponding TIP-20 address on Tempo
    pub tempo_tip20: Address,

    /// Minimum deposit amount (in origin token decimals)
    pub min_deposit: Option<u64>,

    /// Maximum deposit amount (in origin token decimals)
    pub max_deposit: Option<u64>,
}

impl BridgeConfig {
    /// Load configuration from a TOML file
    pub fn load(path: impl AsRef<Path>) -> eyre::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Create a default configuration for testing
    pub fn default_test_config() -> Self {
        let mut chains = HashMap::new();

        let mut tokens = HashMap::new();
        tokens.insert(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                .parse()
                .unwrap(), // USDC on Ethereum
            TokenConfig {
                name: "USD Coin".to_string(),
                symbol: "USDC".to_string(),
                decimals: 6,
                tempo_tip20: "0x20C0000000000000000000000000000001000000"
                    .parse()
                    .unwrap(),
                min_deposit: Some(1_000_000),         // 1 USDC
                max_deposit: Some(1_000_000_000_000), // 1M USDC
            },
        );

        chains.insert(
            "ethereum".to_string(),
            ChainConfig {
                chain_id: 1,
                rpc_url: "http://localhost:8545".to_string(),
                ws_url: Some("ws://localhost:8546".to_string()),
                confirmations: 12,
                escrow_address: Address::ZERO, // Set in tests
                tokens,
                poll_interval_secs: 12,
                start_block: 0,
            },
        );

        Self {
            tempo_chain_id: 62049,
            validator_key_path: None,
            chains,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
tempo_chain_id = 62049

[chains.anvil]
chain_id = 31337
rpc_url = "http://localhost:8545"
confirmations = 1
escrow_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
poll_interval_secs = 1
start_block = 0

[chains.anvil.tokens."0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
name = "USD Coin"
symbol = "USDC"
decimals = 6
tempo_tip20 = "0x20C0000000000000000000000000000001000000"
"#;

        let config: BridgeConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.tempo_chain_id, 62049);
        assert!(config.chains.contains_key("anvil"));
    }
}
