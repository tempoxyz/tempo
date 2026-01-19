//! Bridge configuration from TOML.

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

/// KMS provider type
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KmsProvider {
    #[default]
    Aws,
    Gcp,
}

/// KMS configuration for production key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfig {
    /// KMS provider (aws or gcp)
    #[serde(default)]
    pub provider: KmsProvider,

    /// AWS KMS key ID, key ARN, alias name, or alias ARN
    /// For GCP: projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
    pub key_id: String,

    /// AWS region (required for AWS, ignored for GCP)
    pub region: Option<String>,

    /// The Ethereum address corresponding to the KMS key's public key
    /// Must be provided since deriving from KMS requires an API call
    pub address: Address,
}

/// Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Tempo chain ID
    pub tempo_chain_id: u64,

    /// Test mode flag. When true, the bridge will use empty signatures for
    /// burns when no consensus client is configured. In production (test_mode = false),
    /// the bridge will fail to start if no consensus client is configured.
    #[serde(default)]
    pub test_mode: bool,

    /// Health server port (disabled if not set)
    pub health_port: Option<u16>,

    /// Tempo RPC URL for submitting transactions
    pub tempo_rpc_url: Option<String>,

    /// Secondary Tempo RPC URL for backup/quorum verification
    pub tempo_secondary_rpc_url: Option<String>,

    /// Consensus RPC URL for fetching finalization certificates.
    /// Used for header relay to get BLS threshold signatures.
    /// Typically the same as tempo_rpc_url unless running a separate consensus endpoint.
    pub consensus_rpc_url: Option<String>,

    /// When true, both Tempo RPCs must agree on block hashes
    #[serde(default)]
    pub require_tempo_rpc_quorum: bool,

    /// Validator's signing key path (uses existing key material, fallback if attestation/broadcaster keys not set)
    pub validator_key_path: Option<String>,

    /// Path to HSM/KMS key for attestation signing (higher privilege)
    pub attestation_key_path: Option<String>,

    /// Path to lower-privilege broadcaster key for transaction submission
    pub broadcaster_key_path: Option<String>,

    /// KMS configuration for attestation signing (takes precedence over attestation_key_path)
    pub kms: Option<KmsConfig>,

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

    /// Secondary RPC URL for backup/quorum verification
    pub secondary_rpc_url: Option<String>,

    /// When true, both RPCs must agree on block hashes
    #[serde(default)]
    pub require_rpc_quorum: bool,

    /// WebSocket URL for subscriptions (optional)
    pub ws_url: Option<String>,

    /// Number of confirmations before considering deposit final
    pub confirmations: u64,

    /// Escrow contract address on this chain
    pub escrow_address: Address,

    /// Tempo light client contract address on this chain (for burn verification)
    pub light_client_address: Option<Address>,

    /// Supported token mappings: origin_token -> tempo_tip20
    pub tokens: HashMap<Address, TokenConfig>,

    /// Polling interval in seconds
    pub poll_interval_secs: u64,

    /// Start block for syncing (0 = latest)
    pub start_block: u64,

    /// Whether to require L1 beacon finality before signing deposit attestations.
    /// When true, uses eth_getBlockByNumber("finalized") to check finality.
    /// When false, uses confirmation count only (less secure for PoS chains).
    /// Default: true
    #[serde(default = "default_require_l1_finality")]
    pub require_l1_finality: bool,

    /// Fallback confirmation depth for L1 finality if beacon finality RPC is unavailable.
    /// Approximately 2 epochs = 64 blocks on Ethereum mainnet (~13 minutes).
    /// Only used when require_l1_finality is true and finalized block query fails.
    /// Default: 64
    #[serde(default = "default_l1_finality_confirmations")]
    pub l1_finality_confirmations: u64,
}

fn default_require_l1_finality() -> bool {
    true
}

fn default_l1_finality_confirmations() -> u64 {
    64
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
                secondary_rpc_url: None,
                require_rpc_quorum: false,
                ws_url: Some("ws://localhost:8546".to_string()),
                confirmations: 12,
                escrow_address: Address::ZERO, // Set in tests
                light_client_address: None,    // Set in production
                tokens,
                poll_interval_secs: 12,
                start_block: 0,
                require_l1_finality: false, // Disable for tests
                l1_finality_confirmations: 64,
            },
        );

        Self {
            tempo_chain_id: 62049,
            test_mode: true,
            health_port: None,
            tempo_rpc_url: Some("http://localhost:8551".to_string()),
            tempo_secondary_rpc_url: None,
            consensus_rpc_url: Some("http://localhost:8551".to_string()),
            require_tempo_rpc_quorum: false,
            validator_key_path: None,
            attestation_key_path: None,
            broadcaster_key_path: None,
            kms: None,
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

        // Verify optional fields default correctly
        assert!(config.tempo_secondary_rpc_url.is_none());
        assert!(!config.require_tempo_rpc_quorum);
        assert!(config.attestation_key_path.is_none());
        assert!(config.broadcaster_key_path.is_none());

        let anvil = config.chains.get("anvil").unwrap();
        assert!(anvil.secondary_rpc_url.is_none());
        assert!(!anvil.require_rpc_quorum);

        // Verify L1 finality defaults
        assert!(anvil.require_l1_finality); // Default true
        assert_eq!(anvil.l1_finality_confirmations, 64); // Default 64
    }

    #[test]
    fn test_parse_config_with_new_fields() {
        let toml = r#"
tempo_chain_id = 62049
tempo_rpc_url = "http://localhost:8551"
tempo_secondary_rpc_url = "http://localhost:8552"
require_tempo_rpc_quorum = true
attestation_key_path = "/path/to/attestation.key"
broadcaster_key_path = "/path/to/broadcaster.key"

[chains.anvil]
chain_id = 31337
rpc_url = "http://localhost:8545"
secondary_rpc_url = "http://localhost:8546"
require_rpc_quorum = true
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
        assert_eq!(
            config.tempo_secondary_rpc_url,
            Some("http://localhost:8552".to_string())
        );
        assert!(config.require_tempo_rpc_quorum);
        assert_eq!(
            config.attestation_key_path,
            Some("/path/to/attestation.key".to_string())
        );
        assert_eq!(
            config.broadcaster_key_path,
            Some("/path/to/broadcaster.key".to_string())
        );

        let anvil = config.chains.get("anvil").unwrap();
        assert_eq!(
            anvil.secondary_rpc_url,
            Some("http://localhost:8546".to_string())
        );
        assert!(anvil.require_rpc_quorum);
    }

    #[test]
    fn test_parse_config_with_l1_finality() {
        let toml = r#"
tempo_chain_id = 62049

[chains.ethereum]
chain_id = 1
rpc_url = "http://localhost:8545"
confirmations = 12
escrow_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
poll_interval_secs = 12
start_block = 0
require_l1_finality = true
l1_finality_confirmations = 96

[chains.ethereum.tokens."0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
name = "USD Coin"
symbol = "USDC"
decimals = 6
tempo_tip20 = "0x20C0000000000000000000000000000001000000"

[chains.anvil]
chain_id = 31337
rpc_url = "http://localhost:8545"
confirmations = 1
escrow_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
poll_interval_secs = 1
start_block = 0
require_l1_finality = false

[chains.anvil.tokens."0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
name = "USD Coin"
symbol = "USDC"
decimals = 6
tempo_tip20 = "0x20C0000000000000000000000000000001000000"
"#;

        let config: BridgeConfig = toml::from_str(toml).unwrap();

        // Ethereum chain with explicit L1 finality settings
        let ethereum = config.chains.get("ethereum").unwrap();
        assert!(ethereum.require_l1_finality);
        assert_eq!(ethereum.l1_finality_confirmations, 96);

        // Anvil chain with finality disabled
        let anvil = config.chains.get("anvil").unwrap();
        assert!(!anvil.require_l1_finality);
        assert_eq!(anvil.l1_finality_confirmations, 64); // Default still applies
    }
}
