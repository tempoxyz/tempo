use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{BridgeError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub chains: Vec<ChainConfig>,
    /// Signer config - optional when running in integrated validator mode
    /// (the share is passed via --consensus.signing-share instead)
    #[serde(default)]
    pub signer: Option<SignerConfig>,
    pub threshold: ThresholdConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_port() -> u16 {
    9090
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    pub chain_id: u64,
    /// WebSocket URL for event subscriptions (preferred)
    pub ws_url: Option<String>,
    /// HTTP URL for RPC calls (fallback/submission)
    pub rpc_url: String,
    pub bridge_address: String,
    #[serde(default)]
    pub finality_blocks: u64,
    /// Private key for submitting attestations to this chain.
    /// If not set, attestations are simulated but not submitted.
    #[serde(default)]
    pub submitter_private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerConfig {
    pub validator_index: u32,
    pub bls_key_share_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Path to the sharing file (serialized `Sharing<MinSig>` from DKG).
    /// Optional in integrated validator mode (sharing is extracted from genesis).
    #[serde(default)]
    pub sharing_file: Option<String>,
    /// Current epoch (increments on key rotation).
    #[serde(default = "default_epoch")]
    pub epoch: u64,
}

fn default_epoch() -> u64 {
    1
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| BridgeError::Config(e.to_string()))
    }
}
