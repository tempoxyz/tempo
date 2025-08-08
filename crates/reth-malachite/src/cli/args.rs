//! Malachite-specific command-line arguments.
//!
//! This module defines the additional CLI arguments needed for Malachite consensus
//! configuration, including paths to configuration files, validator keys, and
//! consensus-specific parameters.

use clap::Args;
use std::path::PathBuf;

/// Malachite-specific CLI arguments
#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
#[command(next_help_heading = "Malachite")]
pub struct MalachiteArgs {
    /// Path to Malachite home directory containing config and data
    #[arg(long = "malachite-home", value_name = "PATH")]
    pub home: Option<PathBuf>,

    /// Path to Malachite configuration file
    #[arg(long = "consensus-config", value_name = "FILE")]
    pub consensus_config: Option<PathBuf>,

    /// Path to validator private key file
    #[arg(long = "validator-key", value_name = "FILE")]
    pub validator_key: Option<PathBuf>,

    /// Path to genesis file
    #[arg(long = "genesis", value_name = "FILE")]
    pub genesis: Option<PathBuf>,

    /// Node ID (e.g., "node-0", "node-1")
    #[arg(long = "node-id", value_name = "ID")]
    pub node_id: Option<String>,

    /// Chain ID to use
    #[arg(long = "chain-id", value_name = "ID")]
    pub chain_id: Option<String>,
}

impl MalachiteArgs {
    /// Get the home directory, defaulting to "./data" if not specified
    pub fn home_dir(&self) -> PathBuf {
        self.home.clone().unwrap_or_else(|| PathBuf::from("./data"))
    }

    /// Get the config file path
    pub fn config_file(&self) -> PathBuf {
        self.consensus_config
            .clone()
            .unwrap_or_else(|| self.home_dir().join("config").join("malachite.toml"))
    }

    /// Get the validator key file path
    pub fn validator_key_file(&self) -> PathBuf {
        self.validator_key.clone().unwrap_or_else(|| {
            self.home_dir()
                .join("config")
                .join("priv_validator_key.json")
        })
    }

    /// Get the genesis file path
    pub fn genesis_file(&self) -> PathBuf {
        self.genesis
            .clone()
            .unwrap_or_else(|| self.home_dir().join("config").join("genesis.json"))
    }

    /// Get the node ID, defaulting to "node-0" if not specified
    pub fn node_id(&self) -> String {
        self.node_id.clone().unwrap_or_else(|| "node-0".to_string())
    }

    /// Get the chain ID, defaulting to "reth-malachite-1" if not specified
    pub fn chain_id(&self) -> String {
        self.chain_id
            .clone()
            .unwrap_or_else(|| "reth-malachite-1".to_string())
    }
}
