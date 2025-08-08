//! Configuration loader for the application layer.
//!
//! This module provides functions to load application configuration and genesis
//! data from files, supporting the Tendermint-compatible format used by Malachite.

use super::{Config, Genesis, ValidatorInfo};
use crate::types::Address;
use alloy_primitives::B256;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

/// Load application configuration from a TOML file
pub fn load_config(config_path: &Path) -> Result<Config> {
    let config_str = fs::read_to_string(config_path)?;
    let config_value: toml::Value = toml::from_str(&config_str)?;

    // Extract app settings if they exist
    if let Some(app) = config_value.get("app") {
        let block_time_secs = app
            .get("block_time")
            .and_then(|v| v.as_str())
            .and_then(|s| s.trim_end_matches('s').parse::<u64>().ok())
            .unwrap_or(1);

        let create_empty_blocks = app
            .get("empty_blocks")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let fee_recipient = app
            .get("fee_recipient")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<alloy_primitives::Address>().ok())
            .unwrap_or(alloy_primitives::Address::ZERO);

        let block_build_time_ms = app
            .get("block_build_time_ms")
            .and_then(|v| v.as_integer())
            .and_then(|i| i.try_into().ok())
            .unwrap_or(500);

        Ok(Config {
            block_time: std::time::Duration::from_secs(block_time_secs),
            create_empty_blocks,
            fee_recipient,
            block_build_time_ms,
        })
    } else {
        // Return default config if no app section
        Ok(Config::new())
    }
}

/// Tendermint-compatible genesis file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintGenesis {
    pub genesis_time: String,
    pub chain_id: String,
    pub initial_height: String,
    pub validators: Vec<TendermintValidator>,
    pub app_state: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintValidator {
    pub address: String,
    pub pub_key: TendermintPubKey,
    pub power: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintPubKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub value: String,
}

/// Load genesis data from a JSON file
pub fn load_genesis(genesis_path: &Path) -> Result<Genesis> {
    let genesis_str = fs::read_to_string(genesis_path)?;
    let tm_genesis: TendermintGenesis = serde_json::from_str(&genesis_str)?;

    // Convert validators
    let mut validators = Vec::new();
    for tm_val in tm_genesis.validators {
        // Parse address (hex string to 20 bytes)
        let address_bytes = hex::decode(&tm_val.address)?;
        if address_bytes.len() != 20 {
            return Err(eyre::eyre!("Invalid validator address length"));
        }
        let mut addr_array = [0u8; 20];
        addr_array.copy_from_slice(&address_bytes);
        let address = Address::new(addr_array);

        // Parse voting power
        let voting_power = tm_val.power.parse::<u64>()?;

        // Decode public key from base64
        let public_key = STANDARD.decode(&tm_val.pub_key.value)?;

        validators.push(ValidatorInfo::new(address, voting_power, public_key));
    }

    // Serialize app state
    let app_state = serde_json::to_vec(&tm_genesis.app_state)?;

    // For now, use a zero hash for genesis
    // TODO: Calculate proper genesis hash
    let genesis_hash = B256::ZERO;

    Ok(Genesis {
        chain_id: tm_genesis.chain_id,
        validators,
        app_state,
        genesis_hash,
    })
}

/// Tendermint-compatible validator key file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintValidatorKey {
    pub address: String,
    pub pub_key: TendermintPubKey,
    pub priv_key: TendermintPrivKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TendermintPrivKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub value: String,
}

/// Load validator key and derive address from a JSON file
pub fn load_validator_key(key_path: &Path) -> Result<(Address, Vec<u8>, Vec<u8>)> {
    let key_str = fs::read_to_string(key_path)?;
    let tm_key: TendermintValidatorKey = serde_json::from_str(&key_str)?;

    // Parse address
    let address_bytes = hex::decode(&tm_key.address)?;
    if address_bytes.len() != 20 {
        return Err(eyre::eyre!("Invalid validator address length"));
    }
    let mut addr_array = [0u8; 20];
    addr_array.copy_from_slice(&address_bytes);
    let address = Address::new(addr_array);

    // Decode keys from base64
    let public_key = STANDARD.decode(&tm_key.pub_key.value)?;
    let private_key_full = STANDARD.decode(&tm_key.priv_key.value)?;

    // Extract just the private key part (first 32 bytes)
    // Tendermint format concatenates private key + public key
    let private_key = private_key_full[..32].to_vec();

    Ok((address, public_key, private_key))
}

// Add base64 dependency
use base64::{Engine, engine::general_purpose::STANDARD};
