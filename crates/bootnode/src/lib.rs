//! Internal bootnode with dynamic peer registration.
//!
//! This crate provides a lightweight discv4 bootnode that can dynamically
//! register and deregister peers via an HTTP API. Designed for Kubernetes
//! deployments where nodes register on startup and deregister on shutdown.

mod server;
mod state;

pub use server::{BootnodeConfig, BootnodeHandle, BootnodeServer};
pub use state::{BootnodeInfo, BootnodeState, PeerInfo, RegisterRequest};

use eyre::Result;
use rand::Rng;
use secp256k1::SecretKey;
use std::path::Path;
use tracing::{info, warn};

/// Load a secret key from a file or generate a new one.
///
/// If the path exists, reads and decodes the hex-encoded key.
/// If the path doesn't exist, generates a new key and saves it.
/// If no path is provided, generates an ephemeral key (not persisted).
pub fn load_or_generate_key(path: Option<&Path>) -> Result<SecretKey> {
    match path {
        Some(path) if path.exists() => {
            let contents = std::fs::read_to_string(path)?;
            let bytes = const_hex::decode(contents.trim().trim_start_matches("0x"))?;
            let key = SecretKey::from_slice(&bytes)?;
            info!("Loaded node key from {:?}", path);
            Ok(key)
        }
        Some(path) => {
            let key = generate_secret_key();
            let hex_key = const_hex::encode(key.secret_bytes());
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, hex_key)?;
            info!("Generated and saved new node key to {:?}", path);
            Ok(key)
        }
        None => {
            let key = generate_secret_key();
            warn!("Generated ephemeral node key (not persisted)");
            Ok(key)
        }
    }
}

/// Generate a random secp256k1 secret key.
pub fn generate_secret_key() -> SecretKey {
    let mut rng = rand::thread_rng();
    loop {
        let bytes: [u8; 32] = rng.r#gen();
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

/// Parse a hex-encoded peer ID (64 bytes / 128 hex chars).
pub fn parse_peer_id(s: &str) -> Result<reth_network_peers::PeerId, String> {
    let s = s.trim_start_matches("0x");
    let bytes = const_hex::decode(s).map_err(|e| format!("Invalid hex: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("Expected 64 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(reth_network_peers::PeerId::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_secret_key() {
        let key1 = generate_secret_key();
        let key2 = generate_secret_key();
        assert_ne!(key1.secret_bytes(), key2.secret_bytes());
    }

    #[test]
    fn test_load_or_generate_key_new_file() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("node.key");

        let key1 = load_or_generate_key(Some(&key_path)).unwrap();
        assert!(key_path.exists());

        let key2 = load_or_generate_key(Some(&key_path)).unwrap();
        assert_eq!(key1.secret_bytes(), key2.secret_bytes());
    }

    #[test]
    fn test_load_or_generate_key_ephemeral() {
        let key = load_or_generate_key(None).unwrap();
        assert_eq!(key.secret_bytes().len(), 32);
    }

    #[test]
    fn test_parse_peer_id_valid() {
        let hex = "a".repeat(128);
        let result = parse_peer_id(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_peer_id_with_prefix() {
        let hex = format!("0x{}", "b".repeat(128));
        let result = parse_peer_id(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_peer_id_invalid_length() {
        let hex = "a".repeat(64);
        let result = parse_peer_id(&hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected 64 bytes"));
    }

    #[test]
    fn test_parse_peer_id_invalid_hex() {
        let result = parse_peer_id("zzzz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex"));
    }
}
