//! Ceremony configuration file parsing.

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::set::OrderedAssociated;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};

use crate::{constants::network as net_const, error::Error};

/// Root ceremony configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    /// Unique namespace to prevent replay attacks across ceremonies.
    pub namespace: String,
    /// Network settings.
    pub network: NetworkSettings,
    /// List of participants.
    pub participants: Vec<Participant>,
}

/// Network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Listen address for P2P connections.
    pub listen_address: SocketAddr,
    /// Maximum message size in bytes.
    #[serde(default = "net_const::default_max_message_size")]
    pub max_message_size: usize,
    /// Mailbox size for P2P channels.
    #[serde(default = "net_const::default_mailbox_size")]
    pub mailbox_size: usize,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            max_message_size: net_const::DEFAULT_MAX_MESSAGE_SIZE,
            mailbox_size: net_const::DEFAULT_MAILBOX_SIZE,
        }
    }
}

/// A ceremony participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Human-readable name for display.
    pub name: String,
    /// Hex-encoded ED25519 public key.
    pub public_key: String,
    /// Network address for P2P connection.
    pub address: SocketAddr,
}

impl CeremonyConfig {
    /// Create a new config programmatically.
    pub fn new(
        namespace: String,
        listen_address: SocketAddr,
        participants: Vec<Participant>,
    ) -> Self {
        Self {
            namespace,
            network: NetworkSettings {
                listen_address,
                ..Default::default()
            },
            participants,
        }
    }

    /// Load configuration from a TOML file.
    pub fn load(path: impl AsRef<std::path::Path>) -> eyre::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;

        if config.participants.len() < 2 {
            return Err(Error::InsufficientParticipants(config.participants.len()).into());
        }

        Ok(config)
    }

    /// Parse participants for P2P registration and display.
    ///
    /// Returns participants sorted by public key (deterministic ordering) with addresses,
    /// plus a map of public key to human-readable name.
    pub fn parse_participants(
        &self,
    ) -> eyre::Result<(
        OrderedAssociated<PublicKey, SocketAddr>,
        HashMap<PublicKey, String>,
    )> {
        let mut peers = Vec::new();
        let mut names = HashMap::new();
        for p in &self.participants {
            let bytes = const_hex::decode(&p.public_key)?;
            let key = PublicKey::decode(&bytes[..])?;
            peers.push((key.clone(), p.address));
            names.insert(key, p.name.clone());
        }
        peers.sort_by(|(a, _), (b, _)| a.encode().as_ref().cmp(b.encode().as_ref()));
        Ok((peers.into(), names))
    }
}
