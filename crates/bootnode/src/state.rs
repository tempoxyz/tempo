//! Bootnode state management.

use parking_lot::RwLock;
use reth_discv4::{DiscoveryUpdate, Discv4};
use reth_network_peers::{NodeRecord, PeerId};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tracing::{info, warn};

/// Information about a registered or discovered peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: String,
    pub ip: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub enode: String,
}

impl From<&NodeRecord> for PeerInfo {
    fn from(record: &NodeRecord) -> Self {
        Self {
            id: format!("{:?}", record.id),
            ip: record.address.to_string(),
            tcp_port: record.tcp_port,
            udp_port: record.udp_port,
            enode: record.to_string(),
        }
    }
}

/// Request to register a new peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded 32-byte secret key for the node.
    pub secret_key: String,
    /// IP address of the node.
    pub ip: std::net::IpAddr,
    /// TCP port (defaults to 30303).
    #[serde(default = "default_port")]
    pub tcp_port: u16,
    /// UDP port (defaults to tcp_port).
    pub udp_port: Option<u16>,
}

fn default_port() -> u16 {
    30303
}

/// Bootnode status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootnodeInfo {
    pub enode: String,
    pub peer_id: String,
    pub discovery_addr: String,
    pub http_addr: String,
    pub registered_peers: usize,
    pub discovered_peers: usize,
}

/// Shared state for the bootnode.
#[derive(Clone)]
pub struct BootnodeState {
    /// The discv4 frontend for managing peers.
    pub discv4: Discv4,
    /// This node's ENR record.
    pub local_enr: NodeRecord,
    /// HTTP API address.
    pub http_addr: SocketAddr,
    /// Peers explicitly registered via the API.
    pub registered_peers: Arc<RwLock<HashMap<PeerId, NodeRecord>>>,
    /// Peers discovered via discv4 protocol.
    pub discovered_peers: Arc<RwLock<HashMap<PeerId, NodeRecord>>>,
}

impl BootnodeState {
    /// Create a new bootnode state.
    pub fn new(discv4: Discv4, local_enr: NodeRecord, http_addr: SocketAddr) -> Self {
        Self {
            discv4,
            local_enr,
            http_addr,
            registered_peers: Arc::new(RwLock::new(HashMap::new())),
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get bootnode info.
    pub fn info(&self) -> BootnodeInfo {
        BootnodeInfo {
            enode: self.local_enr.to_string(),
            peer_id: format!("{:?}", self.local_enr.id),
            discovery_addr: self.local_enr.udp_addr().to_string(),
            http_addr: self.http_addr.to_string(),
            registered_peers: self.registered_peers.read().len(),
            discovered_peers: self.discovered_peers.read().len(),
        }
    }

    /// List all registered peers.
    pub fn list_registered(&self) -> Vec<PeerInfo> {
        self.registered_peers
            .read()
            .values()
            .map(PeerInfo::from)
            .collect()
    }

    /// List all discovered peers.
    pub fn list_discovered(&self) -> Vec<PeerInfo> {
        self.discovered_peers
            .read()
            .values()
            .map(PeerInfo::from)
            .collect()
    }

    /// Register a peer with the bootnode.
    pub fn register_peer(&self, record: NodeRecord) -> PeerInfo {
        self.discv4.add_node(record);
        self.registered_peers.write().insert(record.id, record);
        info!("Registered peer: {:?} at {}", record.id, record.address);
        PeerInfo::from(&record)
    }

    /// Deregister a peer from the bootnode.
    pub fn deregister_peer(&self, peer_id: PeerId) -> bool {
        let removed = self.registered_peers.write().remove(&peer_id);
        if removed.is_some() {
            self.discv4.remove_peer(peer_id);
            info!("Deregistered peer: {:?}", peer_id);
            true
        } else {
            false
        }
    }

    /// Get a peer by ID (checks registered first, then discovered).
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        if let Some(record) = self.registered_peers.read().get(peer_id) {
            return Some(PeerInfo::from(record));
        }
        if let Some(record) = self.discovered_peers.read().get(peer_id) {
            return Some(PeerInfo::from(record));
        }
        None
    }

    /// Handle a discovery update from the discv4 service.
    pub fn handle_discovery_update(&self, update: DiscoveryUpdate) {
        match update {
            DiscoveryUpdate::Added(record) => {
                info!("Discovered peer: {:?} at {}", record.id, record.address);
                self.discovered_peers.write().insert(record.id, record);
            }
            DiscoveryUpdate::Removed(peer_id) => {
                info!("Peer removed: {:?}", peer_id);
                self.discovered_peers.write().remove(&peer_id);
            }
            DiscoveryUpdate::DiscoveredAtCapacity(record) => {
                warn!(
                    "Discovery at capacity, ignoring peer: {:?} at {}",
                    record.id, record.address
                );
            }
            DiscoveryUpdate::EnrForkId(record, fork_id) => {
                info!("Peer {:?} has fork_id: {:?}", record.id, fork_id);
            }
            DiscoveryUpdate::Batch(updates) => {
                for update in updates {
                    self.handle_discovery_update(update);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_node_record(port: u16) -> NodeRecord {
        let key = crate::generate_secret_key();
        let addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
        NodeRecord::from_secret_key(addr, &key)
    }

    #[test]
    fn test_peer_info_from_node_record() {
        let record = mock_node_record(30303);
        let info = PeerInfo::from(&record);

        assert_eq!(info.ip, "127.0.0.1");
        assert_eq!(info.tcp_port, 30303);
        assert_eq!(info.udp_port, 30303);
        assert!(info.enode.starts_with("enode://"));
    }

    #[test]
    fn test_register_request_default_port() {
        let json = r#"{"secret_key": "0x1234", "ip": "10.0.0.1"}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tcp_port, 30303);
        assert!(req.udp_port.is_none());
    }

    #[test]
    fn test_register_request_custom_ports() {
        let json =
            r#"{"secret_key": "0x1234", "ip": "10.0.0.1", "tcp_port": 30304, "udp_port": 30305}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tcp_port, 30304);
        assert_eq!(req.udp_port, Some(30305));
    }
}
