//! Configuration for the redacted zone RPC server.

use std::{net::SocketAddr, time::Duration};

/// Listener, authentication, and zone metadata configuration for the redacted RPC server.
///
/// Runtime L1 and local-node providers are injected separately by the node assembly.
#[derive(Debug, Clone)]
pub struct RedactedRpcConfig {
    /// Address to listen on for the redacted RPC server.
    pub listen_addr: SocketAddr,
    /// The zone's numeric identifier.
    pub zone_id: u32,
    /// The zone's chain ID.
    pub chain_id: u64,
    /// Maximum authorization token validity window this server accepts.
    ///
    /// This may be configured lower than the protocol default to tighten local
    /// policy, but it must not exceed the protocol maximum.
    pub max_auth_token_validity: Duration,
    /// Maximum serialized JSON-RPC response size in bytes.
    ///
    /// The node sets this from reth's `rpc.max-response-size` so the regular and redacted
    /// transports enforce the same response budget.
    pub max_response_size: usize,
    /// The ZonePortal contract address on L1 (used for querying deposits, not for auth tokens).
    pub zone_portal: alloy_primitives::Address,
}
