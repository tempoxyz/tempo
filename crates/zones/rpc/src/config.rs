//! Configuration for the redacted zone RPC server.

use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};

/// Default cap on simulation requests (`eth_call`, `eth_estimateGas`, `eth_fillTransaction`) the
/// redacted RPC runs at once.
pub const DEFAULT_MAX_CONCURRENT_SIMULATIONS: NonZeroUsize =
    NonZeroUsize::new(16).expect("value is not zero");

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
    /// Maximum simulation requests (`eth_call`, `eth_estimateGas`, `eth_fillTransaction`) running
    /// at once across all callers. Further simulations wait in arrival order and fail with `-32009`
    /// if no permit frees up within two seconds of their request or batch arriving.
    ///
    /// Simulations can block on uncached Tempo L1 state through the provider that block building
    /// uses, and authorization tokens are self-signed, so this cap bounds how many can do so at
    /// once.
    pub max_concurrent_simulations: NonZeroUsize,
    /// The ZonePortal contract address on L1 (used for querying deposits, not for auth tokens).
    pub zone_portal: alloy_primitives::Address,
}
