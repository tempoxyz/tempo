//! ExEx sidecar for Tempo stablecoin bridge.
//!
//! This sidecar watches origin chains for deposits and submits validator
//! signatures to the Tempo bridge precompile.

pub mod config;
pub mod deposit_id;

#[cfg(test)]
mod tests;
pub mod consensus_client;
pub mod exex;
pub mod health;
pub mod metrics;
pub mod origin_client;
pub mod origin_watcher;
pub mod persistence;
pub mod proof;
pub mod retry;
pub mod signer;
pub mod tempo_client;
pub mod tempo_watcher;

pub use config::BridgeConfig;
pub use consensus_client::ConsensusClient;
pub use exex::BridgeExEx;
pub use metrics::BridgeMetrics;
pub use origin_client::OriginClient;
pub use persistence::StateManager;
pub use proof::{AttestationGenerator, BurnAttestation, TempoBlockHeader};
#[allow(deprecated)]
pub use proof::{BurnProof, ProofGenerator};
pub use signer::{AttestationSigner, BridgeSigner, KmsSigner, LocalSigner};
pub use tempo_client::TempoClient;
