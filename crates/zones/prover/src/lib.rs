//! Versioned request protocol for the Tempo Zone prover service.

pub mod attested_transport;
mod chainspec;
mod connection;
mod protocol;
mod verification;

pub use verification::{ShadowProofVerificationError, ShadowProofVerifier};

pub use chainspec::{TrustedChainSpecError, TrustedChainSpecs};
pub use connection::{ProverConnection, ProverConnectionError, request_error_response};
pub use protocol::{
    ErrorCode, NITRO_VERIFIER_CONFIG_V1, NITRO_VERIFIER_CONFIG_V1_HASH, NO_PROOF_FALLBACK_VERIFIER,
    NO_PROOF_FALLBACK_VERIFIER_HASH, NitroBatchAttestation, PROTOCOL_VERSION, ProofBundle,
    VerifierMode, VerifierModeError, VerifyRequest, VerifyResponse, nitro_batch_attestation_hash,
};

/// Allows batch witnesses up to 2 GiB to bound untrusted frame allocations.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024 * 1024;
