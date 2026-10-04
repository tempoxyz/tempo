//! Transport-independent verification of Tempo finalization certificates.
//!
//! This crate authenticates headers, not execution validity or block bodies. Callers must supply
//! their own network trust anchor. Boundary registration requires previously authenticated
//! ancestry; decoding an RPC-supplied boundary alone does not authenticate a new signing key.

mod digest;
mod network_identity;
mod scheme_provider;
mod verifier;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(test)]
mod tests;

pub use digest::Digest;
pub use network_identity::NetworkIdentity;
pub use scheme_provider::SchemeProvider;
pub use verifier::{
    CertificateVerificationError, Error, FinalizationVerifier, MalformedCertificateError,
};

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoHeader;

/// Domain separation used by Tempo simplex signing and verification.
pub const NAMESPACE: &[u8] = b"TEMPO";

/// Compact evidence returned by `consensus_getFinalizedHeader`.
///
/// Every field is untrusted until checked by [`FinalizationVerifier::decode_and_verify_header`].
/// The complete header is included so its hash is reconstructed locally, including Tempo fields.
/// This format contains finalizations only, never notarizations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedHeader {
    pub epoch: u64,
    pub view: u64,
    pub digest: B256,
    /// Hex-encoded Commonware finalization certificate.
    pub certificate: String,
    pub header: TempoHeader,
}
