//! Full-block adapter for the shared, body-independent finalization verifier.

use alloy_consensus::Sealable as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use rand_core::CryptoRng;
use reth_consensus::ConsensusError;
use tempo_evm::consensus::validate_body_against_header;
use tempo_node::rpc::consensus::CertifiedBlock;

pub use tempo_finality::CertificateVerificationError;
pub(crate) use tempo_finality::FinalizationVerifier;

use crate::consensus::Digest;

#[cfg(test)]
mod test;

/// Preserve execution-body validation for full-node certificate consumers.
pub(crate) trait CertifiedBlockVerification {
    fn decode_and_verify(
        &self,
        rng: &mut impl CryptoRng,
        certified: &CertifiedBlock,
    ) -> Result<Finalization<Scheme<PublicKey, MinSig>, Digest>, Error>;
}

impl CertifiedBlockVerification for FinalizationVerifier {
    fn decode_and_verify(
        &self,
        rng: &mut impl CryptoRng,
        certified: &CertifiedBlock,
    ) -> Result<Finalization<Scheme<PublicKey, MinSig>, Digest>, Error> {
        validate_body_against_header(certified.block.body(), certified.block.header())
            .map_err(Error::BlockBodyMismatch)?;
        if certified.block.hash() != certified.block.header().hash_slow() {
            return Err(tempo_finality::Error::BlockDigestMismatch.into());
        }
        Ok(self.decode_and_verify_header(rng, &certified.header_evidence())?)
    }
}

/// Failure in full-block or header/certificate verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("finalized block body does not match its header")]
    BlockBodyMismatch(#[source] ConsensusError),
    #[error(transparent)]
    Header(#[from] tempo_finality::Error),
}

impl Error {
    pub(crate) const fn is_signature_mismatch(&self) -> bool {
        matches!(self, Self::Header(error) if error.is_signature_mismatch())
    }
}
