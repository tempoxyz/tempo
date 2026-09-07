//! Verification of Tempo consensus finalization certificates.

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_consensus::{
    Epochable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider as _, ed25519::PublicKey,
};
use commonware_parallel::Sequential;
use rand_core::CryptoRng;
use reth_consensus::ConsensusError;
use tempo_chainspec::NetworkIdentity;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::consensus::validate_body_against_header;
use tempo_node::rpc::consensus::CertifiedBlock;

use crate::{config::NAMESPACE, consensus::Digest, epoch::SchemeProvider};

#[cfg(test)]
mod test;

/// Verifies finalization certificates against a trusted network identity.
///
/// A caller following the chain should pass each finalized epoch-boundary block to
/// [`Self::decode_dkg_outcome_and_register_boundary`] before verifying certificates from the next
/// epoch.
#[derive(Clone)]
pub(crate) struct FinalizationVerifier {
    scheme_provider: SchemeProvider,
    network_identity: NetworkIdentity,
    network_scheme: Arc<Scheme<PublicKey, MinSig>>,
    epoch_strategy: FixedEpocher,
}

impl FinalizationVerifier {
    /// Create a verifier anchored at the supplied network identity.
    pub(crate) fn new(network_identity: NetworkIdentity, epoch_strategy: FixedEpocher) -> Self {
        let network_scheme = Arc::new(Scheme::certificate_verifier(
            NAMESPACE,
            network_identity.identity,
        ));
        Self {
            scheme_provider: SchemeProvider::new(),
            network_identity,
            network_scheme,
            epoch_strategy,
        }
    }

    pub(crate) fn with_scheme_provider(self, scheme_provider: SchemeProvider) -> Self {
        Self {
            scheme_provider,
            ..self
        }
    }

    /// Return the verifier's authoritative network identity.
    pub(crate) const fn network_identity(&self) -> &NetworkIdentity {
        &self.network_identity
    }

    /// Install the identity encoded in a finalized epoch-boundary block.
    ///
    /// The caller is responsible for ensuring `extra_data` came from a boundary block on a chain
    /// authenticated by a previously verified finalization.
    pub(crate) fn decode_dkg_outcome_and_register_boundary(
        &self,
        mut extra_data: &[u8],
    ) -> Result<OnchainDkgOutcome, commonware_codec::Error> {
        let outcome = OnchainDkgOutcome::read(&mut extra_data)?;
        self.scheme_provider.register(
            outcome.epoch,
            Scheme::certificate_verifier(NAMESPACE, *outcome.network_identity()),
        );
        Ok(outcome)
    }

    /// Decode and verify a certified block returned by the Tempo consensus RPC.
    pub(crate) fn decode_and_verify(
        &self,
        rng: &mut impl CryptoRng,
        certified: &CertifiedBlock,
    ) -> Result<Finalization<Scheme<PublicKey, MinSig>, Digest>, Error> {
        validate_body_against_header(certified.block.body(), certified.block.header())
            .map_err(Error::BlockBodyMismatch)?;

        // TODO: Decode certificates when constructing `CertifiedBlock` instead of keeping their
        // bytes opaque and decoding them at each consumer.
        let bytes = alloy_primitives::hex::decode(&certified.certificate)
            .map_err(|error| Error::MalformedCertificate(error.into()))?;
        let finalization = Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(&*bytes)
            .map_err(|error| Error::MalformedCertificate(error.into()))?;

        if finalization.proposal.payload.0 != certified.block.hash() {
            return Err(Error::BlockDigestMismatch);
        }

        let epoch = finalization.epoch();
        let height = certified.block.number();
        let expected_epoch = self
            .epoch_strategy
            .containing(Height::new(height))
            .expect("fixed epoch strategy supports every block height")
            .epoch();
        if epoch != expected_epoch {
            return Err(Error::EpochMismatch {
                height,
                expected: expected_epoch.get(),
                actual: epoch.get(),
            });
        }

        self.verify_certificate(rng, &finalization)?;

        Ok(finalization)
    }

    /// Verify an already decoded certificate without requiring its block.
    pub(crate) fn verify_certificate<R: CryptoRng>(
        &self,
        rng: &mut R,
        finalization: &Finalization<Scheme<PublicKey, MinSig>, Digest>,
    ) -> Result<(), CertificateVerificationError> {
        let epoch = finalization.epoch();
        let (scheme, used_network_identity) = match self.scheme_provider.scheme(epoch) {
            Some(scheme) => (scheme, false),
            None if epoch.get() >= self.network_identity.from_epoch => {
                (self.network_scheme.clone(), true)
            }
            None => {
                return Err(CertificateVerificationError::IdentityUnavailable {
                    epoch: epoch.get(),
                    identity_from_epoch: self.network_identity.from_epoch,
                });
            }
        };

        if !finalization.verify(rng, scheme.as_ref(), &Sequential) {
            return Err(if used_network_identity {
                CertificateVerificationError::FallbackVerificationFailed
            } else {
                CertificateVerificationError::Invalid
            });
        }

        // Marshal verifies the certificate again while installing a floor, so retain a
        // successfully used network-identity fallback under the certificate's epoch.
        if used_network_identity {
            self.scheme_provider.register(epoch, (*scheme).clone());
        }

        Ok(())
    }
}

/// Why an already decoded certificate could not be verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertificateVerificationError {
    /// No trusted identity is available for the certificate's epoch.
    #[error(
        "finalization epoch `{epoch}` behind network identity starting epoch `{identity_from_epoch}`"
    )]
    IdentityUnavailable {
        epoch: u64,
        identity_from_epoch: u64,
    },
    /// The signature failed against a scheme learned from a finalized boundary.
    #[error("finalization certificate verification failed")]
    Invalid,
    /// The signature failed against the static fallback identity. The epoch-specific identity may
    /// have rotated while the follower was offline.
    #[error("finalization certificate did not verify against the network identity fallback")]
    FallbackVerificationFailed,
}

/// An error returned while verifying a Tempo finalization certificate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The block body did not match the commitments in its header.
    #[error("finalized block body does not match its header")]
    BlockBodyMismatch(#[source] ConsensusError),
    /// The certificate was not valid hex or did not decode as a Tempo finalization.
    #[error("malformed finalization certificate")]
    MalformedCertificate(#[source] MalformedCertificateError),
    /// The certificate did not finalize the block included in the RPC response.
    #[error("finalization and block digest mismatch")]
    BlockDigestMismatch,
    /// The certificate's epoch did not match the epoch containing its block.
    #[error(
        "finalization for block `{height}` belongs to epoch `{actual}`, expected epoch `{expected}`"
    )]
    EpochMismatch {
        height: u64,
        expected: u64,
        actual: u64,
    },
    /// The certificate could not be verified against an available identity.
    #[error(transparent)]
    CertificateVerification(#[from] CertificateVerificationError),
}

impl Error {
    /// Whether the certificate's signature mismatched an available identity.
    pub(crate) const fn is_signature_mismatch(&self) -> bool {
        matches!(
            self,
            Self::CertificateVerification(
                CertificateVerificationError::Invalid
                    | CertificateVerificationError::FallbackVerificationFailed
            )
        )
    }
}

/// The concrete decoding error for a malformed finalization certificate.
#[derive(Debug, thiserror::Error)]
pub enum MalformedCertificateError {
    #[error("invalid hex encoding")]
    Hex(#[from] alloy_primitives::hex::FromHexError),
    #[error(transparent)]
    Codec(#[from] commonware_codec::Error),
}
