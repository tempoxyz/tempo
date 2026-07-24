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
use tempo_chainspec::NetworkIdentity;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::CertifiedBlock;

use crate::{config::NAMESPACE, consensus::Digest, epoch::SchemeProvider};

#[cfg(test)]
mod test;

/// A decoded Tempo finalization certificate.
pub type TempoFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;

/// Verifies finalization certificates against a trusted network identity.
///
/// A caller following the chain should pass each finalized epoch-boundary block to
/// [`Self::register_boundary`] before verifying certificates from the next epoch.
#[derive(Clone)]
pub struct FinalizationVerifier {
    schemes: SchemeProvider,
    network_identity: NetworkIdentity,
    network_scheme: Arc<Scheme<PublicKey, MinSig>>,
    epoch_strategy: FixedEpocher,
}

impl FinalizationVerifier {
    /// Create a verifier anchored at the supplied network identity.
    pub fn new(network_identity: NetworkIdentity, epoch_strategy: FixedEpocher) -> Self {
        Self::with_scheme_provider(network_identity, SchemeProvider::new(), epoch_strategy)
    }

    pub(crate) fn with_scheme_provider(
        network_identity: NetworkIdentity,
        schemes: SchemeProvider,
        epoch_strategy: FixedEpocher,
    ) -> Self {
        let network_scheme = Arc::new(Scheme::certificate_verifier(
            NAMESPACE,
            network_identity.identity,
        ));
        Self {
            schemes,
            network_identity,
            network_scheme,
            epoch_strategy,
        }
    }

    /// Return the verifier's authoritative network identity.
    pub const fn network_identity(&self) -> &NetworkIdentity {
        &self.network_identity
    }

    /// Install the identity encoded in a finalized epoch-boundary block.
    ///
    /// The caller is responsible for ensuring `extra_data` came from a boundary block on a chain
    /// authenticated by a previously verified finalization.
    pub fn register_boundary(
        &self,
        mut extra_data: &[u8],
    ) -> Result<OnchainDkgOutcome, commonware_codec::Error> {
        let outcome = OnchainDkgOutcome::read(&mut extra_data)?;
        self.schemes.register(
            outcome.epoch,
            Scheme::certificate_verifier(NAMESPACE, *outcome.network_identity()),
        );
        Ok(outcome)
    }

    /// Decode and verify a certified block returned by the Tempo consensus RPC.
    pub fn verify(
        &self,
        rng: &mut impl CryptoRng,
        certified: &CertifiedBlock,
    ) -> Result<TempoFinalization, FinalizationVerificationError> {
        let bytes = alloy_primitives::hex::decode(&certified.certificate).map_err(|error| {
            FinalizationVerificationError::MalformedCertificate(error.to_string())
        })?;
        let finalization = TempoFinalization::decode(&*bytes).map_err(|error| {
            FinalizationVerificationError::MalformedCertificate(error.to_string())
        })?;

        if finalization.proposal.payload.0 != certified.block.hash() {
            return Err(FinalizationVerificationError::BlockDigestMismatch);
        }

        let epoch = finalization.epoch();
        let height = certified.block.number();
        let expected_epoch = self
            .epoch_strategy
            .containing(Height::new(height))
            .expect("fixed epoch strategy supports every block height")
            .epoch();
        if epoch != expected_epoch {
            return Err(FinalizationVerificationError::EpochMismatch {
                height,
                expected: expected_epoch.get(),
                actual: epoch.get(),
            });
        }

        let (scheme, used_network_identity) = match self.schemes.scheme(epoch) {
            Some(scheme) => (scheme, false),
            None if epoch.get() >= self.network_identity.from_epoch => {
                (self.network_scheme.clone(), true)
            }
            None => {
                return Err(FinalizationVerificationError::IdentityUnavailable {
                    epoch: epoch.get(),
                    identity_from_epoch: self.network_identity.from_epoch,
                });
            }
        };

        if !finalization.verify(rng, scheme.as_ref(), &Sequential) {
            return Err(FinalizationVerificationError::InvalidCertificate);
        }

        // Marshal verifies the certificate again while installing a floor, so retain a
        // successfully used network-identity fallback under the certificate's epoch.
        if used_network_identity {
            self.schemes.register(epoch, (*scheme).clone());
        }

        Ok(finalization)
    }
}

/// An error returned while verifying a Tempo finalization certificate.
#[derive(Debug, thiserror::Error)]
pub enum FinalizationVerificationError {
    /// The certificate was not valid hex or did not decode as a Tempo finalization.
    #[error("malformed finalization certificate: {0}")]
    MalformedCertificate(String),
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
    /// No trusted identity is available for the certificate's epoch.
    #[error(
        "finalization epoch `{epoch}` behind network identity starting epoch `{identity_from_epoch}`"
    )]
    IdentityUnavailable {
        epoch: u64,
        identity_from_epoch: u64,
    },
    /// The threshold signature did not verify against the trusted identity.
    #[error("invalid finalization certificate")]
    InvalidCertificate,
}
