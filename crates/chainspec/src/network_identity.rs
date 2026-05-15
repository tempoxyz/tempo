//! Compiled network identities.

use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

/// A compiled weak-subjectivity anchor for the consensus network identity.
///
/// This records the BLS threshold public key that a release knows is active for
/// a chain. The genesis-derived value must be updated with a newer identity
/// after a full DKG rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkIdentity {
    /// First epoch for which `identity` is expected to verify finalizations.
    pub from_epoch: u64,
    /// BLS threshold public key.
    pub identity: <MinSig as Variant>::Public,
}

impl NetworkIdentity {
    pub(crate) fn from_genesis_extra_data(extra_data: &[u8]) -> Option<Self> {
        let outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref()).ok()?;
        Some(Self {
            from_epoch: outcome.epoch.get(),
            identity: outcome.network_identity().clone(),
        })
    }
}
