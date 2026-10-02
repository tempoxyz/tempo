//! Compiled network identities.

use alloy_primitives::hex;
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use eyre::Context;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

const TESTNET_NETWORK_IDENTITY_EPOCH: u64 = 1747;
const TESTNET_NETWORK_IDENTITY: [u8; 96] = hex!(
    "0x967ae1a6d3ddbe5cb0fe5e6fc58e74249787b4a277619b549fed6609d0466054"
    "0dd2449cd7174def35e40f544e5ad72d15d064191a205ed6e0c49619c68f9751"
    "08b614d0d51def9a8416a10a07c4193bea0cbbc4252ec1b33f21095a5d7aa590"
);

const MAINNET_NETWORK_IDENTITY_EPOCH: u64 = 0;
const MAINNET_NETWORK_IDENTITY: [u8; 96] = hex!(
    "0xa217bb85001d4dcf8e5c50136f77af88cb2cab1857279b91c6240f41cca95c4f"
    "43f6dcab3e0dfb87dafb3ecbeb6251e90a5df2e6c47432482821cd8b84665ee4"
    "642589d2d9628a92b03e2bbfb00e006d038cd98def76d2a41b7c228c05f5a193"
);

/// This holds the key that is known to be active. The genesis-derived
/// value must be updated with a newer identity after a full DKG rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkIdentity {
    /// First epoch for which `identity` is expected to verify finalizations.
    pub from_epoch: u64,
    /// BLS threshold public key.
    pub identity: <MinSig as Variant>::Public,
}

impl NetworkIdentity {
    pub(crate) fn mainnet() -> Self {
        let identity = <MinSig as Variant>::Public::read(&mut MAINNET_NETWORK_IDENTITY.as_ref())
            .expect("valid network identity");

        Self {
            identity,
            from_epoch: MAINNET_NETWORK_IDENTITY_EPOCH,
        }
    }

    pub(crate) fn testnet() -> Self {
        let identity = <MinSig as Variant>::Public::read(&mut TESTNET_NETWORK_IDENTITY.as_ref())
            .expect("valid network identity");

        Self {
            identity,
            from_epoch: TESTNET_NETWORK_IDENTITY_EPOCH,
        }
    }

    pub(crate) fn from_extra_data(extra_data: &[u8]) -> eyre::Result<Self> {
        let mut extra_data = extra_data;
        let outcome =
            OnchainDkgOutcome::read(&mut extra_data).wrap_err("unable to parse dkg outcome")?;

        Ok(Self {
            from_epoch: outcome.epoch,
            identity: *outcome.network_identity(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;

    #[test]
    fn compiled_identity_decodes() {
        let identity = NetworkIdentity::testnet();

        assert_eq!(identity.from_epoch, TESTNET_NETWORK_IDENTITY_EPOCH);
        assert_eq!(
            identity.identity.encode().as_ref(),
            TESTNET_NETWORK_IDENTITY.as_ref()
        );

        let identity = NetworkIdentity::mainnet();

        assert_eq!(identity.from_epoch, MAINNET_NETWORK_IDENTITY_EPOCH);
        assert_eq!(
            identity.identity.encode().as_ref(),
            MAINNET_NETWORK_IDENTITY.as_ref()
        );
    }
}
