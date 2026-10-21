//! Compiled network identities.

use std::sync::OnceLock;

use alloy_primitives::hex;
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use eyre::Context;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

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
        static IDENTITY: OnceLock<NetworkIdentity> = OnceLock::new();

        IDENTITY
            .get_or_init(|| Self::from_json(include_str!("../../../mainnet-network-identity.json")))
            .clone()
    }

    pub(crate) fn testnet() -> Self {
        static IDENTITY: OnceLock<NetworkIdentity> = OnceLock::new();

        IDENTITY
            .get_or_init(|| Self::from_json(include_str!("../../../testnet-network-identity.json")))
            .clone()
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

    fn from_json(json: &str) -> Self {
        let config = serde_json::from_str::<Config>(json).expect("valid network identity JSON");
        let bytes = hex::decode_to_array::<_, 96>(config.identity)
            .expect("network identity must be a 96-byte hex string");
        let identity =
            <MinSig as Variant>::Public::read(&mut bytes.as_ref()).expect("valid network identity");

        Self {
            identity,
            from_epoch: config.from_epoch,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    from_epoch: u64,
    identity: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;

    #[test]
    fn compiled_identities_match_files() {
        for (identity, json) in [
            (
                NetworkIdentity::mainnet(),
                include_str!("../../../mainnet-network-identity.json"),
            ),
            (
                NetworkIdentity::testnet(),
                include_str!("../../../testnet-network-identity.json"),
            ),
        ] {
            let published = serde_json::from_str::<serde_json::Value>(json).unwrap();

            assert_eq!(
                identity.from_epoch,
                published["from_epoch"].as_u64().unwrap()
            );
            assert_eq!(
                hex::encode_prefixed(identity.identity.encode()),
                published["identity"]
            );
        }
    }
}
