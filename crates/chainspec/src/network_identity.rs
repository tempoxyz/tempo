//! Compiled network identities.

use std::sync::OnceLock;

use alloy_primitives::hex;
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use eyre::Context;
use serde::{Deserialize, Deserializer, de::Error as _};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

/// This holds the key that is known to be active. The genesis-derived
/// value must be updated with a newer identity after a full DKG rotation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    /// First epoch for which `identity` is expected to verify finalizations.
    pub from_epoch: u64,
    /// BLS threshold public key.
    #[serde(deserialize_with = "deserialize_identity")]
    pub identity: <MinSig as Variant>::Public,
}

impl NetworkIdentity {
    pub(crate) fn mainnet() -> Self {
        static IDENTITY: OnceLock<NetworkIdentity> = OnceLock::new();

        IDENTITY
            .get_or_init(|| {
                serde_json::from_str(env!("TEMPO_MAINNET_NETWORK_IDENTITY"))
                    .expect("valid mainnet network identity")
            })
            .clone()
    }

    pub(crate) fn testnet() -> Self {
        static IDENTITY: OnceLock<NetworkIdentity> = OnceLock::new();

        IDENTITY
            .get_or_init(|| {
                serde_json::from_str(env!("TEMPO_TESTNET_NETWORK_IDENTITY"))
                    .expect("valid testnet network identity")
            })
            .clone()
    }

    pub(crate) fn from_extra_data(extra_data: &[u8]) -> eyre::Result<Self> {
        let mut extra_data = commonware_codec::Copying(extra_data);
        let outcome =
            OnchainDkgOutcome::read(&mut extra_data).wrap_err("unable to parse dkg outcome")?;

        Ok(Self {
            from_epoch: outcome.epoch,
            identity: *outcome.network_identity(),
        })
    }
}

fn deserialize_identity<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<<MinSig as Variant>::Public, D::Error> {
    let bytes = hex::deserialize::<_, [u8; 96]>(deserializer)?;
    <MinSig as Variant>::Public::read(&mut commonware_codec::Copying(bytes.as_ref()))
        .map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use test_case::test_case;

    #[test_case(NetworkIdentity::mainnet(), env!("TEMPO_MAINNET_NETWORK_IDENTITY"))]
    #[test_case(NetworkIdentity::testnet(), env!("TEMPO_TESTNET_NETWORK_IDENTITY"))]
    fn compiled_identities_match_files(identity: NetworkIdentity, json: &str) {
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

    #[test_case("0x00".to_owned() => "invalid string length")]
    #[test_case("gg".repeat(96) => "invalid character 'g' at position 0")]
    #[test_case("00".repeat(96) => "Validation Error: Context(G2), Message(Bad encoding)")]
    fn deserialize_rejects_invalid_identity(encoded: String) -> String {
        let json = serde_json::json!({ "from_epoch": 2042, "identity": encoded });
        serde_json::from_value::<NetworkIdentity>(json)
            .unwrap_err()
            .to_string()
    }
}
