use alloy_primitives::{Address, Bytes};
use alloy_rlp::decode_exact;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use tempo_primitives::{SignatureType, transaction::ConfigurableAccountConfig};

/// One independently signed configurable role in a simulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurableAccountSimulationSpec {
    /// Signing account for a grant; omitted for a direct parent signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Address>,
    /// Full configuration at the requested state, encoded as RLP bytes.
    #[serde(with = "serde_configurable_account_config")]
    pub config: ConfigurableAccountConfig,
    /// Primitive owners in signing order.
    pub approvals: Vec<ConfigurableAccountSimulationApproval>,
}

/// Primitive signature cost to model for one configured owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurableAccountSimulationApproval {
    /// Configured owner whose approval is modeled.
    pub owner: Address,
    /// Omission conservatively models a maximum-size `WebAuthn` approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SignatureType>,
    /// `WebAuthn` data-length hint; see [`TempoTransactionRequest::key_data`](super::TempoTransactionRequest::key_data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Bytes>,
}

mod serde_configurable_account_config {
    use super::*;
    pub(super) fn serialize<S: Serializer>(
        config: &ConfigurableAccountConfig,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Bytes::from(alloy_rlp::encode(config)).serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ConfigurableAccountConfig, D::Error> {
        let encoded = Bytes::deserialize(deserializer)?;
        decode_exact(&encoded).map_err(D::Error::custom)
    }
}
