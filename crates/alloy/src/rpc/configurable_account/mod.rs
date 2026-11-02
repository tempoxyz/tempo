use alloy_primitives::{Address, Bytes};
use alloy_rlp::decode_exact;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use tempo_primitives::transaction::ConfigurableAccountConfig;

/// One independently signed configurable role in a simulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurableAccountSimulationSpec {
    /// Signing account. For a grant: the parent (the default) or an admin. For the outer
    /// signature: the role account (the sender, or the `keyId` delegate), checked when set.
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
    pub key_type: Option<PrimitiveSignatureType>,
    /// `WebAuthn` data-length hint; see [`TempoTransactionRequest::key_data`](super::TempoTransactionRequest::key_data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Bytes>,
}

/// Signature type of a primitive owner key: every [`SignatureType`](tempo_primitives::SignatureType)
/// but a configurable account, which an owner approval cannot use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrimitiveSignatureType {
    /// A secp256k1 signature.
    Secp256k1,
    /// A P256 signature.
    P256,
    /// A `WebAuthn` P256 assertion.
    WebAuthn,
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
        decode_exact(&Bytes::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
