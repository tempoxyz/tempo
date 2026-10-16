use alloy_primitives::{Address, Bytes};
use alloy_rlp::decode_exact;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use tempo_primitives::{
    SignatureType,
    transaction::{
        MultisigConfig, MultisigConfigError, MultisigQuorumError, MultisigSignatureError,
    },
};

mod owners;

/// One independently signed configurable role in a simulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultisigSimulationSpec {
    /// Signing account for a grant; omitted for a direct parent signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Address>,
    /// Full configuration at the requested state, encoded as RLP bytes.
    #[serde(with = "serde_multisig_config")]
    pub config: MultisigConfig,
    /// Primitive owners in signing order.
    pub approvals: Vec<MultisigSimulationApproval>,
}

/// Primitive signature cost to model for one configured owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultisigSimulationApproval {
    pub owner: Address,
    /// Omission conservatively models a maximum-size `WebAuthn` approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SignatureType>,
    /// `WebAuthn` data-length hint; see [`TempoTransactionRequest::key_data`](super::TempoTransactionRequest::key_data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Bytes>,
}

/// Why a multisig simulation spec was rejected.
///
/// The `Display` text is returned to RPC callers unchanged.
#[derive(Debug, thiserror::Error)]
pub enum MultisigSimulationError {
    /// A grant's signer is not the role account.
    #[error("multisig simulation signer does not match the role account")]
    SignerMismatch,
    /// The claimed owner quorum is invalid.
    #[error("{0}")]
    Quorum(MultisigQuorumError),
    /// The multisig configuration is invalid for the role account.
    #[error("{0}")]
    Config(MultisigConfigError),
    /// An approval's `keyData` is not a 1-, 2-, or 4-byte length hint.
    #[error("keyData must contain a 1-, 2-, or 4-byte length hint")]
    InvalidKeyData,
    /// An approval names the multisig key type, which owners cannot use.
    #[error("multisig owners must use primitive signatures")]
    NestedMultisigOwner,
    /// The mock multisig signature could not be constructed.
    #[error("{0}")]
    Signature(MultisigSignatureError),
}

mod serde_multisig_config {
    use super::*;
    pub(super) fn serialize<S: Serializer>(
        config: &MultisigConfig,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Bytes::from(alloy_rlp::encode(config)).serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<MultisigConfig, D::Error> {
        let encoded = Bytes::deserialize(deserializer)?;
        decode_exact(&encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
pub(super) mod tests;
