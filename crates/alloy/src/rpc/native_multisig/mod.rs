use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use tempo_primitives::{
    SignatureType,
    transaction::{
        MAX_MULTISIG_SIGNATURES, MultisigConfig, MultisigQuorumError, MultisigWeightAccumulator,
    },
};

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

impl MultisigSimulationSpec {
    /// Checks the claimed primitive quorum before constructing simulation signatures.
    pub fn validate_owners(&self, account: Address) -> Result<(), String> {
        if self.signer.is_some_and(|signer| signer != account) {
            return Err("multisig simulation signer does not match the role account".into());
        }
        if self.approvals.len() > MAX_MULTISIG_SIGNATURES {
            return Err(MultisigQuorumError::TooManySignatures.to_string());
        }
        self.config
            .validate_for_account(account)
            .map_err(|error| error.to_string())?;
        let mut weight = MultisigWeightAccumulator::new(self.config.threshold)
            .map_err(|error| error.to_string())?;
        for approval in &self.approvals {
            if approval
                .key_data
                .as_ref()
                .is_some_and(|hint| !matches!(hint.len(), 1 | 2 | 4))
            {
                return Err("keyData must contain a 1-, 2-, or 4-byte length hint".into());
            }
            if approval.key_type == Some(SignatureType::Multisig) {
                return Err("multisig owners must use primitive signatures".into());
            }
            let owner_weight = self
                .config
                .owner_weight(approval.owner)
                .ok_or("multisig signer is not an owner")?;
            weight
                .record_owner(approval.owner, owner_weight)
                .map_err(|error| error.to_string())?;
        }
        weight.finish().map_err(|error| error.to_string())
    }
}

/// Primitive signature cost to model for one configured owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultisigSimulationApproval {
    pub owner: Address,
    /// Omission conservatively models a maximum-size WebAuthn approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SignatureType>,
    /// WebAuthn data-length hint; see [`TempoTransactionRequest::key_data`](super::TempoTransactionRequest::key_data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Bytes>,
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
        alloy_rlp::decode_exact(&encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
pub(super) mod tests;
