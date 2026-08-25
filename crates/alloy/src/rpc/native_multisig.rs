use alloy_primitives::{Address, Bytes};
use core::{fmt, marker::PhantomData};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use tempo_primitives::{
    SignatureType,
    transaction::{MAX_MULTISIG_SIGNATURES, MultisigConfig},
};

#[cfg(feature = "revm")]
use {
    alloy_primitives::B256,
    tempo_primitives::{
        TempoSignature,
        transaction::{MultisigSignature, PrimitiveSignature},
    },
};

/// Native multisig witness used only to construct an RPC simulation signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigSimulationWitness {
    /// Account authorized by this witness.
    pub account: Address,
    /// Complete applicable configuration.
    pub config: MultisigConfig,
    /// Owner approvals to model.
    #[serde(deserialize_with = "deserialize_multisig_simulation_approvals")]
    pub approvals: Vec<MultisigSimulationApproval>,
}

/// Native multisig owner approval used for RPC simulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum MultisigSimulationApproval {
    /// Primitive owner approval.
    Primitive {
        /// Configured owner address.
        owner: Address,
        /// Signature type to model. Omission uses a maximum-size WebAuthn signature.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_type: Option<SignatureType>,
        /// Optional signature-specific gas-estimation data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_data: Option<Bytes>,
    },
    /// Nested native multisig owner signature.
    Multisig {
        /// Depth-2 multisig witness. Its approvals must all be primitive.
        witness: MultisigSimulationNestedWitness,
    },
}

/// Depth-2 native multisig witness used for RPC simulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigSimulationNestedWitness {
    /// Nested multisig account.
    pub account: Address,
    /// Complete applicable configuration.
    pub config: MultisigConfig,
    /// Primitive owner approvals to model.
    #[serde(deserialize_with = "deserialize_multisig_simulation_approvals")]
    pub approvals: Vec<MultisigSimulationPrimitiveApproval>,
}

/// Primitive approval in a depth-2 multisig simulation witness.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigSimulationPrimitiveApproval {
    /// Configured owner address.
    pub owner: Address,
    /// Signature type to model. Omission uses a maximum-size WebAuthn signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SignatureType>,
    /// Optional signature-specific gas-estimation data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_data: Option<Bytes>,
}

fn deserialize_multisig_simulation_approvals<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ApprovalsVisitor<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for ApprovalsVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_MULTISIG_SIGNATURES} multisig simulation approvals"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if seq
                .size_hint()
                .is_some_and(|size| size > MAX_MULTISIG_SIGNATURES)
            {
                return Err(A::Error::custom("too many multisig simulation approvals"));
            }

            let mut approvals = Vec::new();
            while approvals.len() < MAX_MULTISIG_SIGNATURES {
                let Some(approval) = seq.next_element()? else {
                    return Ok(approvals);
                };
                approvals.push(approval);
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(A::Error::custom("too many multisig simulation approvals"));
            }
            Ok(approvals)
        }
    }

    deserializer.deserialize_seq(ApprovalsVisitor(PhantomData))
}

#[cfg(feature = "revm")]
#[doc(hidden)]
pub fn create_mock_native_multisig_signature(
    witness: &MultisigSimulationWitness,
) -> Result<MultisigSignature, &'static str> {
    let approvals = witness
        .approvals
        .iter()
        .map(|approval| -> Result<_, &'static str> {
            match approval {
                MultisigSimulationApproval::Primitive {
                    owner,
                    key_type,
                    key_data,
                } => Ok((
                    *owner,
                    TempoSignature::Primitive(create_multisig_simulation_primitive(
                        *key_type,
                        key_data.clone(),
                    )),
                )),
                MultisigSimulationApproval::Multisig { witness } => {
                    let nested = create_mock_nested_multisig_signature(witness)?;
                    Ok((nested.account(), TempoSignature::Multisig(nested)))
                }
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    assemble_mock_multisig_signature(witness.account, &witness.config, approvals)
}

#[cfg(feature = "revm")]
fn create_mock_nested_multisig_signature(
    witness: &MultisigSimulationNestedWitness,
) -> Result<MultisigSignature, &'static str> {
    let approvals = witness
        .approvals
        .iter()
        .map(|approval| {
            (
                approval.owner,
                TempoSignature::Primitive(create_multisig_simulation_primitive(
                    approval.key_type,
                    approval.key_data.clone(),
                )),
            )
        })
        .collect();
    assemble_mock_multisig_signature(witness.account, &witness.config, approvals)
}

#[cfg(feature = "revm")]
fn assemble_mock_multisig_signature(
    account: Address,
    config: &MultisigConfig,
    approvals: Vec<(Address, TempoSignature)>,
) -> Result<MultisigSignature, &'static str> {
    use tempo_primitives::transaction::{MultisigQuorumError, MultisigWeightAccumulator};

    config
        .validate_for_account(account)
        .map_err(|error| error.as_str())?;
    let mut weight =
        MultisigWeightAccumulator::new(config.threshold).map_err(|error| error.as_str())?;
    let approval_count = approvals.len();
    let mut signatures = Vec::new();
    for (index, (owner, signature)) in approvals.into_iter().enumerate() {
        record_simulation_owner(config, &mut weight, owner, index + 1 == approval_count)?;
        signatures.push(signature);
    }
    weight.finish().map_err(MultisigQuorumError::as_str)?;
    MultisigSignature::from_decoded(account, config.clone(), signatures)
        .map_err(|error| error.as_str())
}

#[cfg(feature = "revm")]
fn record_simulation_owner(
    config: &MultisigConfig,
    weight: &mut tempo_primitives::transaction::MultisigWeightAccumulator,
    owner: Address,
    is_last: bool,
) -> Result<(), &'static str> {
    use tempo_primitives::transaction::MultisigQuorumError;

    let owner_weight = config
        .owner_weight(owner)
        .ok_or(MultisigQuorumError::SignerNotOwner)
        .map_err(MultisigQuorumError::as_str)?;
    weight
        .record_owner(owner, owner_weight)
        .map_err(MultisigQuorumError::as_str)?;
    if weight.has_quorum() && !is_last {
        return Err(MultisigQuorumError::ExcessSignatures.as_str());
    }
    Ok(())
}

#[cfg(feature = "revm")]
fn create_multisig_simulation_primitive(
    key_type: Option<SignatureType>,
    key_data: Option<Bytes>,
) -> PrimitiveSignature {
    key_type.map_or_else(
        create_conservative_native_multisig_primitive_signature,
        |key_type| super::revm_compat::create_mock_primitive_signature(&key_type, key_data),
    )
}

#[cfg(feature = "revm")]
fn create_conservative_native_multisig_primitive_signature() -> PrimitiveSignature {
    use tempo_primitives::transaction::{
        MAX_WEBAUTHN_SIGNATURE_LENGTH, tt_signature::WebAuthnSignature,
    };

    const WEBAUTHN_FIXED_SIGNATURE_BYTES: usize = 128;
    PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(vec![
            0xff;
            MAX_WEBAUTHN_SIGNATURE_LENGTH
                - WEBAUTHN_FIXED_SIGNATURE_BYTES
        ]),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, address};
    use tempo_primitives::transaction::MultisigOwner;

    #[test]
    fn rejects_too_many_approvals_during_deserialization() {
        let owner = address!("0x1111111111111111111111111111111111111111");
        let approval = MultisigSimulationApproval::Primitive {
            owner,
            key_type: Some(SignatureType::Secp256k1),
            key_data: None,
        };
        let witness = MultisigSimulationWitness {
            account: address!("0x2222222222222222222222222222222222222222"),
            config: MultisigConfig {
                salt: B256::ZERO,
                version: 1,
                threshold: 1,
                owners: vec![MultisigOwner { owner, weight: 1 }],
            },
            approvals: vec![approval; MAX_MULTISIG_SIGNATURES + 1],
        };

        let encoded = serde_json::to_value(witness).unwrap();
        let error = serde_json::from_value::<MultisigSimulationWitness>(encoded).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("too many multisig simulation approvals")
        );
    }
}
