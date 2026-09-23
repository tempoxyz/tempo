use super::*;
#[cfg(feature = "reth")]
use crate::rpc::TempoTransactionRequest;
use alloy_primitives::B256;
#[cfg(feature = "reth")]
use alloy_rpc_types_eth::TransactionRequest;
#[cfg(feature = "reth")]
use alloy_signer::SignerSync;
#[cfg(feature = "reth")]
use alloy_signer_local::PrivateKeySigner;
#[cfg(feature = "reth")]
use reth_evm::FromTxWithEncoded;
#[cfg(feature = "reth")]
use reth_rpc_convert::{SignableTxRequest, TryIntoSimTx};
#[cfg(feature = "revm")]
use tempo_chainspec::hardfork::TempoHardfork;
#[cfg(feature = "revm")]
use tempo_primitives::TempoSignature;
use tempo_primitives::transaction::MultisigOwner;
#[cfg(feature = "reth")]
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{KeyAuthorization, KeychainSignature, multisig_digest},
};
#[cfg(feature = "reth")]
use tempo_revm::{ExecutionContext, TempoTxEnv};
#[cfg(feature = "revm")]
use tempo_revm::{
    TempoBatchCallEnv, gas_params::tempo_gas_params, handler::calculate_aa_batch_intrinsic_gas,
};

fn spec() -> MultisigSimulationSpec {
    MultisigSimulationSpec {
        config: MultisigConfig {
            salt: B256::ZERO,
            version: 1,
            threshold: 2,
            owners: vec![
                MultisigOwner {
                    owner: Address::repeat_byte(1),
                    weight: 1,
                },
                MultisigOwner {
                    owner: Address::repeat_byte(2),
                    weight: 1,
                },
                MultisigOwner {
                    owner: Address::repeat_byte(3),
                    weight: 1,
                },
            ],
        },
        approvals: [1, 2]
            .map(|owner| MultisigSimulationApproval {
                owner: Address::repeat_byte(owner),
                key_type: Some(SignatureType::Secp256k1),
                key_data: None,
            })
            .to_vec(),
    }
}

#[test_case::test_case(2, true; "valid")]
#[test_case::test_case(0, false; "zero threshold")]
#[test_case::test_case(4, false; "unreachable threshold")]
#[test_case::test_case(9, false; "threshold over cap")]
fn simulation_spec_roundtrips_config_as_rlp_bytes(threshold: u8, valid: bool) {
    let mut spec = spec();
    spec.config.threshold = threshold;
    let mut json = serde_json::to_value(&spec).unwrap();
    assert!(json["config"].as_str().unwrap().starts_with("0x"));
    let decoded = serde_json::from_value::<MultisigSimulationSpec>(json.clone()).unwrap();
    assert_eq!(decoded, spec);
    let account = Address::repeat_byte(9);
    assert_eq!(decoded.validate_owners(account).is_ok(), valid);
    #[cfg(feature = "revm")]
    assert_eq!(
        create_mock_native_multisig_signature(account, &decoded).is_ok(),
        valid
    );
    let mut encoded = alloy_rlp::encode(&spec.config);
    encoded.push(0x80);
    json["config"] = serde_json::to_value(Bytes::from(encoded)).unwrap();
    assert!(serde_json::from_value::<MultisigSimulationSpec>(json).is_err());
}

#[test]
fn simulation_spec_rejects_unknown_fields_and_malformed_hints() {
    let mut json = serde_json::to_value(spec()).unwrap();
    json["aprovals"] = serde_json::json!([]);
    assert!(serde_json::from_value::<MultisigSimulationSpec>(json).is_err());
    for len in [0, 1, 2, 3, 4, 5, 8192] {
        let mut spec = spec();
        spec.approvals[0].key_data = Some(Bytes::from(vec![0; len]));
        assert_eq!(
            spec.validate_owners(Address::repeat_byte(9)).is_ok(),
            matches!(len, 1 | 2 | 4),
            "hint length {len}"
        );
    }
}

#[test_case::test_case(vec![]; "empty")]
#[test_case::test_case(vec![1]; "insufficient")]
#[test_case::test_case(vec![2,1]; "unsorted")]
#[test_case::test_case(vec![1,1]; "duplicate")]
#[test_case::test_case(vec![1,4]; "nonowner")]
#[test_case::test_case(vec![1,2,3]; "after threshold")]
#[test_case::test_case(vec![1;9]; "too many")]
fn rejects_invalid_claimed_quorums(owners: Vec<u8>) {
    let mut spec = spec();
    spec.approvals = owners
        .into_iter()
        .map(|owner| MultisigSimulationApproval {
            owner: Address::repeat_byte(owner),
            key_type: None,
            key_data: None,
        })
        .collect();
    assert!(spec.validate_owners(Address::repeat_byte(9)).is_err());
}

#[test]
fn rejects_nested_owner_and_oversized_json_list() {
    let mut nested = spec();
    nested.approvals[0].key_type = Some(SignatureType::Multisig);
    assert!(nested.validate_owners(Address::repeat_byte(9)).is_err());
    let mut json = serde_json::to_value(spec()).unwrap();
    json["approvals"] = serde_json::json!([{"type":"multisig","spec":{}}]);
    assert!(serde_json::from_value::<MultisigSimulationSpec>(json).is_err());
    let mut value = spec();
    value.approvals = vec![value.approvals[0].clone(); 9];
    let decoded: MultisigSimulationSpec =
        serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap();
    assert_eq!(
        decoded.validate_owners(Address::repeat_byte(9)),
        Err(MultisigQuorumError::TooManySignatures.to_string())
    );
    #[cfg(feature = "revm")]
    assert!(create_mock_native_multisig_signature(Address::repeat_byte(9), &decoded).is_err());
}

#[cfg(feature = "revm")]
#[test]
fn mock_approvals_are_bounded_and_conservative() {
    let mut spec = spec();
    spec.approvals[0].key_type = None;
    let signature = create_mock_native_multisig_signature(Address::repeat_byte(9), &spec).unwrap();
    assert_eq!(signature.signatures()[0].encoded_length(), 2049);
    assert_eq!(signature.signatures()[1].encoded_length(), 65);
}

#[cfg(feature = "revm")]
#[test_case::test_case(128; "small")]
#[test_case::test_case(800; "default size")]
#[test_case::test_case(1920; "maximum")]
fn explicit_webauthn_approvals_charge_worst_case_data(size: u16) {
    let mut spec = spec();
    for approval in &mut spec.approvals {
        approval.key_type = Some(SignatureType::WebAuthn);
        approval.key_data = Some(Bytes::copy_from_slice(&size.to_be_bytes()));
    }
    let signature = create_mock_native_multisig_signature(Address::repeat_byte(9), &spec).unwrap();
    for approval in signature.signatures() {
        let PrimitiveSignature::WebAuthn(approval) = approval else {
            panic!("wrong mock type")
        };
        assert_eq!(approval.webauthn_data.len(), usize::from(size));
        assert!(approval.webauthn_data.iter().all(|byte| *byte != 0));
        assert_eq!(approval.webauthn_data[32], 0x01);
    }
    let env = TempoBatchCallEnv {
        signature: TempoSignature::Multisig(signature),
        ..Default::default()
    };
    let fork = TempoHardfork::T12;
    let gas = tempo_gas_params(fork);
    let intrinsic = |env: &TempoBatchCallEnv| {
        calculate_aa_batch_intrinsic_gas(
            env,
            &gas,
            None::<std::iter::Empty<&alloy_eips::eip2930::AccessListItem>>,
            fork,
        )
        .unwrap()
        .initial_total_gas()
    };
    // Same witness with no WebAuthn data isolates the charge for both approvals.
    let mut empty_spec = spec.clone();
    for approval in &mut empty_spec.approvals {
        approval.key_type = Some(SignatureType::P256);
        approval.key_data = None;
    }
    let empty = TempoBatchCallEnv {
        signature: TempoSignature::Multisig(
            create_mock_native_multisig_signature(Address::repeat_byte(9), &empty_spec).unwrap(),
        ),
        ..Default::default()
    };
    assert_eq!(
        intrinsic(&env) - intrinsic(&empty),
        2 * u64::from(size) * 16
    );
}

#[cfg(feature = "reth")]
#[test_case::test_case(0; "direct")]
#[test_case::test_case(1; "delegate")]
#[test_case::test_case(2; "inline grant")]
fn native_roles_keep_transaction_context_with_empty_encoding(role: u8) {
    let account = Address::repeat_byte(9);
    let multisig = create_mock_native_multisig_signature(account, &spec()).unwrap();
    let mut tx = TempoTransaction::default();
    let signature = match role {
        0 => TempoSignature::Multisig(multisig),
        1 => TempoSignature::Keychain(KeychainSignature::new(Address::repeat_byte(8), multisig)),
        _ => {
            tx.key_authorization = Some(
                KeyAuthorization::unrestricted(
                    4217,
                    SignatureType::Secp256k1,
                    Address::repeat_byte(8),
                )
                .into_signed(multisig),
            );
            TempoSignature::default()
        }
    };
    let tx = tx.into_signed(signature);
    let env = TempoTxEnv::from_encoded_tx(&tx, account, Bytes::new());
    assert!(matches!(
        env.execution_context,
        ExecutionContext::Transaction { .. }
    ));
}

#[cfg(feature = "reth")]
#[test_case::test_case(false; "direct")]
#[test_case::test_case(true; "delegate")]
fn block_simulation_rejects_configurable_roles(delegate: bool) {
    let request = TempoTransactionRequest {
        multisig_simulation: Some(spec()),
        key_id: delegate.then_some(Address::repeat_byte(9)),
        ..Default::default()
    };
    let error = TryIntoSimTx::<TempoTxEnvelope>::try_into_sim_tx(request).unwrap_err();
    assert!(error.to_string().contains("evolving-position state"));
}

#[cfg(feature = "reth")]
#[tokio::test]
async fn signing_preserves_real_configurable_grant_without_simulation_hints() {
    let signer = PrivateKeySigner::random();
    let parent = signer.address();
    let authorization =
        KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::repeat_byte(8));
    let config = MultisigConfig {
        salt: B256::ZERO,
        version: 1,
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: parent,
            weight: 1,
        }],
    };
    let digest = multisig_digest(authorization.signature_hash(), parent, 1);
    let signature = MultisigSignature::try_new(
        parent,
        config,
        vec![PrimitiveSignature::Secp256k1(
            signer.sign_hash_sync(&digest).unwrap(),
        )],
    )
    .unwrap();
    let authorization = authorization.into_signed(signature);
    let request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(parent),
            to: Some(Address::repeat_byte(7).into()),
            chain_id: Some(4217),
            nonce: Some(0),
            gas: Some(100_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        },
        key_authorization: Some(authorization.clone()),
        ..Default::default()
    };
    let TempoTxEnvelope::AA(tx) = request.try_build_and_sign(signer).await.unwrap() else {
        panic!("AA expected");
    };
    assert_eq!(tx.tx().key_authorization, Some(authorization));
}
