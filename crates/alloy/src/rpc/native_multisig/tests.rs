use super::*;
use alloy_primitives::B256;
use tempo_primitives::transaction::MultisigOwner;

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

#[test]
fn simulation_spec_roundtrips_config_as_rlp_bytes() {
    let spec = spec();
    let json = serde_json::to_value(&spec).unwrap();
    assert!(json["config"].as_str().unwrap().starts_with("0x"));
    assert_eq!(
        serde_json::from_value::<MultisigSimulationSpec>(json).unwrap(),
        spec
    );
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
    assert!(
        serde_json::from_value::<MultisigSimulationSpec>(serde_json::to_value(value).unwrap())
            .is_err()
    );
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

#[cfg(feature = "reth")]
#[test_case::test_case(0; "direct")]
#[test_case::test_case(1; "delegate")]
#[test_case::test_case(2; "inline grant")]
fn native_roles_keep_transaction_context_with_empty_encoding(role: u8) {
    use reth_evm::FromTxWithEncoded;
    use tempo_primitives::{
        TempoSignature, TempoTransaction,
        transaction::{KeyAuthorization, KeychainSignature},
    };
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
                .into_signed(TempoSignature::Multisig(multisig)),
            );
            TempoSignature::default()
        }
    };
    let tx = tx.into_signed(signature);
    let env = tempo_revm::TempoTxEnv::from_encoded_tx(&tx, account, Bytes::new());
    assert!(matches!(
        env.execution_context,
        tempo_revm::ExecutionContext::Transaction { .. }
    ));
}

#[cfg(feature = "reth")]
#[test_case::test_case(false; "direct")]
#[test_case::test_case(true; "delegate")]
fn block_simulation_rejects_configurable_roles(delegate: bool) {
    use reth_rpc_convert::TryIntoSimTx;
    let request = crate::rpc::TempoTransactionRequest {
        multisig_simulation: Some(spec()),
        key_id: delegate.then_some(Address::repeat_byte(9)),
        ..Default::default()
    };
    let error =
        TryIntoSimTx::<tempo_primitives::TempoTxEnvelope>::try_into_sim_tx(request).unwrap_err();
    assert!(error.to_string().contains("evolving-position state"));
}

#[cfg(feature = "reth")]
#[tokio::test]
async fn signing_preserves_real_configurable_grant_without_simulation_hints() {
    use alloy_signer::SignerSync;
    use reth_rpc_convert::SignableTxRequest;
    use tempo_primitives::{TempoSignature, TempoTxEnvelope, transaction::KeyAuthorization};
    let signer = alloy_signer_local::PrivateKeySigner::random();
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
    let digest =
        tempo_primitives::transaction::multisig_digest(authorization.signature_hash(), parent, 1);
    let signature = tempo_primitives::transaction::MultisigSignature::try_new(
        parent,
        config,
        vec![
            tempo_primitives::transaction::PrimitiveSignature::Secp256k1(
                signer.sign_hash_sync(&digest).unwrap(),
            ),
        ],
    )
    .unwrap();
    let authorization = authorization.into_signed(TempoSignature::Multisig(signature));
    let request = crate::rpc::TempoTransactionRequest {
        inner: alloy_rpc_types_eth::TransactionRequest {
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
