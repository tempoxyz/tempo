use super::*;
use alloy_primitives::B256;
use tempo_primitives::transaction::MultisigOwner;

pub(crate) fn spec() -> MultisigSimulationSpec {
    MultisigSimulationSpec {
        signer: None,
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
}
