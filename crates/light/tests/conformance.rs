//! Cross-language fixture consumer: all expected roots, bytes and values are in JSON.

use std::num::NonZeroU64;

use alloy_primitives::{B256, hex};
use rand::{SeedableRng as _, rngs::StdRng};
use tempo_finality::NetworkIdentity;
use tempo_light::{CertifiedHeader, HeadTracker};
use tempo_state_proof::{ProofLimits, ProofTargets};

#[cfg(feature = "client")]
#[test]
fn real_devnet_tip20_layout_and_authenticated_rotation_conform() {
    use alloy_primitives::U256;
    use tempo_light::{
        checkpoint::Checkpoint,
        token::{self, ReadRequest},
    };
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/devnet-tip20-v1.json")).unwrap();
    assert_eq!(fixture["formatVersion"], 1);
    assert_eq!(fixture["layout"], "V1");
    let checkpoint: Checkpoint =
        serde_json::from_value(fixture["checkpoint"]["checkpoint"].clone()).unwrap();
    assert!(checkpoint.transition.is_some());
    assert_ne!(
        checkpoint.identity.identity,
        checkpoint.network.anchor.identity
    );
    let mut tracker = checkpoint.restore().unwrap();
    let evidence: CertifiedHeader = serde_json::from_value(fixture["evidence"].clone()).unwrap();
    let snapshot = tracker
        .accept(&mut StdRng::seed_from_u64(123), evidence)
        .unwrap();
    assert_eq!(
        serde_json::to_value(snapshot.evidence().digest).unwrap(),
        fixture["verifiedRead"]["block"]["hash"]
    );
    let requests: Vec<ReadRequest> = serde_json::from_value(fixture["requests"].clone()).unwrap();
    let targets = token::targets(&requests).unwrap();
    let mut responses: Vec<alloy_rpc_types_eth::EIP1186AccountProofResponse> =
        serde_json::from_value(fixture["responses"].clone()).unwrap();
    let batch = snapshot
        .verify(&targets, &responses, ProofLimits::default())
        .unwrap();
    let expected: Vec<U256> =
        serde_json::from_value(fixture["verifiedRead"]["values"].clone()).unwrap();
    for (request, expected) in requests.into_iter().zip(expected) {
        let key = request.key().unwrap();
        let account = &batch.accounts()[&key.account];
        assert_eq!(
            account.account().unwrap().code_hash,
            alloy_primitives::keccak256([0xef])
        );
        assert_eq!(U256::from_be_bytes(account.slots()[&key.slot].0), expected);
    }
    responses[0].storage_proof[0].value += U256::ONE;
    assert!(
        snapshot
            .verify(&targets, &responses, ProofLimits::default())
            .is_err()
    );
}

#[test]
fn shared_finality_and_mpt_fixture_conforms() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/mpt-finality-v1.json")).unwrap();
    assert_eq!(fixture["formatVersion"], 1);
    let identity = hex::decode(fixture["trustAnchor"]["identity"].as_str().unwrap()).unwrap();
    let anchor = NetworkIdentity {
        from_epoch: fixture["trustAnchor"]["fromEpoch"].as_u64().unwrap(),
        identity: commonware_codec::DecodeExt::decode(identity.as_slice()).unwrap(),
    };
    let mut tracker = HeadTracker::new(
        anchor,
        NonZeroU64::new(fixture["epochLength"].as_u64().unwrap()).unwrap(),
    );
    let evidence: CertifiedHeader = serde_json::from_value(fixture["evidence"].clone()).unwrap();
    assert_eq!(
        alloy_rlp::encode(&evidence.header),
        hex::decode(fixture["headerRlp"].as_str().unwrap()).unwrap()
    );
    let snapshot = tracker
        .accept(&mut StdRng::seed_from_u64(999), evidence)
        .unwrap();
    let targets: ProofTargets = serde_json::from_value(fixture["targets"].clone()).unwrap();
    let responses =
        serde_json::from_value::<Vec<alloy_rpc_types_eth::EIP1186AccountProofResponse>>(
            fixture["responses"].clone(),
        )
        .unwrap();
    let batch = snapshot
        .verify(&targets, &responses, ProofLimits::default())
        .unwrap();
    let expected: B256 = serde_json::from_value(fixture["expectedValue"].clone()).unwrap();
    assert_eq!(
        *batch
            .accounts()
            .values()
            .next()
            .unwrap()
            .slots()
            .values()
            .next()
            .unwrap(),
        expected
    );
    for negative in fixture["negativeProofs"].as_array().unwrap() {
        let responses = serde_json::from_value::<
            Vec<alloy_rpc_types_eth::EIP1186AccountProofResponse>,
        >(negative["responses"].clone())
        .unwrap();
        assert!(
            snapshot
                .verify(&targets, &responses, ProofLimits::default())
                .is_err(),
            "{}",
            negative["name"]
        );
    }
}
