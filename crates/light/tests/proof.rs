//! Snapshot integration; transport-neutral proof/cache cases live in tempo-state-proof.
use alloy_consensus::{Header, Sealable as _};
use alloy_primitives::{B256, U256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use tempo_light::Snapshot;
use tempo_state_proof::{
    CacheLimits, ProofLimits, RetentionDelta, StorageReadKey, VerifiedCache, test_utils::fixture,
};

// One DKG and tracker for every head in a scenario, rather than regenerating signing setup per head.
fn snapshots() -> (
    tempo_finality::NetworkIdentity,
    impl FnMut(B256, u64) -> Snapshot,
) {
    use commonware_codec::Encode as _;
    use commonware_consensus::types::Epoch;
    use rand::{SeedableRng as _, rngs::StdRng};
    use tempo_finality::{
        Digest, NetworkIdentity,
        test_utils::{dkg_fixture, make_certificate},
    };
    let mut rng = StdRng::seed_from_u64(100);
    let dkg = dkg_fixture(&mut rng, Epoch::zero());
    let anchor = NetworkIdentity {
        from_epoch: 0,
        identity: *dkg.outcome.network_identity(),
    };
    let mut tracker =
        tempo_light::HeadTracker::new(anchor.clone(), std::num::NonZeroU64::new(10).unwrap());
    (anchor, move |root, height| {
        let header = tempo_primitives::TempoHeader {
            inner: Header {
                number: height,
                state_root: root,
                ..Default::default()
            },
            ..Default::default()
        };
        let digest = header.hash_slow();
        tracker
            .accept(
                &mut rng,
                tempo_light::CertifiedHeader {
                    epoch: 0,
                    view: height,
                    digest,
                    header,
                    certificate: alloy_primitives::hex::encode(
                        make_certificate(Digest(digest), Epoch::zero(), height, &dkg.schemes)
                            .encode(),
                    ),
                },
            )
            .unwrap()
    })
}

#[test]
fn snapshots_bind_proofs_and_cache_mappings_to_their_state_root() {
    let (_, mut snapshot) = snapshots();
    let (root, targets, response) = fixture(1, 42);
    let (next_root, _, next_response) = fixture(2, 43);
    let key = StorageReadKey::new(response.address, response.storage_proof[0].key.as_b256());
    let verify = |snapshot: &Snapshot, response: &EIP1186AccountProofResponse| {
        snapshot.verify(
            &targets,
            std::slice::from_ref(response),
            ProofLimits::default(),
        )
    };
    let (first, next) = (snapshot(root, 1), snapshot(next_root, 5));
    let full = verify(&first, &response).unwrap();
    assert!(verify(&next, &response).is_err()); // Another snapshot's root rejects this proof.
    let mut cache = VerifiedCache::new(CacheLimits::new(
        1.try_into().unwrap(),
        8.try_into().unwrap(),
    ))
    .unwrap();
    for (root, batch) in [
        (root, full.clone()),
        (next_root, verify(&next, &next_response).unwrap()),
    ] {
        cache
            .publish(&[(root, &batch)], &RetentionDelta::default())
            .unwrap();
    }
    assert_eq!(
        cache.get(next_root, key).map(|(_, word)| word),
        Some(B256::with_last_byte(43))
    );
    // The older mapping is evicted, but operation-owned evidence remains valid.
    assert!(cache.get(root, key).is_none());
    assert_eq!(full.word(key), Some(B256::with_last_byte(42)));
}

/// Explicit regeneration only; ordinary tests never write repository files.
#[test]
#[ignore = "run explicitly with TEMPO_LIGHT_EXPORT_FIXTURE set to the output path"]
fn export_conformance_fixture() {
    let (root, targets, response) = fixture(1, 42);
    let (anchor, mut snapshot) = snapshots();
    let snapshot = snapshot(root, 1);
    let mut forged = response.clone();
    forged.storage_proof[0].value += U256::from(1);
    let mut truncated = response.clone();
    truncated.storage_proof[0].proof.clear();
    let fixture = serde_json::json!({
        "formatVersion": 1,
        "description": "Deterministic real threshold certificate and single-leaf Ethereum MPT inclusion proofs. Not a network checkpoint or TIP-20 layout fixture.",
        "epochLength": 10,
        "trustAnchor": anchor,
        "evidence": snapshot.evidence(),
        "headerRlp": alloy_primitives::hex::encode_prefixed(alloy_rlp::encode(snapshot.header())),
        "targets": targets, "responses": [response], "expectedValue": B256::with_last_byte(42),
        "negativeProofs": [
            { "name": "forgedScalar", "responses": [forged] },
            { "name": "truncatedStorageProof", "responses": [truncated] },
            { "name": "omittedAccount", "responses": [] }
        ]
    });
    let output =
        std::env::var("TEMPO_LIGHT_EXPORT_FIXTURE").expect("explicit output path is required");
    std::fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
    )
    .unwrap();
}
