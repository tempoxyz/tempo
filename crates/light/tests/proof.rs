use std::collections::{BTreeMap, BTreeSet};

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, EIP1186StorageProof};
use alloy_trie::{EMPTY_ROOT_HASH, Nibbles, TrieAccount, nodes::LeafNode};
use tempo_light::proof::{Error, ProofLimits, ProofTargets, verify_multi_proof};

fn leaf(key: B256, value: Vec<u8>) -> Bytes {
    alloy_rlp::encode(LeafNode::new(Nibbles::unpack(key), value)).into()
}

fn fixture() -> (B256, ProofTargets, EIP1186AccountProofResponse) {
    let address = Address::repeat_byte(0x20);
    let slot = B256::with_last_byte(10);
    let value = U256::from(42);
    let storage_node = leaf(keccak256(slot), alloy_rlp::encode(value));
    let account = TrieAccount {
        nonce: 1,
        balance: U256::ZERO,
        storage_root: keccak256(&storage_node),
        code_hash: keccak256([0]),
    };
    let account_node = leaf(keccak256(address), alloy_rlp::encode(account));
    let root = keccak256(&account_node);
    let response = EIP1186AccountProofResponse {
        address,
        nonce: account.nonce,
        balance: account.balance,
        code_hash: account.code_hash,
        storage_hash: account.storage_root,
        account_proof: vec![account_node],
        storage_proof: vec![EIP1186StorageProof {
            key: slot.into(),
            value,
            proof: vec![storage_node],
        }],
    };
    (
        root,
        BTreeMap::from([(address, BTreeSet::from([slot]))]),
        response,
    )
}

fn empty(address: Address, slot: B256) -> EIP1186AccountProofResponse {
    EIP1186AccountProofResponse {
        address,
        code_hash: KECCAK_EMPTY,
        storage_hash: EMPTY_ROOT_HASH,
        storage_proof: vec![EIP1186StorageProof {
            key: slot.into(),
            value: U256::ZERO,
            proof: vec![],
        }],
        ..Default::default()
    }
}

fn verify(
    root: B256,
    targets: &ProofTargets,
    responses: &[EIP1186AccountProofResponse],
) -> Result<tempo_light::proof::VerifiedBatch, Error> {
    verify_multi_proof(root, targets, responses, ProofLimits::default())
}

#[test]
fn inclusion_authenticates_account_and_raw_value() {
    let (root, targets, response) = fixture();
    let result = verify(root, &targets, std::slice::from_ref(&response)).unwrap();
    assert_eq!(result.state_root(), root);
    let account = &result.accounts()[&response.address];
    assert_eq!(account.storage_root(), response.storage_hash);
    assert_eq!(account.account().unwrap().code_hash, response.code_hash);
    assert_eq!(
        account.slots()[&response.storage_proof[0].key.as_b256()],
        B256::with_last_byte(42)
    );
}

#[test]
fn complete_slot_non_membership_proves_zero_but_truncation_does_not() {
    let (root, _, mut response) = fixture();
    let slot = B256::with_last_byte(11);
    let targets = BTreeMap::from([(response.address, BTreeSet::from([slot]))]);
    response.storage_proof[0].key = slot.into();
    response.storage_proof[0].value = U256::ZERO;
    let verified = verify(root, &targets, &[response.clone()]).unwrap();
    assert_eq!(
        verified.accounts()[&response.address].slots()[&slot],
        B256::ZERO
    );
    response.storage_proof[0].proof.clear();
    assert!(matches!(
        verify(root, &targets, &[response]),
        Err(Error::InvalidProof(_))
    ));
}

#[test]
fn account_non_membership_and_empty_state_are_complete() {
    let (root, _, response) = fixture();
    let slot = B256::with_last_byte(1);
    let address = Address::repeat_byte(0x21);
    let targets = BTreeMap::from([(address, BTreeSet::from([slot]))]);
    let mut absent = empty(address, slot);
    absent.account_proof = response.account_proof;
    let verified = verify(root, &targets, &[absent.clone()]).unwrap();
    assert!(verified.accounts()[&address].account().is_none());
    assert_eq!(verified.accounts()[&address].slots()[&slot], B256::ZERO);
    absent.account_proof.clear();
    assert!(verify(root, &targets, &[absent.clone()]).is_err());
    verify(EMPTY_ROOT_HASH, &targets, &[absent.clone()]).unwrap();
    absent.code_hash = B256::ZERO;
    absent.storage_hash = B256::ZERO;
    verify(EMPTY_ROOT_HASH, &targets, &[absent]).unwrap();
}

#[test]
fn initialized_account_with_empty_storage_can_prove_zero() {
    let (_, _, mut response) = fixture();
    response.storage_hash = EMPTY_ROOT_HASH;
    response.storage_proof[0].value = U256::ZERO;
    response.storage_proof[0].proof.clear();
    let account = TrieAccount {
        nonce: response.nonce,
        balance: response.balance,
        storage_root: response.storage_hash,
        code_hash: response.code_hash,
    };
    let node = leaf(keccak256(response.address), alloy_rlp::encode(account));
    let root = keccak256(&node);
    response.account_proof = vec![node];
    let slot = response.storage_proof[0].key.as_b256();
    let targets = BTreeMap::from([(response.address, BTreeSet::from([slot]))]);
    assert!(
        verify(root, &targets, &[response])
            .unwrap()
            .accounts()
            .values()
            .next()
            .unwrap()
            .account()
            .is_some()
    );
}

#[test]
fn account_only_targets_require_account_proof() {
    let (root, _, mut response) = fixture();
    response.storage_proof.clear();
    let targets = BTreeMap::from([(response.address, BTreeSet::new())]);
    verify(root, &targets, &[response.clone()]).unwrap();
    response.account_proof.clear();
    assert!(verify(root, &targets, &[response]).is_err());
}

#[test]
fn forged_values_roots_and_metadata_fail() {
    let (root, targets, response) = fixture();
    for kind in 0..7 {
        let mut forged = response.clone();
        match kind {
            0 => forged.storage_proof[0].value += U256::from(1),
            1 => forged.storage_proof[0].value = U256::ZERO,
            2 => forged.storage_hash = EMPTY_ROOT_HASH,
            3 => forged.code_hash = KECCAK_EMPTY,
            4 => forged.nonce += 1,
            5 => forged.balance = U256::from(1),
            _ => forged.account_proof[0] = vec![0xff].into(),
        }
        assert!(verify(root, &targets, &[forged]).is_err(), "kind {kind}");
    }
    assert!(verify(B256::ZERO, &targets, &[response]).is_err());
}

#[test]
fn omitted_duplicate_unexpected_and_substituted_targets_fail() {
    let (root, targets, response) = fixture();
    assert!(verify(root, &targets, &[]).is_err());
    assert!(verify(root, &targets, &[response.clone(), response.clone()]).is_err());
    let mut other = response.clone();
    other.address = Address::ZERO;
    assert!(verify(root, &targets, &[other]).is_err());
    let mut missing = response.clone();
    missing.storage_proof.clear();
    assert!(verify(root, &targets, &[missing]).is_err());
    let mut substituted = response.clone();
    substituted.storage_proof[0].key = B256::ZERO.into();
    assert!(verify(root, &targets, &[substituted]).is_err());
    let slot = response.storage_proof[0].key.as_b256();
    let two_slots = BTreeMap::from([(response.address, BTreeSet::from([slot, B256::ZERO]))]);
    let mut duplicate = response.clone();
    duplicate
        .storage_proof
        .push(duplicate.storage_proof[0].clone());
    assert!(matches!(
        verify(root, &two_slots, &[duplicate]),
        Err(Error::TargetMismatch("duplicate slot"))
    ));
    let two_accounts = BTreeMap::from([
        (response.address, BTreeSet::from([slot])),
        (Address::ZERO, BTreeSet::new()),
    ]);
    assert!(matches!(
        verify(root, &two_accounts, &[response.clone(), response]),
        Err(Error::TargetMismatch("duplicate account"))
    ));
}

#[test]
fn proof_work_limits_are_checked_before_verification() {
    let (root, targets, response) = fixture();
    for limits in [
        ProofLimits {
            max_accounts: 0,
            ..Default::default()
        },
        ProofLimits {
            max_slots: 0,
            ..Default::default()
        },
        ProofLimits {
            max_nodes: 0,
            ..Default::default()
        },
        ProofLimits {
            max_node_bytes: 0,
            ..Default::default()
        },
        ProofLimits {
            max_total_bytes: 0,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            verify_multi_proof(root, &targets, std::slice::from_ref(&response), limits),
            Err(Error::ResourceLimit(_))
        ));
    }
}

#[test]
fn late_failure_does_not_publish_a_partial_verified_batch() {
    let (root, mut targets, response) = fixture();
    let slot = B256::ZERO;
    let address = Address::repeat_byte(0x21);
    targets.insert(address, BTreeSet::from([slot]));
    let incomplete = empty(address, slot);
    assert!(verify(root, &targets, &[response, incomplete]).is_err());
}

fn snapshot(root: B256, height: u64) -> tempo_light::Snapshot {
    use alloy_consensus::{Header, Sealable as _};
    use commonware_codec::Encode as _;
    use commonware_consensus::types::Epoch;
    use rand::{SeedableRng as _, rngs::StdRng};
    use tempo_finality::{
        Digest, NetworkIdentity,
        test_utils::{dkg_fixture, make_certificate},
    };
    let mut rng = StdRng::seed_from_u64(100);
    let dkg = dkg_fixture(&mut rng, Epoch::zero());
    let mut tracker = tempo_light::HeadTracker::new(
        NetworkIdentity {
            from_epoch: 0,
            identity: *dkg.outcome.network_identity(),
        },
        std::num::NonZeroU64::new(10).unwrap(),
    );
    let header = tempo_primitives::TempoHeader {
        inner: Header {
            number: height,
            state_root: root,
            ..Default::default()
        },
        ..Default::default()
    };
    let digest = header.hash_slow();
    let evidence = tempo_light::CertifiedHeader {
        epoch: 0,
        view: height,
        digest,
        header,
        certificate: alloy_primitives::hex::encode(
            make_certificate(Digest(digest), Epoch::zero(), height, &dkg.schemes).encode(),
        ),
    };
    tracker.accept(&mut rng, evidence).unwrap()
}

#[test]
fn cache_reuses_slots_only_after_exact_new_snapshot_authenticates_the_root() {
    use std::num::NonZeroU32;
    use tempo_light::{VerifiedCache, proof::StorageReadKey};
    let (root, targets, response) = fixture();
    let key = StorageReadKey {
        account: response.address,
        slot: response.storage_proof[0].key.as_b256(),
    };
    let first = snapshot(root, 1);
    let mut cache = VerifiedCache::new(NonZeroU32::new(10).unwrap(), NonZeroU32::new(10).unwrap());
    let batch = first
        .verify(
            &targets,
            std::slice::from_ref(&response),
            ProofLimits::default(),
        )
        .unwrap();
    cache.commit(&first, &batch).unwrap();
    assert_eq!(cache.get(&first, key), Some(B256::with_last_byte(42)));

    let mut account_only = response.clone();
    account_only.nonce += 1;
    account_only.storage_proof.clear();
    let account_node = leaf(
        keccak256(response.address),
        alloy_rlp::encode(TrieAccount {
            nonce: account_only.nonce,
            balance: account_only.balance,
            storage_root: account_only.storage_hash,
            code_hash: account_only.code_hash,
        }),
    );
    let second = snapshot(keccak256(&account_node), 5);
    account_only.account_proof = vec![account_node];
    assert_eq!(cache.get(&second, key), None);
    let root_targets = BTreeMap::from([(response.address, BTreeSet::new())]);
    let batch = second
        .verify(&root_targets, &[account_only], ProofLimits::default())
        .unwrap();
    cache.commit(&second, &batch).unwrap();
    assert_eq!(cache.get(&second, key), Some(B256::with_last_byte(42)));

    let mut changed = response;
    let storage = leaf(keccak256(key.slot), alloy_rlp::encode(U256::from(43)));
    changed.storage_hash = keccak256(&storage);
    changed.storage_proof.clear();
    let account = leaf(
        keccak256(key.account),
        alloy_rlp::encode(TrieAccount {
            nonce: changed.nonce,
            balance: changed.balance,
            storage_root: changed.storage_hash,
            code_hash: changed.code_hash,
        }),
    );
    let third = snapshot(keccak256(&account), 8);
    changed.account_proof = vec![account];
    let batch = third
        .verify(&root_targets, &[changed], ProofLimits::default())
        .unwrap();
    cache.commit(&third, &batch).unwrap();
    assert_eq!(cache.get(&third, key), None);
    assert_eq!(cache.get(&first, key), Some(B256::with_last_byte(42)));
}

#[test]
fn cache_binding_failure_is_atomic_and_pruning_does_not_destroy_snapshots() {
    use std::num::NonZeroU32;
    use tempo_light::{VerifiedCache, cache::Error, proof::StorageReadKey};
    let (root, targets, response) = fixture();
    let first = snapshot(root, 1);
    let batch = first
        .verify(
            &targets,
            std::slice::from_ref(&response),
            ProofLimits::default(),
        )
        .unwrap();
    let mut cache = VerifiedCache::new(NonZeroU32::new(1).unwrap(), NonZeroU32::new(1).unwrap());
    cache.commit(&first, &batch).unwrap();
    let key = StorageReadKey {
        account: response.address,
        slot: response.storage_proof[0].key.as_b256(),
    };
    let empty_snapshot = snapshot(EMPTY_ROOT_HASH, 2);
    assert!(matches!(
        cache.commit(&empty_snapshot, &batch),
        Err(Error::WrongSnapshot)
    ));
    assert_eq!(cache.entry_counts(), (1, 1));
    assert_eq!(cache.get(&first, key), Some(B256::with_last_byte(42)));

    let absent = empty(Address::ZERO, B256::ZERO);
    let empty_targets = BTreeMap::from([(Address::ZERO, BTreeSet::from([B256::ZERO]))]);
    let empty_batch = empty_snapshot
        .verify(&empty_targets, &[absent], ProofLimits::default())
        .unwrap();
    cache.commit(&empty_snapshot, &empty_batch).unwrap();
    assert_eq!(cache.entry_counts(), (1, 1));
    assert_eq!(cache.get(&first, key), None);
    // Pruning loses only the cache lookup; the retained authenticated snapshot still verifies.
    let refetched = first
        .verify(&targets, &[response], ProofLimits::default())
        .unwrap();
    cache.commit(&first, &refetched).unwrap();
    assert_eq!(cache.get(&first, key), Some(B256::with_last_byte(42)));
}

/// Explicit regeneration command; normal tests never write repository files.
#[test]
#[ignore = "run explicitly with TEMPO_LIGHT_EXPORT_FIXTURE set to the output path"]
fn export_conformance_fixture() {
    use commonware_codec::Encode as _;
    use commonware_consensus::types::Epoch;
    use rand::{SeedableRng as _, rngs::StdRng};
    let (root, targets, response) = fixture();
    let snapshot = snapshot(root, 1);
    let mut rng = StdRng::seed_from_u64(100);
    let dkg = tempo_finality::test_utils::dkg_fixture(&mut rng, Epoch::zero());
    let mut forged = response.clone();
    forged.storage_proof[0].value += U256::from(1);
    let mut truncated = response.clone();
    truncated.storage_proof[0].proof.clear();
    let fixture = serde_json::json!({
        "formatVersion": 1,
        "description": "Deterministic real threshold certificate and single-leaf Ethereum MPT inclusion proofs. Not a network checkpoint or TIP-20 layout fixture.",
        "epochLength": 10,
        "trustAnchor": { "fromEpoch": 0, "identity": alloy_primitives::hex::encode_prefixed(dkg.outcome.network_identity().encode()) },
        "evidence": snapshot.evidence(),
        "headerRlp": alloy_primitives::hex::encode_prefixed(alloy_rlp::encode(snapshot.header())),
        "targets": targets,
        "responses": [response],
        "expectedValue": B256::with_last_byte(42),
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

#[test]
fn empty_trie_marker_must_not_hide_additional_garbage_nodes() {
    let address = Address::ZERO;
    let slot = B256::ZERO;
    let targets = BTreeMap::from([(address, BTreeSet::from([slot]))]);
    let mut response = empty(address, slot);
    response.account_proof = vec![vec![alloy_rlp::EMPTY_STRING_CODE].into()];
    verify(EMPTY_ROOT_HASH, &targets, &[response.clone()]).unwrap();
    response.account_proof.push(vec![0xff].into());
    assert!(matches!(
        verify(EMPTY_ROOT_HASH, &targets, &[response]),
        Err(Error::NonCanonicalEmptyProof)
    ));
}
