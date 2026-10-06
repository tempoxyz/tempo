use alloy_primitives::{Address, B256, KECCAK256_EMPTY, U256, keccak256};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, EIP1186StorageProof};
use alloy_trie::{EMPTY_ROOT_HASH, Nibbles};
use std::collections::{BTreeMap, BTreeSet};
use tempo_state_proof::{test_utils::*, *};

fn empty(address: Address, slot: B256) -> EIP1186AccountProofResponse {
    EIP1186AccountProofResponse {
        address,
        code_hash: KECCAK256_EMPTY,
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
) -> Result<VerifiedBatch, ProofError> {
    verify_multi_proof(root, targets, responses, ProofLimits::default())
}

#[test]
fn membership_absence_and_empty_storage_preserve_metadata() {
    let (root, targets, response) = fixture(1, 42);
    let key = StorageReadKey::new(response.address, response.storage_proof[0].key.as_b256());
    let batch = verify(root, &targets, std::slice::from_ref(&response)).unwrap();
    assert_eq!(batch.state_root(), root);
    assert_eq!(batch.word(key), Some(B256::with_last_byte(42)));
    let metadata = batch.accounts()[&key.account].account().unwrap();
    assert_eq!(metadata.nonce, response.nonce);
    assert_eq!(metadata.balance, response.balance);
    assert_eq!(metadata.storage_root, response.storage_hash);
    assert_eq!(metadata.code_hash, response.code_hash);
    let roots = ProofTargets::from([(response.address, BTreeSet::new())]);
    let mut account_only = response.clone();
    account_only.storage_proof.clear();
    assert!(
        verify(root, &roots, &[account_only]).unwrap().accounts()[&key.account]
            .slots()
            .is_empty()
    );

    // One empty-storage setup covers absent, present-empty and initialized accounts, including RPC aliases.
    for state in ["absent", "zero aliases", "present empty", "initialized"] {
        let mut response = empty(key.account, key.slot);
        let (root, expected) = match state {
            "absent" => (EMPTY_ROOT_HASH, None),
            "zero aliases" => {
                response.code_hash = B256::ZERO;
                response.storage_hash = B256::ZERO;
                (EMPTY_ROOT_HASH, None)
            }
            _ => {
                if state == "initialized" {
                    response.nonce = 1;
                    response.code_hash = keccak256([0]);
                }
                let (root, account) = account_root(&mut response);
                (root, Some(account))
            }
        };
        let batch = verify(root, &targets, &[response]).unwrap();
        assert_eq!(
            batch.accounts()[&key.account].account(),
            expected.as_ref(),
            "{state}"
        );
        assert_eq!(batch.word(key), Some(B256::ZERO), "{state}");
        assert_eq!(
            check_consumed(&batch, &BTreeMap::from([(key, B256::ZERO)])).unwrap(),
            1
        );
    }

    // Complete exclusion in a nonempty trie is valid; omitting its path is not.
    for account in [false, true] {
        let mut excluded = if account {
            empty(Address::ZERO, key.slot)
        } else {
            response.clone()
        };
        let slot = if account { key.slot } else { B256::ZERO };
        excluded.account_proof = response.account_proof.clone();
        excluded.storage_proof[0].key = slot.into();
        excluded.storage_proof[0].value = U256::ZERO;
        let targets = ProofTargets::from([(excluded.address, BTreeSet::from([slot]))]);
        verify(root, &targets, std::slice::from_ref(&excluded)).unwrap();
        if account {
            excluded.account_proof.clear();
        } else {
            excluded.storage_proof[0].proof.clear();
        }
        assert!(verify(root, &targets, &[excluded]).is_err());
    }
}

#[test]
fn exact_targets_forged_evidence_and_work_budgets_are_rejected() {
    let (root, targets, response) = fixture(1, 42);
    for change in [
        "value",
        "zero",
        "storage root",
        "code",
        "nonce",
        "balance",
        "encoding",
        "account",
        "slot",
        "missing slot",
    ] {
        let mut bad = response.clone();
        match change {
            "value" => bad.storage_proof[0].value += U256::ONE,
            "zero" => bad.storage_proof[0].value = U256::ZERO,
            "storage root" => bad.storage_hash = EMPTY_ROOT_HASH,
            "code" => bad.code_hash = KECCAK256_EMPTY,
            "nonce" => bad.nonce += 1,
            "balance" => bad.balance = U256::ONE,
            "encoding" => bad.account_proof[0] = vec![0xff].into(),
            "account" => bad.address = Address::ZERO,
            "slot" => bad.storage_proof[0].key = B256::ZERO.into(),
            _ => bad.storage_proof.clear(),
        }
        assert!(verify(root, &targets, &[bad]).is_err(), "{change}");
    }
    assert!(verify(B256::ZERO, &targets, std::slice::from_ref(&response)).is_err());
    assert!(verify(root, &targets, &[]).is_err());
    let mut account_only = response.clone();
    account_only.storage_proof.clear();
    account_only.account_proof.clear();
    assert!(
        verify(
            root,
            &ProofTargets::from([(response.address, BTreeSet::new())]),
            &[account_only]
        )
        .is_err()
    );
    let mut two = targets.clone();
    two.insert(Address::ZERO, BTreeSet::new());
    assert!(matches!(
        verify(root, &two, &[response.clone(), response.clone()]),
        Err(ProofError::Targets(TargetError::DuplicateAccount(_)))
    ));
    let mut duplicate = response.clone();
    duplicate
        .storage_proof
        .push(duplicate.storage_proof[0].clone());
    let two = ProofTargets::from([(
        response.address,
        BTreeSet::from([B256::ZERO, response.storage_proof[0].key.as_b256()]),
    )]);
    assert!(matches!(
        verify(root, &two, &[duplicate]),
        Err(ProofError::Targets(TargetError::DuplicateSlot(_)))
    ));

    for kind in [
        ResourceKind::Accounts,
        ResourceKind::Slots,
        ResourceKind::Nodes,
        ResourceKind::NodeBytes,
        ResourceKind::TotalBytes,
    ] {
        let mut limits = ProofLimits::default();
        match kind {
            ResourceKind::Accounts => limits.max_accounts = 0,
            ResourceKind::Slots => limits.max_slots = 0,
            ResourceKind::Nodes => limits.max_nodes = 0,
            ResourceKind::NodeBytes => limits.max_node_bytes = 0,
            ResourceKind::TotalBytes => limits.max_total_bytes = 0,
        }
        assert!(
            matches!(verify_multi_proof(root, &targets, std::slice::from_ref(&response), limits), Err(ProofError::LimitExceeded { kind: actual, .. }) if actual == kind)
        );
    }
    let mut repeated = response;
    repeated
        .account_proof
        .push(repeated.account_proof[0].clone());
    assert!(matches!(
        verify_multi_proof(
            root,
            &targets,
            &[repeated],
            ProofLimits {
                max_nodes: 2,
                ..Default::default()
            }
        ),
        Err(ProofError::LimitExceeded {
            kind: ResourceKind::Nodes,
            ..
        })
    ));
    for account in [true, false] {
        let mut response = empty(Address::ZERO, B256::ZERO);
        let targets = ProofTargets::from([(response.address, BTreeSet::from([B256::ZERO]))]);
        let proof = if account {
            &mut response.account_proof
        } else {
            &mut response.storage_proof[0].proof
        };
        *proof = vec![vec![alloy_rlp::EMPTY_STRING_CODE].into()];
        verify(EMPTY_ROOT_HASH, &targets, std::slice::from_ref(&response)).unwrap();
        let proof = if account {
            &mut response.account_proof
        } else {
            &mut response.storage_proof[0].proof
        };
        proof.push(vec![0xff].into());
        assert!(matches!(
            verify(EMPTY_ROOT_HASH, &targets, &[response]),
            Err(ProofError::NonCanonicalEmptyProof { .. })
        ));
    }
}

#[test]
fn pending_child_truncation_cannot_masquerade_as_zero_exclusion() {
    use alloy_trie::{HashBuilder, proof::ProofRetainer};
    let slot = B256::ZERO;
    let leaves = (0..64u64)
        .map(|i| {
            (
                Nibbles::unpack(keccak256(U256::from(i).to_be_bytes::<32>())),
                alloy_rlp::encode(U256::from(i + 1)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut builder = HashBuilder::default()
        .with_proof_retainer(ProofRetainer::new(vec![Nibbles::unpack(keccak256(slot))]));
    for (key, value) in &leaves {
        builder.add_leaf(*key, value);
    }
    let (_, _, mut response) = fixture(1, 42);
    response.storage_hash = builder.root();
    let nodes = builder
        .take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| node)
        .collect::<Vec<_>>();
    assert!(nodes.len() > 1);
    let (root, _) = account_root(&mut response);
    response.storage_proof[0] = EIP1186StorageProof {
        key: slot.into(),
        value: U256::ONE,
        proof: nodes,
    };
    let targets = ProofTargets::from([(response.address, BTreeSet::from([slot]))]);
    verify(root, &targets, std::slice::from_ref(&response)).unwrap();
    response.storage_proof[0].value = U256::ZERO;
    response.storage_proof[0].proof.truncate(1);
    assert!(verify(root, &targets, &[response]).is_err());
}

#[test]
fn batch_composition_and_consumed_values_are_exact() {
    let (root, targets, response) = fixture(1, 42);
    let key = StorageReadKey::new(response.address, response.storage_proof[0].key.as_b256());
    let mut batch = verify(root, &targets, &[response]).unwrap();
    let before = batch.clone();
    assert!(matches!(
        batch.merge(VerifiedBatch::empty(B256::ZERO)),
        Err(CompositionError::StateRoot { .. })
    ));
    assert_eq!(batch, before);
    batch.merge(before.clone()).unwrap();
    assert_eq!(batch, before);
    for (consumed, valid) in [
        (BTreeMap::from([(key, B256::with_last_byte(42))]), true),
        (BTreeMap::from([(key, B256::ZERO)]), false),
        (BTreeMap::new(), false),
        (
            BTreeMap::from([
                (key, B256::with_last_byte(42)),
                (StorageReadKey::new(Address::ZERO, B256::ZERO), B256::ZERO),
            ]),
            false,
        ),
    ] {
        assert_eq!(check_consumed(&batch, &consumed).is_ok(), valid);
    }
}
