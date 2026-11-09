//! The `eth_getMultiProof` proof path, and a reference rebuilt from the model to check it.

use crate::model::{storage_root, Model};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{
    proof::{ProofNodes, ProofRetainer},
    HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH,
};
use antithesis_sdk::assert_sometimes;
use eyre::{ensure, eyre, Result};
use reth_provider::StateProofProvider;
use reth_trie::{AccountProof, MultiProofTargetsV2, ProofV2Target};
use serde_json::json;
use std::collections::BTreeMap;

/// Mirrors `EthState::get_multi_proof` once the block's state provider is resolved: one V2
/// multiproof for all targets, then an account proof for each requested `(address, slots)`.
pub(crate) fn get_multi_proof(
    state: &impl StateProofProvider,
    targets: &[(Address, Vec<B256>)],
) -> Result<Vec<AccountProof>> {
    let mut proof_targets = MultiProofTargetsV2::default();
    for (address, slots) in targets {
        let hashed_address = keccak256(address);
        proof_targets.account_targets.push(ProofV2Target::new(hashed_address));
        if !slots.is_empty() {
            proof_targets
                .storage_targets
                .entry(hashed_address)
                .or_default()
                .extend(slots.iter().map(|slot| ProofV2Target::new(keccak256(slot))));
        }
    }
    let multiproof = state.multiproof_v2(proof_targets, false)?;
    Ok(targets
        .iter()
        .map(|(address, slots)| multiproof.account_proof(*address, slots))
        .collect::<Result<_, _>>()?)
}

/// Checks that every proof verifies against `root`, carries the model's values, and has exactly
/// the nodes on its key's path in the model's trie.
#[allow(clippy::clone_on_copy, reason = "Account is not Copy with account-ext enabled.")]
pub(crate) fn check(
    state: &Model,
    root: B256,
    targets: &[(Address, Vec<B256>)],
    proofs: &[AccountProof],
) -> Result<()> {
    ensure!(proofs.len() == targets.len(), "{} proofs for {} targets", proofs.len(), targets.len());
    let accounts = reference(
        state.iter().map(|(address, entry)| {
            let account: TrieAccount = entry.account.clone().into_trie_account(storage_root(entry));
            (keccak256(address), alloy_rlp::encode(account))
        }),
        targets.iter().map(|(address, _)| keccak256(address)),
    );
    for ((address, slots), proof) in targets.iter().zip(proofs) {
        ensure!(proof.address == *address, "proof for {} answers {address}", proof.address);
        proof.verify(root).map_err(|error| eyre!("{address} does not verify: {error:?}"))?;
        let entry = state.get(address);
        assert_sometimes!(entry.is_none(), "Account exclusion proof checked", &json!({}));
        ensure!(
            proof.info == entry.map(|entry| entry.account.clone()),
            "{address}: account {:?}",
            proof.info
        );
        ensure!(
            proof.storage_root == entry.map_or(EMPTY_ROOT_HASH, storage_root),
            "{address}: storage root {}",
            proof.storage_root
        );
        let expected = path(&accounts, keccak256(address));
        ensure!(
            proof.proof == expected,
            "{address}: account proof nodes {:?}, expected {expected:?}",
            proof.proof
        );
        ensure!(proof.storage_proofs.len() == slots.len(), "{address}: storage proof count");
        let storage = reference(
            entry
                .into_iter()
                .flat_map(|entry| &entry.storage)
                .map(|(slot, value)| (keccak256(B256::from(*slot)), alloy_rlp::encode(value))),
            slots.iter().map(keccak256),
        );
        for (slot, storage_proof) in slots.iter().zip(&proof.storage_proofs) {
            let value = entry
                .and_then(|entry| entry.storage.get(&U256::from_be_bytes(slot.0)))
                .copied()
                .unwrap_or_default();
            assert_sometimes!(
                entry.is_some() && value.is_zero(),
                "Storage exclusion proof checked",
                &json!({})
            );
            ensure!(
                storage_proof.key == *slot,
                "{address}: storage proof for {}",
                storage_proof.key
            );
            ensure!(
                storage_proof.value == value,
                "{address}/{slot}: value {}",
                storage_proof.value
            );
            let expected = path(&storage, keccak256(slot));
            ensure!(
                storage_proof.proof == expected,
                "{address}/{slot}: storage proof nodes {:?}, expected {expected:?}",
                storage_proof.proof
            );
        }
    }
    Ok(())
}

/// Rebuilds a trie from its leaves with `HashBuilder`, retaining the nodes on every target path.
fn reference(
    leaves: impl IntoIterator<Item = (B256, Vec<u8>)>,
    targets: impl IntoIterator<Item = B256>,
) -> ProofNodes {
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(
        targets.into_iter().map(Nibbles::unpack).collect(),
    ));
    // HashBuilder needs sorted keys.
    for (key, value) in leaves.into_iter().collect::<BTreeMap<_, _>>() {
        builder.add_leaf(Nibbles::unpack(key), &value);
    }
    builder.root();
    builder.take_proof_nodes()
}

/// The reference nodes on `key`'s path, root first.
fn path(nodes: &ProofNodes, key: B256) -> Vec<Bytes> {
    nodes.matching_nodes_sorted(&Nibbles::unpack(key)).into_iter().map(|(_, node)| node).collect()
}
