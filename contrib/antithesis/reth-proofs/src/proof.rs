//! The `eth_getMultiProof` proof path, the execution witness of the same reads, and the check
//! of their proofs against the state root.

use alloy_primitives::{keccak256, map::B256Map, Bytes, B256};
use antithesis_sdk::assert_sometimes;
use antithesis_trie_shapes::harness::ProofTarget;
use eyre::{ensure, eyre, Result};
use reth_provider::StateProofProvider;
use reth_trie::{
    AccountProof, DecodedMultiProofV2, ExecutionWitnessMode, HashedPostState, MultiProofTargetsV2,
    ProofV2Target, TrieInput, TrieNodeV2,
};

/// Mirrors `EthState::get_multi_proof` once the block's state provider is resolved: one V2
/// multiproof for all targets, then an account proof for each requested `(address, slots)`.
pub(crate) fn get_multi_proof(
    state: &impl StateProofProvider,
    targets: &[ProofTarget],
) -> Result<Vec<AccountProof>> {
    let mut proof_targets = MultiProofTargetsV2::default();
    for ProofTarget { address, slots } in targets {
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
        .map(|target| multiproof.account_proof(target.address, &target.slots))
        .collect::<Result<_, _>>()?)
}

/// The trie part of `debug_executionWitness` for a block that only reads the proofs' targets:
/// the witness of a post state writing back the values the proofs read.
pub(crate) fn witness(
    state: &impl StateProofProvider,
    proofs: &[AccountProof],
) -> Result<Vec<Bytes>> {
    let mut post_state = HashedPostState::default();
    for proof in proofs {
        let hashed_address = keccak256(proof.address);
        post_state.accounts.insert(hashed_address, proof.info.clone());
        if !proof.storage_proofs.is_empty() {
            post_state.storages.entry(hashed_address).or_default().storage.extend(
                proof.storage_proofs.iter().map(|storage| (keccak256(storage.key), storage.value)),
            );
        }
    }
    Ok(state.witness(TrieInput::default(), post_state, ExecutionWitnessMode::Legacy)?)
}

/// Rebuilds the targets' proofs from a flat witness the way a stateless prover does, starting
/// from `root`.
pub(crate) fn from_witness(
    root: B256,
    targets: &[ProofTarget],
    witness: &[Bytes],
) -> Result<Vec<AccountProof>> {
    let nodes = witness.iter().map(|node| (keccak256(node), node)).collect::<B256Map<_>>();
    let decoded = DecodedMultiProofV2::from_witness(root, &nodes)?;
    // A leaf shorter than a hash is embedded in its parent, never a witness entry of its own.
    assert_sometimes!(
        decoded.storage_proofs.values().flatten().any(|node| {
            matches!(&node.node, TrieNodeV2::Leaf(leaf) if !node.path.is_empty() &&
                alloy_rlp::encode(leaf).len() < B256::len_bytes())
        }),
        "Witness decodes an inline storage leaf"
    );
    Ok(targets
        .iter()
        .map(|target| decoded.account_proof(target.address, &target.slots))
        .collect::<Result<_, _>>()?)
}

/// Checks that every proof answers its target and verifies against the block's state `root`.
pub(crate) fn check(root: B256, targets: &[ProofTarget], proofs: &[AccountProof]) -> Result<()> {
    ensure!(proofs.len() == targets.len(), "{} proofs for {} targets", proofs.len(), targets.len());
    for (ProofTarget { address, slots }, proof) in targets.iter().zip(proofs) {
        ensure!(proof.address == *address, "proof for {} answers {address}", proof.address);
        ensure!(proof.storage_proofs.len() == slots.len(), "{address}: storage proof count");
        for (slot, storage_proof) in slots.iter().zip(&proof.storage_proofs) {
            ensure!(
                storage_proof.key == *slot,
                "{address}: storage proof for {}",
                storage_proof.key
            );
            assert_sometimes!(
                proof.info.is_some() && storage_proof.value.is_zero(),
                "Storage exclusion proof checked"
            );
        }
        assert_sometimes!(proof.info.is_none(), "Account exclusion proof checked");
        proof.verify(root).map_err(|error| eyre!("{address} does not verify: {error:?}"))?;
    }
    Ok(())
}
