//! The server's `eth_getMultiProof` proof path and the execution witness of the same reads. The
//! test commands check both (antithesis-trie-shapes `proofs`).

use alloy_primitives::{keccak256, Bytes};
use antithesis_trie_shapes::harness::ProofTarget;
use eyre::Result;
use reth_provider::StateProofProvider;
use reth_trie::{
    AccountProof, ExecutionWitnessMode, HashedPostState, MultiProofTargetsV2, ProofV2Target,
    TrieInput,
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
