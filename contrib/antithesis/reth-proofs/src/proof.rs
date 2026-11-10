//! The `eth_getMultiProof` proof path, and the check of its proofs against the state root.

use alloy_primitives::keccak256;
use antithesis_trie_shapes::harness::ProofTarget;
use eyre::Result;
use reth_provider::StateProofProvider;
use reth_trie::{AccountProof, MultiProofTargetsV2, ProofV2Target};

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
