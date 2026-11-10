//! Test-command side of the reth-proofs workload: random `eth_getMultiProof` targets, and the
//! checks of the proofs and execution witness the server returns against the model's state root.

use crate::{
    harness::{AccountSample, ProofTarget},
    near_address, near_slot, Collider,
};
use alloy_primitives::{keccak256, map::B256Map, Address, Bytes, B256, U256};
use antithesis_sdk::assert_sometimes;
use eyre::{ensure, eyre, Result};
use rand_09::Rng;
use reth_trie_common::{AccountProof, DecodedMultiProofV2, TrieNodeV2};
use serde::{Deserialize, Serialize};

/// The server's answer to one proof request.
#[derive(Debug, Serialize, Deserialize)]
pub struct Proved {
    /// `eth_getMultiProof`'s proofs, one per target.
    pub proofs: Vec<AccountProof>,
    /// The execution witness of a block reading the same targets.
    pub witness: Vec<Bytes>,
}

/// Generates one request's targets from a sample of the tip state: existing, deleted and absent
/// keys, absent neighbours of existing keys, repeated addresses, and every slot of a storage
/// collider group. At older blocks, keys of the tip state may not exist yet.
pub fn targets(
    rng: &mut impl Rng,
    accounts: &[AccountSample],
    collider: &Collider,
) -> Vec<ProofTarget> {
    let addresses = accounts.iter().map(|account| account.address).collect::<Vec<_>>();
    let groups = collider.storage_groups().collect::<Vec<_>>();
    let mut targets = Vec::<ProofTarget>::new();
    for _ in 0..rng.random_range(1..=8) {
        // Random slots almost never land on a leaf embedded in its parent; group members do.
        if !groups.is_empty() && rng.random_ratio(1, 8) {
            let (address, slots) = groups[rng.random_range(0..groups.len())];
            targets.push(ProofTarget { address, slots: slots.to_vec() });
            continue;
        }
        let roll = rng.random_range(0..8);
        let address = if roll == 0 && !targets.is_empty() {
            targets[rng.random_range(0..targets.len())].address
        } else if roll < 5 && !addresses.is_empty() {
            addresses[rng.random_range(0..addresses.len())]
        } else {
            new_address(rng, &addresses)
        };
        // Touched slots include deleted ones, whose exclusion proofs end at collapsed nodes.
        let slots = accounts
            .iter()
            .find(|account| account.address == address)
            .map(|account| account.slots.clone())
            .unwrap_or_default();
        let requested = (0..rng.random_range(0..=6))
            .map(|_| {
                B256::from(if !slots.is_empty() && rng.random_bool(0.5) {
                    slots[rng.random_range(0..slots.len())]
                } else {
                    new_slot(rng, &slots)
                })
            })
            .collect();
        targets.push(ProofTarget { address, slots: requested });
    }
    targets
}

/// Rebuilds the targets' proofs from a flat witness the way a stateless prover does, starting
/// from `root`.
pub fn from_witness(
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
pub fn check(root: B256, targets: &[ProofTarget], proofs: &[AccountProof]) -> Result<()> {
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

/// Draws a fresh address, half the time one whose hash shares a prefix with an existing one.
fn new_address(rng: &mut impl Rng, addresses: &[Address]) -> Address {
    if addresses.is_empty() || rng.random_bool(0.5) {
        return Address::from(rng.random::<[u8; 20]>());
    }
    let of = addresses[rng.random_range(0..addresses.len())];
    near_address(rng, of)
}

/// Draws a fresh slot, half the time one whose hash shares a prefix with an existing one.
fn new_slot(rng: &mut impl Rng, slots: &[U256]) -> U256 {
    if slots.is_empty() || rng.random_bool(0.5) {
        return U256::from_be_bytes(rng.random::<[u8; 32]>());
    }
    let of = slots[rng.random_range(0..slots.len())];
    near_slot(rng, of)
}
