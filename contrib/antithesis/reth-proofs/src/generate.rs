//! Random writes and `eth_getMultiProof` targets, biased towards shared hashed-key prefixes.
//!
//! Uniform keys rarely share more than a few leading nibbles, so the tries stay shallow. Collision
//! groups from `antithesis-trie-shapes`, shared with reth-state-root, build deep branches and
//! extensions and later grow, collapse and rewrite them; grinding neighbours of existing keys
//! requests exclusion proofs that diverge inside them.

use crate::model::{collide, collide_next, random_address, random_slot, Model, Update};
use alloy_primitives::{Address, B256, U256};
use antithesis_trie_shapes::{
    harness::{AccountSample, ProofTarget},
    near_address, near_slot, Collider,
};
use rand_09::Rng;

/// Generates one block's writes. New random accounts stop at `accounts`; collision groups add
/// a bounded number on top.
#[allow(clippy::clone_on_copy, reason = "Account is not Copy with account-ext enabled.")]
pub(crate) fn writes(
    rng: &mut impl Rng,
    state: &Model,
    collider: &mut Collider,
    accounts: usize,
    updates: usize,
) -> Vec<Update> {
    let mut state = state.clone();
    let mut generated = Vec::with_capacity(updates);
    while generated.len() < updates {
        if collide_next(rng, generated.len(), updates) {
            generated.extend(collide(rng, &mut state, collider, updates - generated.len()));
            continue;
        }
        generated.push({
            let addresses = state.keys().copied().collect::<Vec<_>>();
            let address = if !addresses.is_empty() &&
                (addresses.len() >= accounts || rng.random_ratio(3, 4))
            {
                addresses[rng.random_range(0..addresses.len())]
            } else {
                new_address(rng, &addresses)
            };
            let update = if !state.contains_key(&address) || rng.random_ratio(1, 4) {
                let mut account =
                    state.get(&address).map(|entry| entry.account.clone()).unwrap_or_default();
                account.nonce += 1;
                account.balance = U256::from(rng.random_range(1..=1_000_000u64));
                Update::Account { address, account }
            } else {
                // Revisit touched slots so overwrites and deletions collapse existing branches.
                let slots = state[&address].touched_slots.iter().copied().collect::<Vec<_>>();
                let slot = if !slots.is_empty() && rng.random_bool(0.5) {
                    slots[rng.random_range(0..slots.len())]
                } else {
                    new_slot(rng, &slots)
                };
                let value = if rng.random_ratio(1, 3) {
                    U256::ZERO
                } else {
                    U256::from(rng.random::<u64>())
                };
                Update::Storage { address, slot, value }
            };
            update.apply_to_model(&mut state);
            update
        });
    }
    generated
}

/// Generates one request's targets from a sample of the tip state: existing, deleted and absent
/// keys, absent neighbours of existing keys, and repeated addresses. At older blocks, keys of the
/// tip state may not exist yet.
pub(crate) fn targets(rng: &mut impl Rng, accounts: &[AccountSample]) -> Vec<ProofTarget> {
    let addresses = accounts.iter().map(|account| account.address).collect::<Vec<_>>();
    let mut targets = Vec::<ProofTarget>::new();
    for _ in 0..rng.random_range(1..=8) {
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

/// Draws a fresh address, half the time one whose hash shares a prefix with an existing one.
fn new_address(rng: &mut impl Rng, addresses: &[Address]) -> Address {
    if addresses.is_empty() || rng.random_bool(0.5) {
        return random_address(rng);
    }
    let of = addresses[rng.random_range(0..addresses.len())];
    near_address(rng, of)
}

/// Draws a fresh slot, half the time one whose hash shares a prefix with an existing one.
fn new_slot(rng: &mut impl Rng, slots: &[U256]) -> U256 {
    if slots.is_empty() || rng.random_bool(0.5) {
        return random_slot(rng);
    }
    let of = slots[rng.random_range(0..slots.len())];
    near_slot(rng, of)
}
