//! Random writes, biased towards shared hashed-key prefixes.
//!
//! Uniform keys rarely share more than a few leading nibbles, so the tries stay shallow. Collision
//! groups from `antithesis-trie-shapes` build deep branches and extensions and later grow, collapse
//! and rewrite them; new keys drawn near existing ones deepen the tries inside them.

use crate::model::{collide, collide_next, random_address, random_slot, Model, Update};
use alloy_primitives::{Address, U256};
use antithesis_trie_shapes::{near_address, near_slot, Collider};
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
