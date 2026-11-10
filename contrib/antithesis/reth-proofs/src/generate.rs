//! Random writes and `eth_getMultiProof` targets, biased towards shared hashed-key prefixes.
//!
//! Uniform keys rarely share more than a few leading nibbles, so the tries stay shallow. Grinding
//! neighbours of existing keys builds deeper branches and extensions, and requests exclusion
//! proofs that diverge inside them.

use crate::model::{random_address, random_slot, Model, Update};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_trie::Nibbles;
use rand_09::Rng;

/// Longest hashed-key prefix to grind; each nibble multiplies the expected hashing work by 16.
const MAX_SHARED_NIBBLES: usize = 4;

/// Generates one block's writes, keeping at most `accounts` accounts.
#[allow(clippy::clone_on_copy, reason = "Account is not Copy with account-ext enabled.")]
pub(crate) fn writes(
    rng: &mut impl Rng,
    state: &Model,
    accounts: usize,
    updates: usize,
) -> Vec<Update> {
    let mut state = state.clone();
    (0..updates)
        .map(|_| {
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
        })
        .collect()
}

/// Generates one request's `(address, slots)` targets: existing, deleted and absent keys,
/// absent neighbours of existing keys, and repeated addresses.
pub(crate) fn targets(rng: &mut impl Rng, state: &Model) -> Vec<(Address, Vec<B256>)> {
    let addresses = state.keys().copied().collect::<Vec<_>>();
    let mut targets = Vec::<(Address, Vec<B256>)>::new();
    for _ in 0..rng.random_range(1..=8) {
        let roll = rng.random_range(0..8);
        let address = if roll == 0 && !targets.is_empty() {
            targets[rng.random_range(0..targets.len())].0
        } else if roll < 5 && !addresses.is_empty() {
            addresses[rng.random_range(0..addresses.len())]
        } else {
            new_address(rng, &addresses)
        };
        // Touched slots include deleted ones, whose exclusion proofs end at collapsed nodes.
        let slots = state
            .get(&address)
            .map(|entry| entry.touched_slots.iter().copied().collect::<Vec<_>>())
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
        targets.push((address, requested));
    }
    targets
}

/// Draws a fresh address, half the time one whose hash shares a prefix with an existing one.
fn new_address(rng: &mut impl Rng, addresses: &[Address]) -> Address {
    if addresses.is_empty() || rng.random_bool(0.5) {
        return random_address(rng);
    }
    let neighbour = keccak256(addresses[rng.random_range(0..addresses.len())]);
    grind(rng, neighbour, Address::from_word, |address| keccak256(address))
}

/// Draws a fresh slot, half the time one whose hash shares a prefix with an existing one.
fn new_slot(rng: &mut impl Rng, slots: &[U256]) -> U256 {
    if slots.is_empty() || rng.random_bool(0.5) {
        return random_slot(rng);
    }
    let neighbour = keccak256(B256::from(slots[rng.random_range(0..slots.len())]));
    grind(rng, neighbour, |word| U256::from_be_bytes(word.0), |slot| keccak256(B256::from(*slot)))
}

/// Returns the first preimage derived from one random seed whose hash shares
/// `1..=MAX_SHARED_NIBBLES` leading nibbles with `neighbour`, without being equal to it.
///
/// Deriving candidates locally keeps the search to one Antithesis random draw.
fn grind<T>(
    rng: &mut impl Rng,
    neighbour: B256,
    preimage: impl Fn(B256) -> T,
    hash: impl Fn(&T) -> B256,
) -> T {
    let shared = rng.random_range(1..=MAX_SHARED_NIBBLES);
    let seed = rng.random::<u64>();
    let neighbour_nibbles = Nibbles::unpack(neighbour);
    let mut counter = 0u64;
    loop {
        let mut input = [0; 16];
        input[..8].copy_from_slice(&seed.to_be_bytes());
        input[8..].copy_from_slice(&counter.to_be_bytes());
        let candidate = preimage(keccak256(input));
        let hashed = hash(&candidate);
        if hashed != neighbour &&
            Nibbles::unpack(hashed).common_prefix_length(&neighbour_nibbles) >= shared
        {
            return candidate;
        }
        counter += 1;
    }
}
