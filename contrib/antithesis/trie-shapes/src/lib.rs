//! Trie key shapes for the reth Antithesis workloads, ported from the zones collide driver.
//!
//! Uniformly random keys keep a trie shallow and bushy: among 10,000 keys, two share eight
//! leading nibbles in about one run in a hundred. A collision group is a birthday-ground pair of
//! keys sharing up to 10 leading nibbles, plus up to two neighbours matching a shorter
//! prefix, in the account trie or in one account's storage trie. Storage values have a random byte
//! width from 1 to 32, so leaves land on both sides of the boundary below which a leaf is embedded
//! in its parent instead of hashed. Later steps revisit recorded groups: growing them with a new
//! neighbour, clearing every storage key, or rewriting a subset, so blocks, persistence and proofs
//! have to read, split and collapse deep, narrow branches and extensions.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_trie::{nodes::LeafNode, Nibbles};
use antithesis_sdk::assert_sometimes;
use rand_09::Rng;
use serde_json::json;
use std::collections::{hash_map::Entry, HashMap};

/// Deepest shared prefix, in nibbles, a pair is ground for. Finding a pair takes about
/// 16^(depth/2) candidates, about a million at 10.
const MAX_DEPTH: usize = 10;
/// Deepest prefix a neighbour is ground to match. A targeted search takes about 16^depth
/// candidates, about a million at 5.
const MAX_NEIGHBOR_DEPTH: usize = 5;
/// Most neighbours a new group gets on top of its pair.
const MAX_NEIGHBORS: usize = 2;
/// Most keys a group grows to, which bounds the writes of one step.
pub const MAX_MEMBERS: usize = 8;
/// Most recorded groups; at the cap every step revisits one.
const MAX_GROUPS: usize = 32;
/// Shared prefixes from this long count as deep for coverage.
const DEEP: usize = MAX_DEPTH - 2;

/// The trie a group's keys live in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trie {
    /// Keys are hashed addresses.
    Accounts,
    /// Keys are hashed slots of this account.
    Storage(Address),
}

impl Trie {
    /// Where the key with preimage word `word` sits in the trie.
    fn key(self, word: B256) -> B256 {
        match self {
            Self::Accounts => keccak256(Address::from_word(word)),
            Self::Storage(_) => keccak256(word),
        }
    }

    /// The live value of the key with preimage word, as current reads it: an account's balance
    /// (zero when absent) or a slot's value.
    fn current(self, word: B256, current: &impl Fn(Address, Option<U256>) -> U256) -> U256 {
        match self {
            Self::Accounts => current(Address::from_word(word), None),
            Self::Storage(address) => current(address, Some(U256::from_be_bytes(word.0))),
        }
    }

    fn write(self, word: B256, value: U256) -> Write {
        match self {
            Self::Accounts => Write::Account { address: Address::from_word(word), balance: value },
            Self::Storage(address) => {
                Write::Storage { address, slot: U256::from_be_bytes(word.0), value }
            }
        }
    }
}

/// One write of a collide step. Account writes create or update the account with a nonzero
/// balance; storage writes of zero clear the slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    Account { address: Address, balance: U256 },
    Storage { address: Address, slot: U256, value: U256 },
}

/// A recorded collision group: key preimage words and their values, zero when cleared. Other
/// writes can change those keys too, so revisits refresh the values from the caller's state.
#[derive(Debug)]
struct Group {
    trie: Trie,
    members: Vec<B256>,
    values: Vec<U256>,
}

/// Collision groups generated so far in one round's state.
#[derive(Debug)]
pub struct Collider {
    groups: Vec<Group>,
    max_depth: usize,
}

impl Default for Collider {
    fn default() -> Self {
        Self::new(MAX_DEPTH)
    }
}

impl Collider {
    /// A collider grinding pairs that share up to max_depth nibbles, at most [MAX_DEPTH], and
    /// neighbours up to the smaller of max_depth and [MAX_NEIGHBOR_DEPTH].
    fn new(max_depth: usize) -> Self {
        assert!((1..=MAX_DEPTH).contains(&max_depth));
        Self { groups: Vec::new(), max_depth }
    }

    /// One collide step of at most [MAX_MEMBERS] writes: half the time revisits a recorded
    /// group, otherwise grinds a new one, in the account trie or, when an existing `owner` is
    /// given, half the time in its storage trie. current reads the live value of a key from the
    /// caller's state: an account's balance for no slot, otherwise the slot's value.
    pub fn step(
        &mut self,
        rng: &mut impl Rng,
        owner: Option<Address>,
        current: impl Fn(Address, Option<U256>) -> U256,
    ) -> Vec<Write> {
        if !self.groups.is_empty() && (self.groups.len() >= MAX_GROUPS || rng.random_bool(0.5)) {
            return self.revisit(rng, &current);
        }
        let trie = match owner {
            Some(owner) if rng.random_bool(0.5) => Trie::Storage(owner),
            _ => Trie::Accounts,
        };
        let depth = rng.random_range(1..=self.max_depth);
        let (first, second) = colliding_pair(trie, rng.random(), depth);
        let mut members = vec![first, second];
        let prefix_key = trie.key(first);
        for _ in 0..rng.random_range(0..=MAX_NEIGHBORS) {
            let neighbor_depth = rng.random_range(1..=depth.min(MAX_NEIGHBOR_DEPTH));
            let member = neighbor(trie, rng.random(), prefix_key, neighbor_depth);
            if !members.contains(&member) {
                members.push(member);
            }
        }
        let shared = shared_nibbles(trie.key(first), trie.key(second));
        let details = json!({"trie": format!("{trie:?}"), "shared": shared, "keys": members.len()});
        assert_sometimes!(shared < 4, "Generated colliding keys share a short prefix", &details);
        assert_sometimes!(shared >= DEEP, "Generated colliding keys share a deep prefix", &details);
        let values = members.iter().map(|_| random_value(rng)).collect();
        let mut group = Group { trie, members, values };
        let writes = (0..group.members.len()).collect::<Vec<_>>();
        let writes = group.writes(&writes);
        self.groups.push(group);
        writes
    }

    /// Grows, clears or rewrites a random recorded group.
    fn revisit(
        &mut self,
        rng: &mut impl Rng,
        current: &impl Fn(Address, Option<U256>) -> U256,
    ) -> Vec<Write> {
        let max_neighbor_depth = self.max_depth.min(MAX_NEIGHBOR_DEPTH);
        let index = rng.random_range(0..self.groups.len());
        let group = &mut self.groups[index];
        let trie = group.trie;
        for (member, value) in group.members.iter().zip(&mut group.values) {
            *value = trie.current(*member, current);
        }
        let storage = matches!(group.trie, Trie::Storage(_));
        let set_before = group.values.iter().filter(|value| !value.is_zero()).count();
        let indices = match rng.random_range(0..4) {
            // Grow: a new key under a member's prefix splits a branch or extension.
            0 if group.members.len() < MAX_MEMBERS => {
                let anchor = group.members[rng.random_range(0..group.members.len())];
                let depth = rng.random_range(1..=max_neighbor_depth);
                let member = neighbor(group.trie, rng.random(), group.trie.key(anchor), depth);
                if group.members.contains(&member) {
                    return Vec::new();
                }
                assert_sometimes!(set_before > 1, "A generated collision group grows", &json!({}));
                group.members.push(member);
                group.values.push(random_value(rng));
                vec![group.members.len() - 1]
            }
            // Clear every storage key, so the whole subtree goes. Accounts are never deleted.
            1 if storage => {
                assert_sometimes!(
                    set_before > 1,
                    "A generated storage collision group is cleared",
                    &json!({})
                );
                group.values.iter_mut().for_each(|value| *value = U256::ZERO);
                (0..group.members.len()).collect()
            }
            // Rewrite a random nonempty subset; storage keys clear a quarter of the time.
            _ => {
                let mut subset =
                    (0..group.members.len()).filter(|_| rng.random_bool(0.5)).collect::<Vec<_>>();
                if subset.is_empty() {
                    subset.push(rng.random_range(0..group.members.len()));
                }
                for &i in &subset {
                    group.values[i] = if storage && rng.random_ratio(1, 4) {
                        U256::ZERO
                    } else {
                        random_value(rng)
                    };
                }
                let set_after = group.values.iter().filter(|value| !value.is_zero()).count();
                assert_sometimes!(
                    set_after > 0 && set_after < set_before,
                    "A generated colliding key is cleared while a sibling keeps its value",
                    &json!({})
                );
                subset
            }
        };
        group.writes(&indices)
    }
}

impl Group {
    /// The writes setting members `indices` to their current values.
    fn writes(&mut self, indices: &[usize]) -> Vec<Write> {
        if matches!(self.trie, Trie::Storage(_)) {
            let keys = self.members.iter().map(|word| self.trie.key(*word)).collect::<Vec<_>>();
            let embeds = keys.iter().zip(&self.values).any(|(key, value)| {
                let depth = keys
                    .iter()
                    .zip(&self.values)
                    .filter(|(other, value)| *other != key && !value.is_zero())
                    .map(|(other, _)| shared_nibbles(*key, *other))
                    .max();
                !value.is_zero() && depth.is_some_and(|depth| embedded(depth, *value))
            });
            assert_sometimes!(embeds, "A generated colliding storage leaf is embedded", &json!({}));
        }
        indices.iter().map(|&i| self.trie.write(self.members[i], self.values[i])).collect()
    }
}

/// An address whose hash shares 1 to 4 leading nibbles with the hash of `of`.
pub fn near_address(rng: &mut impl Rng, of: Address) -> Address {
    let depth = rng.random_range(1..=4);
    Address::from_word(neighbor(Trie::Accounts, rng.random(), keccak256(of), depth))
}

/// A slot whose hash shares 1 to 4 leading nibbles with the hash of `of`.
pub fn near_slot(rng: &mut impl Rng, of: U256) -> U256 {
    let depth = rng.random_range(1..=4);
    let key = keccak256(B256::from(of));
    U256::from_be_bytes(neighbor(Trie::Storage(Address::ZERO), rng.random(), key, depth).0)
}

/// A random nonzero value of random byte width, so leaves span every encoding size: half the
/// time up to 4 bytes, as most real amounts are, otherwise up to 32.
fn random_value(rng: &mut impl Rng) -> U256 {
    let max_width = if rng.random_bool(0.5) { 4 } else { 32 };
    let width = rng.random_range(1..=max_width);
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[32 - width..]);
    U256::from_be_bytes(bytes).max(U256::from(1))
}

/// Whether a storage leaf holding `value` below a branch at `depth` nibbles encodes in under
/// 32 bytes, so its parent embeds it instead of referencing its hash.
fn embedded(depth: usize, value: U256) -> bool {
    let path = Nibbles::unpack(B256::ZERO).slice(depth + 1..);
    alloy_rlp::encode(LeafNode::new(path, alloy_rlp::encode(value))).len() < 32
}

/// How many leading nibbles `a` and `b` share.
fn shared_nibbles(a: B256, b: B256) -> usize {
    Nibbles::unpack(a).common_prefix_length(&Nibbles::unpack(b))
}

/// The first `depth` nibbles of `key`, as an integer.
fn prefix(key: B256, depth: usize) -> u64 {
    u64::from_be_bytes(key[..8].try_into().expect("8 bytes")) >> (64 - 4 * depth)
}

/// The preimage word of candidate `counter` of a search tagged `tag` from `seed`. Its last 20
/// bytes are the address an account candidate uses.
fn candidate(tag: &[u8; 4], seed: u64, counter: u64) -> B256 {
    let mut word = [0u8; 32];
    word[12..16].copy_from_slice(tag);
    word[16..24].copy_from_slice(&seed.to_be_bytes());
    word[24..].copy_from_slice(&counter.to_be_bytes());
    B256::from(word)
}

/// Two preimages, derived from `seed`, whose keys in `trie` share at least the first `depth`
/// nibbles. A birthday search: about 16^(depth/2) candidates.
fn colliding_pair(trie: Trie, seed: u64, depth: usize) -> (B256, B256) {
    assert!((1..=16).contains(&depth));
    let mut seen = HashMap::<u64, B256>::new();
    for counter in 0.. {
        let word = candidate(b"coll", seed, counter);
        match seen.entry(prefix(trie.key(word), depth)) {
            Entry::Occupied(entry) => return (*entry.get(), word),
            Entry::Vacant(entry) => {
                entry.insert(word);
            }
        }
    }
    unreachable!("the search runs until it finds a pair")
}

/// A preimage, derived from `seed`, whose key in `trie` shares at least the first `depth`
/// nibbles of `key` without being equal to it. A targeted search: about 16^depth candidates.
fn neighbor(trie: Trie, seed: u64, key: B256, depth: usize) -> B256 {
    assert!((1..=MAX_NEIGHBOR_DEPTH).contains(&depth));
    let target = prefix(key, depth);
    (0..)
        .map(|counter| candidate(b"nbor", seed, counter))
        .find(|word| {
            let candidate = trie.key(*word);
            candidate != key && prefix(candidate, depth) == target
        })
        .expect("the search runs until it finds a neighbour")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_09::{rngs::StdRng, SeedableRng};

    const TRIES: [Trie; 2] = [Trie::Accounts, Trie::Storage(Address::ZERO)];

    #[test]
    fn ground_pairs_share_the_prefix() {
        for trie in TRIES {
            for depth in [1, 4, 8] {
                let (a, b) = colliding_pair(trie, 7, depth);
                assert_ne!(trie.key(a), trie.key(b));
                assert!(shared_nibbles(trie.key(a), trie.key(b)) >= depth, "{trie:?} {depth}");
            }
        }
    }

    #[test]
    fn neighbors_share_the_prefix() {
        for trie in TRIES {
            let key = keccak256([1u8]);
            for depth in 1..=4 {
                assert!(shared_nibbles(key, trie.key(neighbor(trie, 3, key, depth))) >= depth);
            }
        }
    }

    #[test]
    fn writes_use_the_ground_keys() {
        let word = candidate(b"test", 1, 2);
        let Write::Account { address, .. } = Trie::Accounts.write(word, U256::from(1)) else {
            panic!("account write")
        };
        assert_eq!(keccak256(address), Trie::Accounts.key(word));
        let Write::Storage { slot, .. } = Trie::Storage(Address::ZERO).write(word, U256::from(1))
        else {
            panic!("storage write")
        };
        assert_eq!(keccak256(B256::from(slot)), Trie::Storage(Address::ZERO).key(word));
    }

    #[test]
    fn embedding_depends_on_depth_and_width() {
        // One-byte values embed from 8 shared nibbles, wider ones need deeper branches.
        assert!(embedded(8, U256::from(0x7f)));
        assert!(!embedded(7, U256::from(0x7f)));
        assert!(!embedded(8, U256::from(0x80)));
        assert!(embedded(MAX_DEPTH, U256::from(0x7f)));
        assert!(!embedded(MAX_DEPTH, U256::from(0xffff)));
        assert!(!embedded(MAX_DEPTH, U256::MAX));
    }

    #[test]
    fn steps_stay_bounded() {
        let mut rng = StdRng::seed_from_u64(1);
        // Shallow searches keep the unoptimized test build fast.
        let mut collider = Collider::new(3);
        for _ in 0..200 {
            let writes = collider.step(&mut rng, Some(Address::repeat_byte(1)), |_, _| U256::ZERO);
            assert!(writes.len() <= MAX_MEMBERS);
            for write in writes {
                if let Write::Account { balance, .. } = write {
                    assert!(!balance.is_zero());
                }
            }
        }
        assert!(collider.groups.len() <= MAX_GROUPS);
        assert!(collider.groups.iter().all(|group| group.members.len() <= MAX_MEMBERS));
    }
}
