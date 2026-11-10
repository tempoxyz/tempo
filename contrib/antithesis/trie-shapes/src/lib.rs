//! Trie shapes for the reth Antithesis workloads: key layouts to generate, and a tracker that
//! measures which shapes the tries actually reach.
//!
//! Keys are hashes, so uniformly random keys build tries that are wide near the root and shallow
//! below it. A collider grinds key preimages into templates, in the account trie or in one
//! account's storage trie:
//!
//! - spike: a birthday-ground pair sharing up to 10 leading nibbles, plus up to two neighbours on a
//!   shorter prefix: long extensions ending in a narrow branch.
//! - fan: 2 to 16 keys that diverge at the nibble after a 1 to 3 nibble prefix: wide branches below
//!   the root.
//! - nest: a fan under the prefix of an existing group's key, with deeper neighbours under some of
//!   its children: extensions and branches nested in each other.
//! - mass: random slots added to one heavy storage trie, so its upper levels fill up.
//!
//! Storage values have a random byte width from 1 to 32, so deep leaves land on both sides of the
//! boundary below which a leaf is embedded in its parent. Later steps revisit recorded groups:
//! growing them, clearing every storage key, or rewriting a subset, so branches split and collapse.
//! A targeted search for a d-nibble prefix costs about 16^d hashes, which bounds fans to shallow
//! prefixes; past that, width comes only from key count. [ShapeTracker] reports the shapes the
//! resulting tries really have.

pub mod harness;
mod shape;

pub use shape::{Leaves, ShapeTracker};

use alloy_primitives::{keccak256, Address, B256, U256};
use antithesis_sdk::assert_sometimes;
use rand_09::{seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{hash_map::Entry, HashMap};

/// Deepest shared prefix, in nibbles, a spike pair is ground for: about 16^(depth/2) candidates,
/// about a million at 10.
const MAX_DEPTH: usize = 10;
/// Deepest prefix a neighbour is ground to match: about 16^depth candidates, a million at 5.
const MAX_NEIGHBOR_DEPTH: usize = 5;
/// Deepest prefix a fan's children share: each child costs about 16^(depth + 1) candidates.
const MAX_FAN_DEPTH: usize = 3;
/// Most neighbours a spike gets on top of its pair.
const MAX_NEIGHBORS: usize = 2;
/// Most keys a group grows to.
const MAX_MEMBERS: usize = 32;
/// Most recorded groups; at the cap every step revisits one.
const MAX_GROUPS: usize = 32;
/// Shared prefixes from this long count as deep for coverage.
const DEEP: usize = MAX_DEPTH - 2;

/// The trie a group's keys live in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Trie {
    /// Keys are hashed addresses.
    Accounts,
    /// Keys are hashed slots of this account.
    Storage(Address),
}

impl Trie {
    /// Where the key with this preimage word sits in the trie.
    fn key(self, word: B256) -> B256 {
        match self {
            Self::Accounts => keccak256(Address::from_word(word)),
            Self::Storage(_) => keccak256(word),
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

/// One generated write. Account writes create or update the account with a nonzero balance;
/// storage writes of zero clear the slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Write {
    Account { address: Address, balance: U256 },
    Storage { address: Address, slot: U256, value: U256 },
}

/// A recorded group of key preimage words in one trie.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    trie: Trie,
    members: Vec<B256>,
}

/// Groups generated so far in one round's state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collider {
    groups: Vec<Group>,
    /// The account whose storage trie mass steps fill.
    heavy: Option<Address>,
    max_depth: usize,
}

impl Default for Collider {
    fn default() -> Self {
        Self::new(MAX_DEPTH)
    }
}

impl Collider {
    /// A collider whose searches go at most max_depth nibbles deep (at most 10).
    fn new(max_depth: usize) -> Self {
        assert!((2..=MAX_DEPTH).contains(&max_depth));
        Self { groups: Vec::new(), heavy: None, max_depth }
    }

    fn neighbor_depth(&self) -> usize {
        self.max_depth.min(MAX_NEIGHBOR_DEPTH)
    }

    fn fan_depth(&self) -> usize {
        MAX_FAN_DEPTH.min(self.max_depth - 1)
    }

    /// One step of at most budget writes: revisits a recorded group, or generates a spike, fan,
    /// nest or mass, in the account trie or, when an existing owner is given, in a storage trie.
    pub fn step(
        &mut self,
        rng: &mut impl Rng,
        owner: Option<Address>,
        budget: usize,
    ) -> Vec<Write> {
        if budget == 0 {
            return Vec::new();
        }
        let recorded = self.groups.len();
        let revisit =
            !self.groups.is_empty() && (self.groups.len() >= MAX_GROUPS || rng.random_ratio(2, 5));
        let mut writes = if revisit {
            self.revisit(rng, budget)
        } else {
            let trie = match owner {
                Some(owner) if rng.random_bool(0.5) => Trie::Storage(owner),
                _ => Trie::Accounts,
            };
            match (rng.random_range(0..4), owner) {
                (0, _) => self.spike(rng, trie),
                (1, _) => self.fan(rng, trie, budget),
                (2, _) if !self.groups.is_empty() => self.nest(rng, budget),
                (3, Some(owner)) => self.mass(rng, owner, budget),
                _ => self.spike(rng, trie),
            }
        };
        writes.truncate(budget);
        // A new group's writes follow its members in order: keep only the members written.
        if self.groups.len() > recorded {
            self.groups.last_mut().expect("a group was recorded").members.truncate(writes.len());
        }
        writes
    }

    /// Each storage group's account and slots, deleted ones included: deep groups hold the
    /// leaves embedded in their parents.
    pub fn storage_groups(&self) -> impl Iterator<Item = (Address, &[B256])> {
        self.groups.iter().filter_map(|group| match group.trie {
            Trie::Accounts => None,
            Trie::Storage(address) => Some((address, group.members.as_slice())),
        })
    }

    /// Adds the groups and members other recorded, as test commands step copies of the server's
    /// collider concurrently. A group is identified by its trie and first member, and grows to at
    /// most MAX_MEMBERS from other's; new groups stop at MAX_GROUPS.
    pub fn merge(&mut self, other: Self) {
        self.heavy = self.heavy.or(other.heavy);
        for group in other.groups {
            let existing = self.groups.iter().position(|existing| {
                existing.trie == group.trie && existing.members.first() == group.members.first()
            });
            match existing {
                Some(index) => {
                    let existing = &mut self.groups[index];
                    for member in group.members {
                        if existing.members.len() < MAX_MEMBERS &&
                            !existing.members.contains(&member)
                        {
                            existing.members.push(member);
                        }
                    }
                }
                None if self.groups.len() < MAX_GROUPS => self.groups.push(group),
                None => {}
            }
        }
    }

    /// Records a new group and returns writes setting each key to a random value.
    fn record(&mut self, rng: &mut impl Rng, trie: Trie, members: Vec<B256>) -> Vec<Write> {
        let writes = members.iter().map(|word| trie.write(*word, random_value(rng))).collect();
        self.groups.push(Group { trie, members });
        writes
    }

    fn spike(&mut self, rng: &mut impl Rng, trie: Trie) -> Vec<Write> {
        let depth = rng.random_range(1..=self.max_depth);
        let (first, second) = colliding_pair(trie, rng.random(), depth);
        let mut members = vec![first, second];
        let prefix_key = trie.key(first);
        for _ in 0..rng.random_range(0..=MAX_NEIGHBORS) {
            let depth = rng.random_range(1..=depth.min(self.neighbor_depth()));
            let member = find(trie, b"nbor", rng.random(), prefix_key, depth, None);
            if !members.contains(&member) {
                members.push(member);
            }
        }
        let shared = shared_nibbles(trie.key(first), trie.key(second));
        let details = json!({"trie": format!("{trie:?}"), "shared": shared});
        assert_sometimes!(shared < 4, "A generated spike shares a short prefix", &details);
        assert_sometimes!(shared >= DEEP, "A generated spike shares a deep prefix", &details);
        self.record(rng, trie, members)
    }

    fn fan(&mut self, rng: &mut impl Rng, trie: Trie, budget: usize) -> Vec<Write> {
        let anchor = self.anchor(rng, trie);
        let depth = rng.random_range(1..=self.fan_depth());
        let members = fan_under(rng, trie, anchor, depth, budget.min(16));
        self.record(rng, trie, members)
    }

    /// A fan under the prefix of an existing group's key, with deeper neighbours under up to two
    /// of its children.
    fn nest(&mut self, rng: &mut impl Rng, budget: usize) -> Vec<Write> {
        let group = &self.groups[rng.random_range(0..self.groups.len())];
        let trie = group.trie;
        let anchor = trie.key(group.members[rng.random_range(0..group.members.len())]);
        let depth = rng.random_range(1..=self.fan_depth());
        let mut members = fan_under(rng, trie, anchor, depth, budget.min(8));
        if depth + 2 <= self.neighbor_depth() {
            for child in members.clone().into_iter().take(rng.random_range(1..=2)) {
                let deeper = rng.random_range(depth + 2..=self.neighbor_depth());
                let member = find(trie, b"nest", rng.random(), trie.key(child), deeper, None);
                if !members.contains(&member) {
                    members.push(member);
                }
            }
        }
        self.record(rng, trie, members)
    }

    /// Random slots for the heavy account's storage trie, the first owner a mass step gets.
    fn mass(&mut self, rng: &mut impl Rng, owner: Address, budget: usize) -> Vec<Write> {
        let address = *self.heavy.get_or_insert(owner);
        (0..rng.random_range(1..=budget))
            .map(|_| Write::Storage {
                address,
                slot: U256::from_be_bytes(rng.random::<[u8; 32]>()),
                value: random_value(rng),
            })
            .collect()
    }

    /// A key to build under: a recorded member's key in this trie, or a random one.
    fn anchor(&self, rng: &mut impl Rng, trie: Trie) -> B256 {
        let members = self
            .groups
            .iter()
            .filter(|group| group.trie == trie)
            .flat_map(|group| &group.members)
            .collect::<Vec<_>>();
        if members.is_empty() || rng.random_bool(0.25) {
            B256::from(rng.random::<[u8; 32]>())
        } else {
            trie.key(*members[rng.random_range(0..members.len())])
        }
    }

    /// Grows, clears or rewrites a random recorded group, within budget writes.
    fn revisit(&mut self, rng: &mut impl Rng, budget: usize) -> Vec<Write> {
        let neighbor_depth = self.neighbor_depth();
        let index = rng.random_range(0..self.groups.len());
        let group = &mut self.groups[index];
        let trie = group.trie;
        let storage = matches!(trie, Trie::Storage(_));
        match rng.random_range(0..4) {
            // Grow: a new key under a member's prefix splits a branch or extension.
            0 if group.members.len() < MAX_MEMBERS => {
                let anchor = group.members[rng.random_range(0..group.members.len())];
                let depth = rng.random_range(1..=neighbor_depth);
                let member = find(trie, b"grow", rng.random(), trie.key(anchor), depth, None);
                if group.members.contains(&member) {
                    return Vec::new();
                }
                assert_sometimes!(true, "A generated group grows", &json!({}));
                group.members.push(member);
                vec![trie.write(member, random_value(rng))]
            }
            // Clear every storage key, so the whole subtree goes. Accounts are never deleted.
            1 if storage && group.members.len() <= budget => {
                assert_sometimes!(true, "A generated storage group is cleared", &json!({}));
                group.members.iter().map(|word| trie.write(*word, U256::ZERO)).collect()
            }
            // Rewrite a random nonempty subset; storage keys clear a quarter of the time.
            _ => {
                let mut subset = group
                    .members
                    .iter()
                    .copied()
                    .filter(|_| rng.random_bool(0.5))
                    .collect::<Vec<_>>();
                if subset.is_empty() {
                    subset.push(group.members[rng.random_range(0..group.members.len())]);
                }
                subset.shuffle(rng);
                subset.truncate(budget);
                subset
                    .into_iter()
                    .map(|word| {
                        let value = if storage && rng.random_ratio(1, 4) {
                            U256::ZERO
                        } else {
                            random_value(rng)
                        };
                        trie.write(word, value)
                    })
                    .collect()
            }
        }
    }
}

/// Up to count keys (at least 2) sharing the first depth nibbles of anchor, each with a different
/// nibble after them.
fn fan_under(
    rng: &mut impl Rng,
    trie: Trie,
    anchor: B256,
    depth: usize,
    count: usize,
) -> Vec<B256> {
    let mut nibbles = (0..16u8).collect::<Vec<_>>();
    nibbles.shuffle(rng);
    nibbles.truncate(rng.random_range(2..=count.max(2)));
    nibbles
        .into_iter()
        .map(|nibble| find(trie, b"fan_", rng.random(), anchor, depth, Some(nibble)))
        .collect()
}

/// An address whose hash shares 1 to 4 leading nibbles with the hash of of.
pub fn near_address(rng: &mut impl Rng, of: Address) -> Address {
    let depth = rng.random_range(1..=4);
    Address::from_word(find(Trie::Accounts, b"near", rng.random(), keccak256(of), depth, None))
}

/// A slot whose hash shares 1 to 4 leading nibbles with the hash of of.
pub fn near_slot(rng: &mut impl Rng, of: U256) -> U256 {
    let depth = rng.random_range(1..=4);
    let key = keccak256(B256::from(of));
    let trie = Trie::Storage(Address::ZERO);
    U256::from_be_bytes(find(trie, b"near", rng.random(), key, depth, None).0)
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

/// How many leading nibbles a and b share.
fn shared_nibbles(a: B256, b: B256) -> usize {
    alloy_trie::Nibbles::unpack(a).common_prefix_length(&alloy_trie::Nibbles::unpack(b))
}

/// The first depth nibbles of key, as an integer.
fn prefix(key: B256, depth: usize) -> u64 {
    u64::from_be_bytes(key[..8].try_into().expect("8 bytes")) >> (64 - 4 * depth)
}

/// The preimage word of candidate counter of a search tagged tag from seed. Its last 20 bytes are
/// the address an account candidate uses.
fn candidate(tag: &[u8; 4], seed: u64, counter: u64) -> B256 {
    let mut word = [0u8; 32];
    word[12..16].copy_from_slice(tag);
    word[16..24].copy_from_slice(&seed.to_be_bytes());
    word[24..].copy_from_slice(&counter.to_be_bytes());
    B256::from(word)
}

/// Two preimages, derived from seed, whose keys in trie share at least the first depth nibbles.
/// A birthday search: about 16^(depth/2) candidates.
fn colliding_pair(trie: Trie, seed: u64, depth: usize) -> (B256, B256) {
    assert!((1..=15).contains(&depth));
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

/// A preimage, derived from seed, whose key in trie shares the first depth nibbles of key and,
/// when next is given, has it as the following nibble; never key itself. A targeted search: about
/// 16^depth candidates, 16 times that with next.
fn find(trie: Trie, tag: &[u8; 4], seed: u64, key: B256, depth: usize, next: Option<u8>) -> B256 {
    let (width, target) = match next {
        Some(nibble) => (depth + 1, prefix(key, depth) << 4 | u64::from(nibble)),
        None => (depth, prefix(key, depth)),
    };
    assert!((1..=MAX_NEIGHBOR_DEPTH).contains(&width));
    (0..)
        .map(|counter| candidate(tag, seed, counter))
        .find(|word| {
            let found = trie.key(*word);
            found != key && prefix(found, width) == target
        })
        .expect("the search runs until it finds a key")
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
    fn found_keys_share_the_prefix() {
        for trie in TRIES {
            let key = keccak256([1u8]);
            for depth in 1..=4 {
                let found = trie.key(find(trie, b"test", 3, key, depth, None));
                assert!(shared_nibbles(key, found) >= depth);
            }
        }
    }

    #[test]
    fn fans_diverge_after_the_prefix() {
        let mut rng = StdRng::seed_from_u64(2);
        let anchor = keccak256([2u8]);
        for trie in TRIES {
            let members = fan_under(&mut rng, trie, anchor, 2, 16);
            let mut next = members
                .iter()
                .map(|word| {
                    let key = trie.key(*word);
                    assert!(shared_nibbles(anchor, key) >= 2);
                    alloy_trie::Nibbles::unpack(key).get_unchecked(2)
                })
                .collect::<Vec<_>>();
            next.sort_unstable();
            next.dedup();
            assert_eq!(next.len(), members.len());
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
    fn steps_stay_within_budget() {
        let mut rng = StdRng::seed_from_u64(1);
        // Shallow searches keep the unoptimized test build fast.
        let mut collider = Collider::new(3);
        for step in 0..300 {
            let budget = 1 + step % 20;
            let writes = collider.step(&mut rng, Some(Address::repeat_byte(1)), budget);
            assert!(writes.len() <= budget);
            for write in writes {
                if let Write::Account { balance, .. } = write {
                    assert!(!balance.is_zero());
                }
            }
        }
        assert!(collider.groups.len() <= MAX_GROUPS);
        assert!(collider.groups.iter().all(|group| group.members.len() <= MAX_MEMBERS + 16));
    }

    #[test]
    fn new_groups_hold_only_written_members() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut collider = Collider::new(3);
        for _ in 0..300 {
            let before = collider.groups.len();
            let writes = collider.step(&mut rng, Some(Address::repeat_byte(1)), 2);
            if collider.groups.len() > before {
                assert_eq!(collider.groups.last().unwrap().members.len(), writes.len());
            }
        }
    }

    #[test]
    fn merge_keeps_concurrent_steps() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut server = Collider::new(3);
        server.step(&mut rng, None, 8);
        let (mut first, mut second) = (server.clone(), server.clone());
        while first.groups.len() == server.groups.len() {
            first.step(&mut rng, Some(Address::repeat_byte(1)), 8);
        }
        while second.groups.len() == server.groups.len() {
            second.step(&mut rng, Some(Address::repeat_byte(2)), 8);
        }
        let grown = first.groups[0].members.len().max(second.groups[0].members.len());
        server.merge(first);
        server.merge(second);
        assert!(server.groups.len() >= 3);
        assert!(server.groups[0].members.len() >= grown.min(MAX_MEMBERS));
        // Merging the same groups again adds nothing.
        let before = server.clone();
        server.merge(before.clone());
        assert_eq!(server.groups.len(), before.groups.len());
        assert!(server.groups.iter().zip(&before.groups).all(|(a, b)| a.members == b.members));
    }
}
