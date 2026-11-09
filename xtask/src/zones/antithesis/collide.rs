//! `collide`: pathUSD storage keys that share long trie prefixes.
//!
//! Uniformly random keys keep a storage trie shallow and bushy: among 10,000 keys, two share eight
//! leading nibbles in about one run in a hundred. This driver grinds addresses until the trie keys
//! of a mapping share a random number of leading nibbles, so pathUSD's storage trie also gets the
//! deep, narrow branches, extensions and nested subtries random traffic almost never builds.
//!
//! A group is a birthday-ground pair plus up to two neighbors matching a shorter prefix of the
//! pair's keys, in either the allowances of one owner (spenders ground) or the balances mapping
//! (holders ground and funded by a transfer). Values have a random byte width from 1 to 32, so
//! leaves land on both sides of every encoding boundary, including the one below which a leaf is
//! embedded in its parent instead of hashed. Later runs revisit recorded groups: rewriting or
//! clearing some keys, clearing all of them, or growing the group with a new neighbor, at any time
//! before or after the group settled, so blocks and batch proofs have to read, rewrite, split and
//! collapse those shapes.

use alloy::primitives::{Address, B256, TxKind, U256, keccak256};
use alloy_trie::{Nibbles, nodes::LeafNode};
use antithesis_sdk::{assert_always, assert_sometimes, random::get_random};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, hash_map::Entry};
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::{PATH_USD_ADDRESS, storage::StorageKey as _, tip20::slots};
use tempo_primitives::transaction::{Call, calc_gas_balance_spending};

use super::{
    BATCH_BASE_GAS, BATCH_CALL_GAS, Context, MIN_SENDER_BALANCE, Record, random_below,
    random_between, random_choice, shuffled,
};
use alloy::{providers::Provider as _, rpc::types::BlockId, sol_types::SolCall as _};

/// Deepest shared prefix, in nibbles, a pair is ground for. Finding a pair takes about
/// 16^(depth/2) candidates, about a million at 10.
const MAX_DEPTH: u64 = 10;
/// Deepest prefix a neighbor is ground to match. A targeted search takes about 16^depth
/// candidates, about a million at 5.
const MAX_NEIGHBOR_DEPTH: u64 = 5;
/// Most neighbors a new group gets on top of its pair.
const MAX_NEIGHBORS: u64 = 2;
/// Shared prefixes from this long count as deep for coverage.
const DEEP: u64 = MAX_DEPTH - 2;
/// Recorded groups a revisit considers before grinding a new one instead.
const REVISIT_CANDIDATES: usize = 16;

/// Which pathUSD mapping a collision group's keys are in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CollisionKind {
    /// `allowances[owner][member]`: members are spenders of one owner.
    #[default]
    Allowance,
    /// `balances[member]`: members are holders the owner funded.
    Balance,
}

impl CollisionKind {
    fn random() -> Self {
        if random_below(2) == 0 {
            Self::Allowance
        } else {
            Self::Balance
        }
    }

    /// The mapping slot member keys hash into.
    fn base(self, owner: Address) -> U256 {
        match self {
            Self::Allowance => owner.mapping_slot(slots::ALLOWANCES),
            Self::Balance => slots::BALANCES,
        }
    }
}

/// The storage slot of `member` in a collision group of `kind` under `owner`.
pub(super) fn collision_slot(kind: CollisionKind, owner: Address, member: Address) -> B256 {
    B256::from(member.mapping_slot(kind.base(owner)))
}

/// Where that slot sits in pathUSD's storage trie: the hash of the slot.
fn trie_key(base: U256, member: Address) -> B256 {
    keccak256(member.mapping_slot(base).to_be_bytes::<32>())
}

impl Context {
    /// Half the time revisits a recorded collision group, otherwise grinds and writes a new one
    /// for a leased owner.
    pub(super) async fn collide(&self) -> eyre::Result<()> {
        if random_below(2) == 0 && self.revisit_collision().await? {
            return Ok(());
        }
        let node = super::random_index(self.zones.len());
        let Some((owner, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        let kind = CollisionKind::random();
        let base = kind.base(owner.address());
        let depth = random_below(MAX_DEPTH) + 1;
        let (first, second) = colliding_pair(base, get_random(), depth);
        let mut members = vec![first, second];
        let prefix_key = trie_key(base, first);
        for _ in 0..random_below(MAX_NEIGHBORS + 1) {
            let neighbor_depth = random_between(1, u128::from(depth.min(MAX_NEIGHBOR_DEPTH)));
            let member = neighbor(base, get_random(), prefix_key, neighbor_depth as u64);
            if !members.contains(&member) {
                members.push(member);
            }
        }
        let writes: Vec<(Address, U256)> = members
            .iter()
            .map(|member| (*member, random_value(kind, balance, members.len())))
            .collect();
        let shared = shared_nibbles(trie_key(base, first), trie_key(base, second));
        let Some((block, _)) = self
            .write_group(node, &owner, balance, kind, &writes, &members)
            .await?
        else {
            return Ok(());
        };
        self.ledger.append(&Record::Collision {
            kind,
            owner: owner.address(),
            members: members.clone(),
            depth: shared,
            zone_block: block,
        })?;
        let details = json!({
            "kind": kind,
            "owner": owner.address(),
            "members": members,
            "shared": shared,
            "block": block,
        });
        assert_sometimes!(
            shared < 4,
            "Colliding storage keys share a short prefix",
            &details
        );
        assert_sometimes!(
            (4..DEEP).contains(&shared),
            "Colliding storage keys share a medium prefix",
            &details
        );
        assert_sometimes!(
            shared >= DEEP,
            "Colliding storage keys share a deep prefix",
            &details
        );
        assert_sometimes!(
            members[2..]
                .iter()
                .any(|member| shared_nibbles(prefix_key, trie_key(base, *member)) < shared),
            "A collision group nests neighbors around its pair",
            &details
        );
        assert_sometimes!(
            kind == CollisionKind::Balance,
            "Balance keys collide",
            &details
        );
        println!(
            "collide: {} {kind:?} keys under {} share {shared} nibbles, block {block}",
            members.len(),
            owner.address()
        );
        Ok(())
    }

    /// Rewrites, clears or grows a recorded group whose owner is free and funded. Returns whether
    /// it found such a group.
    async fn revisit_collision(&self) -> eyre::Result<bool> {
        let groups: Vec<(CollisionKind, Address, Vec<Address>, u64)> = self
            .ledger
            .records()?
            .into_iter()
            .filter_map(|record| match record {
                Record::Collision {
                    kind,
                    owner,
                    members,
                    zone_block,
                    ..
                } => Some((kind, owner, members, zone_block)),
                _ => None,
            })
            .collect();
        // A grown group is recorded again with its new key: only its largest record is live.
        let groups: Vec<_> = groups
            .iter()
            .filter(|(kind, owner, members, _)| {
                !groups.iter().any(|(other_kind, other_owner, others, _)| {
                    other_kind == kind
                        && other_owner == owner
                        && others.len() > members.len()
                        && members.iter().all(|member| others.contains(member))
                })
            })
            .cloned()
            .collect();
        let accounts = self.ledger.sender_accounts()?;
        for (kind, owner, members, zone_block) in
            shuffled(groups).into_iter().take(REVISIT_CANDIDATES)
        {
            let Some(account) = accounts.iter().find(|account| account.address() == owner) else {
                continue;
            };
            let Some(lease) = self.ledger.try_lease(account)? else {
                continue;
            };
            let node = super::random_index(self.zones.len());
            let balance: u128 = ITIP20::new(PATH_USD_ADDRESS, &self.zones[node])
                .balanceOf(owner)
                .from(owner)
                .call()
                .await?
                .try_into()?;
            if balance < MIN_SENDER_BALANCE {
                continue;
            }
            let base = kind.base(owner);
            let mut grown = members.clone();
            let action = random_below(4);
            let writes: Vec<(Address, U256)> = match action {
                // Grow: a new key under the group's prefix splits a branch or extension.
                0 => {
                    let anchor = random_choice(members.clone()).unwrap_or(owner);
                    let depth = random_between(1, u128::from(MAX_NEIGHBOR_DEPTH)) as u64;
                    let member = neighbor(base, get_random(), trie_key(base, anchor), depth);
                    if members.contains(&member) {
                        Vec::new()
                    } else {
                        grown.push(member);
                        vec![(member, random_value(kind, balance, 1))]
                    }
                }
                // Clear every allowance, so the whole subtree goes.
                1 if kind == CollisionKind::Allowance => {
                    members.iter().map(|member| (*member, U256::ZERO)).collect()
                }
                // Rewrite a random nonempty subset; allowances clear a quarter of the time.
                _ => {
                    let mut subset: Vec<Address> = members
                        .iter()
                        .copied()
                        .filter(|_| random_below(2) == 0)
                        .collect();
                    if subset.is_empty() {
                        subset.extend(random_choice(members.clone()));
                    }
                    subset
                        .into_iter()
                        .map(|member| {
                            let value = if kind == CollisionKind::Allowance && random_below(4) == 0
                            {
                                U256::ZERO
                            } else {
                                random_value(kind, balance, members.len())
                            };
                            (member, value)
                        })
                        .collect()
                }
            };
            let settled = match self.settled_block().await {
                Ok((height, _)) => height >= zone_block,
                Err(_) => false,
            };
            let Some((block, after)) = self
                .write_group(node, account, balance, kind, &writes, &grown)
                .await?
            else {
                return Ok(true);
            };
            if grown.len() > members.len() {
                self.ledger.append(&Record::Collision {
                    kind,
                    owner,
                    members: grown.clone(),
                    depth: deepest_shared(base, &grown),
                    zone_block: block,
                })?;
            }
            // Keys this block took from set to zero, and keys of the group left set, when known.
            let (cleared, present) = after.unzip();
            let details = json!({
                "kind": kind,
                "owner": owner,
                "members": grown,
                "writes": writes.len(),
                "cleared": cleared,
                "present": present,
                "settled": settled,
                "set_in": zone_block,
                "block": block,
            });
            assert_sometimes!(
                settled,
                "A collision group is rewritten after it settled",
                &details
            );
            assert_sometimes!(
                settled && grown.len() > members.len(),
                "A collision group grows after it settled",
                &details
            );
            assert_sometimes!(
                cleared > Some(0) && present > Some(0),
                "A colliding key is cleared while a sibling keeps its value",
                &details
            );
            assert_sometimes!(
                cleared > Some(0) && present == Some(0),
                "Every key of a collision group is cleared",
                &details
            );
            println!(
                "collide: revisited {kind:?} group of {owner}: {} writes, {cleared:?} cleared, {} keys (settled: {settled}), block {block}",
                writes.len(),
                grown.len()
            );
            drop(lease);
            return Ok(true);
        }
        Ok(false)
    }

    /// Sends `writes` as the calls of one Tempo transaction from `owner`: approvals for an
    /// allowance group, transfers (adding to each holder's balance, recorded as transfers for the
    /// finality checks) for a balance group. Checks every key reads back at the block it landed
    /// in, and returns that block, or `None` when the transaction did not fit half the balance,
    /// reverted or was not confirmed. `group` is every key of the group after these writes.
    /// With the block, when no other send of the owner's shared it: how many keys it took from
    /// set to zero, and how many keys of the group are set after it.
    async fn write_group(
        &self,
        node: usize,
        owner: &super::Account,
        balance: u128,
        kind: CollisionKind,
        writes: &[(Address, U256)],
        group: &[Address],
    ) -> eyre::Result<Option<(u64, Option<(usize, usize)>)>> {
        if writes.is_empty() {
            return Ok(None);
        }
        let zone = self.wallet(owner, &self.zone_urls[node]);
        let gas_price = zone.get_gas_price().await?;
        let gas_limit = BATCH_BASE_GAS + BATCH_CALL_GAS * writes.len() as u64;
        let spent: U256 = match kind {
            CollisionKind::Allowance => U256::ZERO,
            CollisionKind::Balance => writes.iter().map(|(_, value)| *value).sum(),
        };
        if calc_gas_balance_spending(gas_limit, gas_price) + spent > U256::from(balance / 2) {
            return Ok(None);
        }
        let writes = shuffled(writes.to_vec());
        let calls = writes
            .iter()
            .map(|(member, value)| {
                let input = match kind {
                    CollisionKind::Allowance => ITIP20::approveCall {
                        spender: *member,
                        amount: *value,
                    }
                    .abi_encode(),
                    CollisionKind::Balance => ITIP20::transferCall {
                        to: *member,
                        amount: *value,
                    }
                    .abi_encode(),
                };
                Call {
                    to: TxKind::Call(PATH_USD_ADDRESS),
                    value: U256::ZERO,
                    input: input.into(),
                }
            })
            .collect();
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        let nonce = zone
            .get_transaction_count(owner.address())
            .pending()
            .await?;
        let Some((hash, block, status)) = self
            .send_calls(&zone, owner, gas_price, calls, nonce)
            .await?
        else {
            return Ok(None);
        };
        if !status {
            println!("collide: {hash} reverted");
            return Ok(None);
        }
        if kind == CollisionKind::Balance {
            for (member, value) in &writes {
                self.ledger.append(&Record::Transfer {
                    zone_tx: hash,
                    zone_block: block,
                    from: owner.address(),
                    to: *member,
                    amount: (*value).try_into()?,
                })?;
            }
        }
        // Sends an earlier command gave up on can still land later in the same block and
        // overwrite these keys: then the block's end state is theirs.
        let nonce_after = zone
            .get_transaction_count(owner.address())
            .block_id(BlockId::number(block))
            .await?;
        if nonce_after > nonce + 1 {
            return Ok(Some((block, None)));
        }
        // Transfers add up, so for a balance group one the owner gave up on that landed earlier
        // in the same block also counts between the two reads: then skip the check too.
        if kind == CollisionKind::Balance {
            let nonce_before = zone
                .get_transaction_count(owner.address())
                .block_id(BlockId::number(block.saturating_sub(1)))
                .await?;
            if nonce_before < nonce {
                return Ok(Some((block, None)));
            }
        }
        let read_at = async |member: Address, height: u64| -> eyre::Result<U256> {
            let at = BlockId::number(height);
            Ok(match kind {
                CollisionKind::Allowance => {
                    token
                        .allowance(owner.address(), member)
                        .block(at)
                        .call()
                        .await?
                }
                CollisionKind::Balance => {
                    token
                        .balanceOf(member)
                        .from(member)
                        .block(at)
                        .call()
                        .await?
                }
            })
        };
        for (member, value) in &writes {
            let read = read_at(*member, block).await?;
            let expected = match kind {
                CollisionKind::Allowance => *value,
                CollisionKind::Balance => read_at(*member, block.saturating_sub(1)).await? + *value,
            };
            assert_always!(
                read == expected,
                "Colliding storage key reads back the value just written",
                &json!({
                    "kind": kind,
                    "owner": owner.address(),
                    "member": member,
                    "expected": expected,
                    "read": read,
                    "block": block,
                })
            );
        }
        // Embedding depends on the keys still present after the block, cleared ones gone and
        // members this transaction left alone included.
        let mut present = Vec::new();
        let mut values = Vec::new();
        for member in group {
            let value = read_at(*member, block).await?;
            if !value.is_zero() {
                present.push(*member);
                values.push(value);
            }
        }
        let base = kind.base(owner.address());
        for (member, value) in present.iter().zip(&values) {
            if !writes.iter().any(|(written, _)| written == member) {
                continue;
            }
            assert_sometimes!(
                embedded(leaf_depth(base, *member, &present), *value),
                "A colliding leaf is small enough to embed in its branch",
                &json!({ "kind": kind, "member": member, "value": value, "block": block })
            );
        }
        let mut cleared = 0;
        for (member, value) in &writes {
            if value.is_zero() && !read_at(*member, block.saturating_sub(1)).await?.is_zero() {
                cleared += 1;
            }
        }
        Ok(Some((block, Some((cleared, present.len())))))
    }
}

/// A random nonzero value of random byte width, so leaves span every encoding size: half the
/// time up to 4 bytes, as most real amounts are, otherwise up to 32. Balance values are capped so
/// `count` of them fit in a quarter of `balance`.
fn random_value(kind: CollisionKind, balance: u128, count: usize) -> U256 {
    let max_width = if random_below(2) == 0 { 4 } else { 32 };
    let width = random_between(1, max_width) as usize;
    let mut bytes = [0u8; 32];
    for chunk in bytes[32 - width..].chunks_mut(8) {
        let random = get_random().to_be_bytes();
        chunk.copy_from_slice(&random[..chunk.len()]);
    }
    let value = U256::from_be_bytes(bytes).max(U256::from(1));
    match kind {
        CollisionKind::Allowance => value,
        CollisionKind::Balance => {
            let cap = U256::from((balance / 4 / count.max(1) as u128).max(1));
            if value > cap {
                value % cap + U256::from(1)
            } else {
                value
            }
        }
    }
}

/// Whether a storage leaf holding `value` below a branch at `depth` nibbles encodes in under
/// 32 bytes, so its parent embeds it instead of referencing its hash.
fn embedded(depth: u64, value: U256) -> bool {
    let path = Nibbles::unpack(B256::ZERO).slice(depth as usize + 1..);
    alloy_rlp::encode(LeafNode::new(path, alloy_rlp::encode(value))).len() < 32
}

/// The depth of the branch above `member`'s leaf among `members`: the most nibbles it shares
/// with any of them.
fn leaf_depth(base: U256, member: Address, members: &[Address]) -> u64 {
    let key = trie_key(base, member);
    members
        .iter()
        .filter(|other| **other != member)
        .map(|other| shared_nibbles(key, trie_key(base, *other)))
        .max()
        .unwrap_or(0)
}

/// The most nibbles any two of `members` share.
fn deepest_shared(base: U256, members: &[Address]) -> u64 {
    members
        .iter()
        .map(|member| leaf_depth(base, *member, members))
        .max()
        .unwrap_or(0)
}

fn shared_nibbles(a: B256, b: B256) -> u64 {
    let mut shared = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        if x == y {
            shared += 2;
        } else {
            if x >> 4 == y >> 4 {
                shared += 1;
            }
            break;
        }
    }
    shared
}

/// The first `depth` nibbles of `key`, as an integer.
fn prefix(key: B256, depth: u64) -> u64 {
    u64::from_be_bytes(key[..8].try_into().expect("8 bytes")) >> (64 - 4 * depth)
}

/// The address of candidate `counter` of a search tagged `tag` from `seed`. Nobody holds its key.
fn candidate(tag: &[u8; 4], seed: u64, counter: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(tag);
    bytes[4..12].copy_from_slice(&seed.to_be_bytes());
    bytes[12..].copy_from_slice(&counter.to_be_bytes());
    Address::from(bytes)
}

/// Two members, derived from `seed`, whose keys under `base` share at least the first `depth`
/// nibbles. A birthday search: about 16^(depth/2) candidates.
fn colliding_pair(base: U256, seed: u64, depth: u64) -> (Address, Address) {
    assert!((1..=16).contains(&depth));
    let mut seen: HashMap<u64, Address> = HashMap::new();
    for counter in 0.. {
        let member = candidate(b"coll", seed, counter);
        match seen.entry(prefix(trie_key(base, member), depth)) {
            Entry::Occupied(entry) => return (*entry.get(), member),
            Entry::Vacant(entry) => {
                entry.insert(member);
            }
        }
    }
    unreachable!("the search runs until it finds a pair")
}

/// A member, derived from `seed`, whose key under `base` shares at least the first `depth`
/// nibbles of `key`. A targeted search: about 16^depth candidates.
fn neighbor(base: U256, seed: u64, key: B256, depth: u64) -> Address {
    assert!((1..=MAX_NEIGHBOR_DEPTH).contains(&depth));
    let target = prefix(key, depth);
    (0..)
        .map(|counter| candidate(b"nbor", seed, counter))
        .find(|member| prefix(trie_key(base, *member), depth) == target)
        .expect("the search runs until it finds a neighbor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ground_pairs_share_the_prefix() {
        let owner = Address::repeat_byte(0xab);
        for kind in [CollisionKind::Allowance, CollisionKind::Balance] {
            let base = kind.base(owner);
            for depth in [1, 4, 8] {
                let (a, b) = colliding_pair(base, 7, depth);
                assert_ne!(a, b);
                let shared = shared_nibbles(trie_key(base, a), trie_key(base, b));
                assert!(shared >= depth, "{kind:?} depth {depth}: shared {shared}");
            }
        }
    }

    #[test]
    fn neighbors_share_the_prefix() {
        let base = CollisionKind::Balance.base(Address::ZERO);
        let key = trie_key(base, Address::repeat_byte(1));
        for depth in 1..=4 {
            let member = neighbor(base, 3, key, depth);
            assert!(shared_nibbles(key, trie_key(base, member)) >= depth);
        }
    }

    #[test]
    fn slots_match_the_trie_keys() {
        let owner = Address::repeat_byte(0xab);
        let member = Address::repeat_byte(0xcd);
        for kind in [CollisionKind::Allowance, CollisionKind::Balance] {
            assert_eq!(
                keccak256(collision_slot(kind, owner, member)),
                trie_key(kind.base(owner), member)
            );
        }
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
    fn values_span_widths_and_respect_the_cap() {
        let balance = 1_000_000u128;
        for _ in 0..1000 {
            let value = random_value(CollisionKind::Balance, balance, 4);
            assert!(!value.is_zero() && value <= U256::from(balance / 16));
            assert!(!random_value(CollisionKind::Allowance, balance, 4).is_zero());
        }
    }
}
