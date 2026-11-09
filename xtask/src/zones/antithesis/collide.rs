//! `collide`: allowances whose storage-trie keys share a long prefix.
//!
//! Uniformly random keys keep a storage trie shallow and bushy: among 10,000 keys, two share eight
//! leading nibbles in about one run in a hundred, and their values are almost never small. This
//! driver grinds spender addresses until two allowance keys of one owner share a random number of
//! leading nibbles, so pathUSD's storage trie also gets deep, narrow branches and extensions, and,
//! from eight shared nibbles with small values, leaves short enough to be embedded in their parent
//! branch instead of hashed. Later runs revisit recorded pairs, updating and clearing them after
//! they may have settled, so blocks and batch proofs have to read, rewrite and collapse those
//! shapes.

use alloy::primitives::{Address, B256, TxKind, U256, keccak256};
use antithesis_sdk::{assert_always, assert_sometimes, random::get_random};
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

/// Deepest shared prefix, in nibbles, the driver grinds for. Finding a pair takes about
/// 16^(depth/2) candidates, about a million at 10.
const MAX_DEPTH: u64 = 10;
/// From this many shared nibbles, a leaf holding a value under 0x80 is embedded in its parent.
const INLINE_DEPTH: u64 = 8;
/// Largest allowance that still encodes as a single RLP byte, keeping a deep leaf embedded.
const SMALL_AMOUNT: u128 = 0x7f;
/// Recorded pairs a revisit considers before grinding a new one instead.
const REVISIT_CANDIDATES: usize = 16;

/// What one spender of a pair is set to.
#[derive(Debug, Clone, Copy)]
enum Write {
    Small,
    Large,
    Clear,
}

impl Write {
    fn random() -> Self {
        match random_below(4) {
            0 | 1 => Self::Small,
            2 => Self::Large,
            _ => Self::Clear,
        }
    }

    fn amount(self) -> U256 {
        match self {
            Self::Small => U256::from(random_between(1, SMALL_AMOUNT)),
            Self::Large => U256::from(random_between(SMALL_AMOUNT + 1, u128::from(u64::MAX))),
            Self::Clear => U256::ZERO,
        }
    }
}

impl Context {
    /// Half the time revisits a recorded pair of colliding allowances, otherwise grinds and sets
    /// a new pair for a leased owner.
    pub(super) async fn collide(&self) -> eyre::Result<()> {
        if random_below(2) == 0 && self.revisit_collision().await? {
            return Ok(());
        }
        let node = super::random_index(self.zones.len());
        let Some((owner, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        let depth = random_below(MAX_DEPTH) + 1;
        let (first, second) = colliding_spenders(owner.address(), get_random(), depth);
        let shared = shared_nibbles(
            allowance_trie_key(owner.address(), first),
            allowance_trie_key(owner.address(), second),
        );
        // Small amounts most of the time, so pairs at or past the inline depth stay embedded.
        let writes = [
            (
                first,
                if random_below(4) == 0 {
                    Write::Large
                } else {
                    Write::Small
                },
            ),
            (
                second,
                if random_below(4) == 0 {
                    Write::Large
                } else {
                    Write::Small
                },
            ),
        ];
        let Some(block) = self
            .write_allowances(node, &owner, balance, &writes)
            .await?
        else {
            return Ok(());
        };
        self.ledger.append(&Record::Collision {
            owner: owner.address(),
            spenders: vec![first, second],
            depth: shared,
            zone_block: block,
        })?;
        assert_sometimes!(
            shared >= INLINE_DEPTH,
            "Colliding allowance keys share at least 8 trie nibbles",
            &json!({ "owner": owner.address(), "shared": shared, "block": block })
        );
        println!(
            "collide: allowances of {} to {first} and {second} share {shared} nibbles, block {block}",
            owner.address()
        );
        Ok(())
    }

    /// Updates or clears one or both allowances of a recorded pair whose owner is free and
    /// funded. Returns whether it found such a pair.
    async fn revisit_collision(&self) -> eyre::Result<bool> {
        let pairs: Vec<(Address, Vec<Address>, u64, u64)> = self
            .ledger
            .records()?
            .into_iter()
            .filter_map(|record| match record {
                Record::Collision {
                    owner,
                    spenders,
                    depth,
                    zone_block,
                } => Some((owner, spenders, depth, zone_block)),
                _ => None,
            })
            .collect();
        let accounts = self.ledger.sender_accounts()?;
        for (owner, spenders, depth, zone_block) in
            shuffled(pairs).into_iter().take(REVISIT_CANDIDATES)
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
            // One spender alone half the time, so a clear can collapse the branch onto its
            // remaining sibling.
            let writes: Vec<(Address, Write)> = if random_below(2) == 0 {
                random_choice(spenders.clone())
                    .map(|spender| vec![(spender, Write::random())])
                    .unwrap_or_default()
            } else {
                spenders
                    .iter()
                    .map(|spender| (*spender, Write::random()))
                    .collect()
            };
            let settled = match self.settled_block().await {
                Ok((height, _)) => height >= zone_block,
                Err(_) => false,
            };
            let Some(block) = self
                .write_allowances(node, account, balance, &writes)
                .await?
            else {
                return Ok(true);
            };
            assert_sometimes!(
                settled && depth >= INLINE_DEPTH,
                "Deep colliding allowance is rewritten after it settled",
                &json!({ "owner": owner, "shared": depth, "set_in": zone_block, "block": block })
            );
            println!(
                "collide: revisited {} allowances of {owner} sharing {depth} nibbles (settled: {settled}), block {block}",
                writes.len()
            );
            drop(lease);
            return Ok(true);
        }
        Ok(false)
    }

    /// Sends `writes` as the calls of one Tempo transaction from `owner` and checks every
    /// allowance reads back at the block it landed in. Returns that block, or `None` when the
    /// transaction did not fit half the balance, reverted or was not confirmed.
    async fn write_allowances(
        &self,
        node: usize,
        owner: &super::Account,
        balance: u128,
        writes: &[(Address, Write)],
    ) -> eyre::Result<Option<u64>> {
        if writes.is_empty() {
            return Ok(None);
        }
        let zone = self.wallet(owner, &self.zone_urls[node]);
        let gas_price = zone.get_gas_price().await?;
        let gas_limit = BATCH_BASE_GAS + BATCH_CALL_GAS * writes.len() as u64;
        if calc_gas_balance_spending(gas_limit, gas_price) > U256::from(balance / 2) {
            return Ok(None);
        }
        let amounts: Vec<(Address, U256)> = writes
            .iter()
            .map(|(spender, write)| (*spender, write.amount()))
            .collect();
        let calls = amounts
            .iter()
            .map(|(spender, amount)| Call {
                to: TxKind::Call(PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: ITIP20::approveCall {
                    spender: *spender,
                    amount: *amount,
                }
                .abi_encode()
                .into(),
            })
            .collect();
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
        // Sends an earlier command gave up on can still land later in the same block and
        // overwrite these allowances: then the block's end state is theirs.
        let nonce_after = zone
            .get_transaction_count(owner.address())
            .block_id(BlockId::number(block))
            .await?;
        if nonce_after > nonce + 1 {
            return Ok(Some(block));
        }
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        for (spender, amount) in &amounts {
            let read = token
                .allowance(owner.address(), *spender)
                .block(BlockId::number(block))
                .call()
                .await?;
            assert_always!(
                read == *amount,
                "Colliding allowance reads back the amount just set",
                &json!({
                    "owner": owner.address(),
                    "spender": spender,
                    "approved": amount,
                    "read": read,
                    "block": block,
                })
            );
        }
        Ok(Some(block))
    }
}

/// The storage slot of `owner`'s allowance to `spender`.
pub(super) fn allowance_slot(owner: Address, spender: Address) -> B256 {
    B256::from(spender.mapping_slot(owner.mapping_slot(slots::ALLOWANCES)))
}

/// Where the allowance sits in pathUSD's storage trie: the hash of its slot.
fn allowance_trie_key(owner: Address, spender: Address) -> B256 {
    keccak256(allowance_slot(owner, spender))
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

/// Two spenders, derived from `seed` and no key, whose allowance keys under `owner` share at
/// least the first `depth` nibbles. A birthday search: about 16^(depth/2) candidates.
fn colliding_spenders(owner: Address, seed: u64, depth: u64) -> (Address, Address) {
    assert!((1..=16).contains(&depth));
    let base = owner.mapping_slot(slots::ALLOWANCES);
    let mut seen: HashMap<u64, Address> = HashMap::new();
    let mut counter = 0u64;
    loop {
        let mut bytes = [0u8; 20];
        bytes[..4].copy_from_slice(b"coll");
        bytes[4..12].copy_from_slice(&seed.to_be_bytes());
        bytes[12..].copy_from_slice(&counter.to_be_bytes());
        let spender = Address::from(bytes);
        let key = keccak256(spender.mapping_slot(base).to_be_bytes::<32>());
        let prefix = u64::from_be_bytes(key[..8].try_into().expect("8 bytes")) >> (64 - 4 * depth);
        match seen.entry(prefix) {
            Entry::Occupied(entry) => return (*entry.get(), spender),
            Entry::Vacant(entry) => {
                entry.insert(spender);
            }
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{Nibbles, nodes::LeafNode};

    #[test]
    fn ground_spenders_share_the_prefix() {
        let owner = Address::repeat_byte(0xab);
        for depth in [1, 4, 8] {
            let (a, b) = colliding_spenders(owner, 7, depth);
            assert_ne!(a, b);
            let shared = shared_nibbles(allowance_trie_key(owner, a), allowance_trie_key(owner, b));
            assert!(shared >= depth, "depth {depth}: shared {shared}");
        }
    }

    #[test]
    fn deep_small_leaves_are_embedded() {
        // A leaf below a branch at the inline depth keeps 64 - 8 - 1 nibbles of path.
        let key = Nibbles::unpack(B256::repeat_byte(0x11));
        let leaf = |depth: usize, amount: U256| {
            alloy_rlp::encode(LeafNode::new(
                key.slice(depth + 1..),
                alloy_rlp::encode(amount),
            ))
            .len()
        };
        let small = U256::from(SMALL_AMOUNT);
        assert!(leaf(INLINE_DEPTH as usize, small) < 32);
        assert!(leaf(INLINE_DEPTH as usize - 1, small) >= 32);
        assert!(leaf(INLINE_DEPTH as usize, U256::from(SMALL_AMOUNT + 1)) >= 32);
    }
}
