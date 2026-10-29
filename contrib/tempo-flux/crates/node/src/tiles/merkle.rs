use alloy_primitives::{B256, U256, keccak256};
use alloy_trie::{EMPTY_ROOT_HASH, TrieAccount};
use flux::{
    spine::{DCacheRead, SpineAdapter},
    tile::Tile,
};
use rustc_hash::{FxHashMap, FxHashSet};
use tempo_flux_primitives::{Executed, StateDiff, diff};

use crate::{spine::NodeSpine, trie::Trie};

/// Owns the merkle view of state: applies each block's diff to incremental
/// account and storage tries and computes the state root.
pub struct MerkleTile {
    accounts: FxHashMap<B256, TrieAccount>,
    account_trie: Trie,
    storage: FxHashMap<B256, Trie>,
    rlp: Vec<u8>,
    /// Recompute the root from scratch every block and assert it matches.
    pub verify: bool,
}

impl MerkleTile {
    pub fn new(genesis: &StateDiff, payload: &[u8]) -> Self {
        let mut tile = Self {
            accounts: FxHashMap::default(),
            account_trie: Trie::default(),
            storage: FxHashMap::default(),
            rlp: Vec::new(),
            verify: false,
        };
        tile.apply(payload, genesis);
        tile
    }

    fn put(&mut self, key: B256, acc: TrieAccount) {
        self.rlp.clear();
        alloy_rlp::Encodable::encode(&acc, &mut self.rlp);
        self.account_trie.insert(key, self.rlp.clone());
        self.accounts.insert(key, acc);
    }

    fn full_root(&self) -> B256 {
        let mut leaves: Vec<_> = self.accounts.iter().collect();
        leaves.sort_unstable_by_key(|(k, _)| **k);
        let mut hb = alloy_trie::HashBuilder::default();
        let mut buf = Vec::new();
        for (k, acc) in leaves {
            buf.clear();
            alloy_rlp::Encodable::encode(acc, &mut buf);
            hb.add_leaf(alloy_trie::Nibbles::unpack(k), &buf);
        }
        hb.root()
    }

    fn apply(&mut self, payload: &[u8], d: &StateDiff) {
        let (accounts, slots) = diff::split(payload, d.accounts as usize);
        let mut touched = FxHashSet::default();
        for a in diff::accounts(accounts, d.accounts as usize) {
            let key = keccak256(a.address);
            touched.insert(key);
            if a.deleted {
                self.accounts.remove(&key);
                self.storage.remove(&key);
                continue;
            }
            let acc = self.accounts.entry(key).or_insert(TrieAccount {
                storage_root: EMPTY_ROOT_HASH,
                ..Default::default()
            });
            acc.nonce = a.nonce;
            acc.balance = U256::from_be_bytes(a.balance);
            acc.code_hash = B256::from(a.code_hash);
        }
        for s in diff::slots(slots, d.slots as usize) {
            let addr = keccak256(s.address);
            touched.insert(addr);
            let trie = self.storage.entry(addr).or_default();
            let key = keccak256(s.key);
            let value = U256::from_be_bytes(s.value);
            if value.is_zero() {
                trie.remove(key);
            } else {
                self.rlp.clear();
                alloy_rlp::Encodable::encode(&value, &mut self.rlp);
                trie.insert(key, self.rlp.clone());
            }
        }
        for key in touched {
            let Some(mut acc) = self.accounts.get(&key).cloned() else {
                self.account_trie.remove(key);
                continue;
            };
            if let Some(trie) = self.storage.get_mut(&key) {
                acc.storage_root = trie.root();
            }
            self.put(key, acc);
        }
    }
}

impl Tile<NodeSpine> for MerkleTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        let mut diffs = Vec::new();
        adapter.consume_with_dcache::<StateDiff, Vec<u8>, _, _>(
            |_, payload| payload.to_vec(),
            |res, _| match res {
                DCacheRead::Ok((d, p)) => diffs.push((d, p)),
                DCacheRead::NoRef(d) => diffs.push((d, Vec::new())),
                // Execution already applied this block and can't redo it, so
                // stop loudly instead of leaving consensus waiting forever.
                _ => panic!("merkle lost a state diff; the state root can no longer be computed"),
            },
        );
        for (d, payload) in diffs {
            let start = crate::now_ns();
            let state_root = if d.valid {
                self.apply(&payload, &d);
                let root = self.account_trie.root();
                if self.verify {
                    assert_eq!(
                        root,
                        self.full_root(),
                        "incremental root diverged at {}",
                        d.height
                    );
                }
                root.0
            } else {
                [0; 32]
            };
            tracing::info!(
                d.height,
                accounts = self.account_trie.len(),
                root = %B256::from(state_root),
                root_ms = format!("{:.2}", (crate::now_ns() - start) as f64 / 1e6),
                "state root"
            );
            adapter.produce(Executed {
                height: d.height,
                hash: d.hash,
                state_root,
                gas_used: d.gas_used,
                valid: d.valid,
            });
        }
    }
}
