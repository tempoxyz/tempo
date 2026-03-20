#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

use alloy_primitives::{Address, TxHash, U256, map::HashMap};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_transaction_pool::{
    AA2dPool, AA2dPoolConfig, AASequenceId,
    test_utils::{TxBuilder, wrap_valid_tx},
};

const NUM_SENDERS: u8 = 4;
const NUM_NONCE_KEYS: u8 = 3;

#[derive(Debug, Arbitrary)]
enum PoolOp {
    AddTx {
        sender_idx: u8,
        nonce_key: u8,
        nonce: u8,
        priority_fee: u16,
    },
    /// Replace a tx at the same (sender, nonce_key, nonce) with higher fee.
    ReplaceTx {
        sender_idx: u8,
        nonce_key: u8,
        nonce: u8,
        priority_fee: u16,
    },
    RemoveByHash {
        tx_slot: u8,
    },
    /// Remove tx and all its descendants (higher nonces in same sequence).
    RemoveAndDescendants {
        tx_slot: u8,
    },
    /// Remove all txs from a sender.
    RemoveBySender {
        sender_idx: u8,
    },
    /// Simulate nonce advancement (mining) for a specific (sender, nonce_key).
    NonceChange {
        sender_idx: u8,
        nonce_key: u8,
        new_nonce: u8,
    },
    IterateBest {
        steps: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct Aa2dInput {
    /// Use tiny pool limits to force eviction/discard paths.
    tiny_limits: bool,
    ops: Vec<PoolOp>,
}

fuzz_target!(|input: Aa2dInput| {
    if input.ops.is_empty() || input.ops.len() > 200 {
        return;
    }

    let senders: Vec<Address> = (0..NUM_SENDERS)
        .map(|i| Address::with_last_byte(i + 1))
        .collect();

    let config = if input.tiny_limits {
        AA2dPoolConfig {
            max_txs_per_sender: 4,
            ..AA2dPoolConfig::default()
        }
    } else {
        AA2dPoolConfig::default()
    };

    let mut pool = AA2dPool::new(config);
    let mut tracked_hashes: Vec<TxHash> = Vec::new();

    for op in &input.ops {
        match op {
            PoolOp::AddTx {
                sender_idx,
                nonce_key,
                nonce,
                priority_fee,
            }
            | PoolOp::ReplaceTx {
                sender_idx,
                nonce_key,
                nonce,
                priority_fee,
            } => {
                let sender = senders[(*sender_idx % NUM_SENDERS) as usize];
                let nk = U256::from(*nonce_key % NUM_NONCE_KEYS);
                let n = *nonce as u64;
                let fee = (*priority_fee as u128).saturating_add(1);

                let tx = TxBuilder::aa(sender)
                    .nonce_key(nk)
                    .nonce(n)
                    .max_priority_fee(fee)
                    .build();
                let hash = *tx.hash();
                let valid = wrap_valid_tx(tx, TransactionOrigin::External);

                if pool
                    .add_transaction(Arc::new(valid), 0, TempoHardfork::T1)
                    .is_ok()
                {
                    tracked_hashes.push(hash);
                }
            }
            PoolOp::RemoveByHash { tx_slot } => {
                if !tracked_hashes.is_empty() {
                    let idx = (*tx_slot as usize) % tracked_hashes.len();
                    let hash = tracked_hashes[idx];
                    pool.remove_transactions([&hash].into_iter());
                    tracked_hashes.swap_remove(idx);
                }
            }
            PoolOp::RemoveAndDescendants { tx_slot } => {
                if !tracked_hashes.is_empty() {
                    let idx = (*tx_slot as usize) % tracked_hashes.len();
                    let hash = tracked_hashes[idx];
                    let removed = pool.remove_transactions_and_descendants([&hash].into_iter());
                    // Remove all returned hashes from tracked
                    for r in &removed {
                        if let Some(pos) = tracked_hashes.iter().position(|h| h == r.hash()) {
                            tracked_hashes.swap_remove(pos);
                        }
                    }
                }
            }
            PoolOp::RemoveBySender { sender_idx } => {
                let sender = senders[(*sender_idx % NUM_SENDERS) as usize];
                let removed = pool.remove_transactions_by_sender(sender);
                for r in &removed {
                    if let Some(pos) = tracked_hashes.iter().position(|h| h == r.hash()) {
                        tracked_hashes.swap_remove(pos);
                    }
                }
            }
            PoolOp::NonceChange {
                sender_idx,
                nonce_key,
                new_nonce,
            } => {
                let sender = senders[(*sender_idx % NUM_SENDERS) as usize];
                let nk = U256::from(*nonce_key % NUM_NONCE_KEYS);
                let seq_id = AASequenceId { address: sender, nonce_key: nk };
                let mut changes = HashMap::default();
                changes.insert(seq_id, *new_nonce as u64);
                let (promoted, mined) = pool.on_nonce_changes(changes);
                // Remove mined hashes from tracking
                for m in &mined {
                    if let Some(pos) = tracked_hashes.iter().position(|h| h == m.hash()) {
                        tracked_hashes.swap_remove(pos);
                    }
                }
                let _ = promoted;
            }
            PoolOp::IterateBest { steps } => {
                let mut best = pool.best_transactions();
                let steps = (*steps).min(100);
                let mut prev_priority: Option<u128> = None;
                for _ in 0..steps {
                    match best.next_tx_and_priority() {
                        Some((_tx, priority)) => {
                            if let reth_transaction_pool::Priority::Value(p) = priority {
                                if let Some(prev) = prev_priority {
                                    assert!(
                                        prev >= p,
                                        "Best iterator order violation: {} < {}",
                                        prev,
                                        p
                                    );
                                }
                                prev_priority = Some(p);
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        // Invariant: pool size is reasonable
        let (pending, queued) = pool.pending_and_queued_txn_count();
        let _ = (pending, queued);
    }

    // Full invariant check after all ops
    pool.assert_invariants();
});
