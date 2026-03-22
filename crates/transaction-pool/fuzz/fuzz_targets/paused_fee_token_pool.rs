#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

use alloy_primitives::Address;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin};
use tempo_transaction_pool::{
    paused::{PausedEntry, PausedFeeTokenPool, PAUSED_POOL_GLOBAL_CAP},
    test_utils::{TxBuilder, wrap_valid_tx},
};

const NUM_TOKENS: u8 = 4;
const MAX_BATCH: u8 = 20;

#[derive(Debug, Arbitrary)]
enum PausedOp {
    InsertBatch {
        token_idx: u8,
        count: u8,
        valid_before_base: Option<u16>,
        sender_seed: u8,
    },
    DrainToken {
        token_idx: u8,
    },
    EvictExpired {
        tip_timestamp: u16,
    },
    CheckContains {
        tx_slot: u8,
    },
    CountForToken {
        token_idx: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct PausedInput {
    ops: Vec<PausedOp>,
}

fuzz_target!(|input: PausedInput| {
    if input.ops.is_empty() || input.ops.len() > 200 {
        return;
    }

    let tokens: Vec<Address> = (0..NUM_TOKENS)
        .map(|i| Address::with_last_byte(i + 1))
        .collect();

    let mut pool = PausedFeeTokenPool::new();
    let mut all_hashes = Vec::new();

    for op in &input.ops {
        match op {
            PausedOp::InsertBatch {
                token_idx,
                count,
                valid_before_base,
                sender_seed,
            } => {
                let tidx = *token_idx % NUM_TOKENS;
                let token = tokens[tidx as usize];
                let n = ((*count % MAX_BATCH) as usize).max(1);

                let entries: Vec<PausedEntry> = (0..n)
                    .map(|i| {
                        let sender = Address::with_last_byte(sender_seed.wrapping_add(i as u8));
                        let tx = TxBuilder::aa(sender).build();
                        let hash = *tx.hash();
                        all_hashes.push(hash);
                        let valid = Arc::new(wrap_valid_tx(tx, TransactionOrigin::External));
                        PausedEntry {
                            tx: valid,
                            valid_before: valid_before_base.map(|b| b as u64 + i as u64),
                        }
                    })
                    .collect();

                pool.insert_batch(token, entries);
            }
            PausedOp::DrainToken { token_idx } => {
                let tidx = *token_idx % NUM_TOKENS;
                let token = tokens[tidx as usize];
                let _drained = pool.drain_token(&token);
                assert_eq!(
                    pool.count_for_token(&token),
                    0,
                    "Token count should be 0 after drain"
                );
            }
            PausedOp::EvictExpired { tip_timestamp } => {
                let before = pool.len();
                let evicted = pool.evict_expired(*tip_timestamp as u64);
                let after = pool.len();
                assert_eq!(
                    before - evicted,
                    after,
                    "Eviction count mismatch: {} - {} != {}",
                    before,
                    evicted,
                    after
                );
            }
            PausedOp::CheckContains { tx_slot } => {
                if !all_hashes.is_empty() {
                    let idx = (*tx_slot as usize) % all_hashes.len();
                    let _ = pool.contains(&all_hashes[idx]);
                }
            }
            PausedOp::CountForToken { token_idx } => {
                let tidx = *token_idx % NUM_TOKENS;
                let token = tokens[tidx as usize];
                let count = pool.count_for_token(&token);
                assert!(count <= pool.len());
            }
        }

        // Global invariants after every op
        assert!(
            pool.len() <= PAUSED_POOL_GLOBAL_CAP,
            "Pool size {} exceeds global cap {}",
            pool.len(),
            PAUSED_POOL_GLOBAL_CAP
        );
    }

    // Final: sum of per-token counts should equal total len
    let sum: usize = tokens.iter().map(|t| pool.count_for_token(t)).sum();
    assert_eq!(
        sum,
        pool.len(),
        "Per-token sum {} != total len {}",
        sum,
        pool.len()
    );
});
