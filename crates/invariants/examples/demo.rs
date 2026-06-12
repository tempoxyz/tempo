//! End-to-end demo.
//!
//! Run with:  `cargo run -p tempo-invariants --example demo`
//!
//! Walks the two entrypoints a caller uses: `registry()` for the catalog of
//! registered checks, and `run()` to evaluate them over a set of entities —
//! TIP20 tokens read through the real `TIP20Token` accessors, a block off
//! `BlockView`, and a channel-reserve view with externally enumerated channels.

use alloy_primitives::{U256, address, aliases::U96};
use tempo_invariants::{
    RunEntities,
    block::BlockView,
    registry,
    reserve::{ChannelState, ReserveView},
    run,
};
use tempo_precompiles::{
    storage::{PrecompileStorageProvider, StorageKey, hashmap::HashMapStorageProvider},
    tip20::slots,
    tip20_channel_reserve::TIP20_CHANNEL_RESERVE_ADDRESS,
};

fn main() {
    // 1. The catalog is whatever has registered itself via `invariant!`.
    println!("== registered invariants ({}) ==", registry().len());
    for m in registry() {
        println!(
            "  {:<26} {:?}  {:?}  {}",
            m.id, m.scope, m.severity, m.description
        );
    }

    // 2. Synthetic state, written at the authoritative tip20::slots constants.
    let healthy = address!("0x20C0000000000000000000000000000000000011");
    let over_cap = address!("0x20C0000000000000000000000000000000000022");
    let over_optin = address!("0x20C0000000000000000000000000000000000033");

    let mut p = HashMapStorageProvider::new(1);
    p.sstore(healthy, slots::TOTAL_SUPPLY, U256::from(1_000))
        .unwrap();
    p.sstore(healthy, slots::SUPPLY_CAP, U256::from(2_000))
        .unwrap();
    p.sstore(healthy, slots::OPTED_IN_SUPPLY, U256::from(500))
        .unwrap();
    p.sstore(over_cap, slots::TOTAL_SUPPLY, U256::from(3_000))
        .unwrap();
    p.sstore(over_cap, slots::SUPPLY_CAP, U256::from(2_000))
        .unwrap();
    p.sstore(over_optin, slots::TOTAL_SUPPLY, U256::from(1_000))
        .unwrap();
    p.sstore(over_optin, slots::OPTED_IN_SUPPLY, U256::from(1_500))
        .unwrap();

    // A block that overshoots its gas limit (block scope).
    let block = BlockView {
        number: 42,
        gas_used: 31_000_000,
        gas_limit: 30_000_000,
    };

    // A reserve view (reserve scope): the reserve holds only 100 of `healthy` but
    // two enumerated channels owe 80 + 50 = 130 -> insolvent. The balance is
    // seeded at the authoritative balances-mapping slot for the reserve address.
    let reserve_balance_slot = TIP20_CHANNEL_RESERVE_ADDRESS.mapping_slot(slots::BALANCES);
    p.sstore(healthy, reserve_balance_slot, U256::from(100))
        .unwrap();
    let reserve = ReserveView {
        token: healthy,
        channels: vec![
            ChannelState {
                deposit: U96::from(80),
                settled: U96::ZERO,
                closeRequestedAt: 0,
            },
            ChannelState {
                deposit: U96::from(50),
                settled: U96::ZERO,
                closeRequestedAt: 0,
            },
        ],
    };

    let tokens = [healthy, over_cap, over_optin];
    let reserves = [reserve];
    let entities = RunEntities {
        tip20_tokens: &tokens,
        block: Some(&block),
        reserves: &reserves,
    };

    // 3. Run every registered check over the entities. A new `invariant!` block
    //    shows up here automatically — no edit to this file.
    let out = run(&mut p, &entities);

    println!("\n== violations ({}) ==", out.failures.len());
    for f in &out.failures {
        println!("  [{}] {:?} {}", f.id, f.entity, f.detail);
    }
    if !out.errors.is_empty() {
        println!("\n== skipped entities ({}) ==", out.errors.len());
        for e in &out.errors {
            println!("  [{:?}] {:?} {}", e.scope, e.entity, e.message);
        }
    }
}
