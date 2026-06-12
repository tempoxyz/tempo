//! Channel-reserve invariant behaviour tests (mirrors `src/reserve/`).
//!
//! The reserve's token balance is seeded at the authoritative balances-mapping
//! slot (`slots::BALANCES` + canonical key derivation, no redefined layout); the
//! open-channel set is supplied via the view — the data the enumeration tier
//! provides and that can't come from the token alone. One test, all combinations.

use alloy_primitives::{U256, address, aliases::U96};
use tempo_invariants::{
    RunEntities,
    reserve::{ChannelState, ReserveView},
    run,
};
use tempo_precompiles::{
    storage::{PrecompileStorageProvider, StorageKey, hashmap::HashMapStorageProvider},
    tip20::slots,
    tip20_channel_reserve::TIP20_CHANNEL_RESERVE_ADDRESS,
};

#[test]
fn channel_solvency() {
    let token = address!("0x20C0000000000000000000000000000000000001");

    // held = token balance held by the reserve precompile;
    // channels = (deposit, settled) per open channel.
    let fires = |held: u128, channels: &[(u128, u128)]| {
        let mut p = HashMapStorageProvider::new(1);
        let balance_slot = TIP20_CHANNEL_RESERVE_ADDRESS.mapping_slot(slots::BALANCES);
        p.sstore(token, balance_slot, U256::from(held)).unwrap();

        let view = ReserveView {
            token,
            channels: channels
                .iter()
                .map(|&(deposit, settled)| ChannelState {
                    deposit: U96::from(deposit),
                    settled: U96::from(settled),
                    closeRequestedAt: 0,
                })
                .collect(),
        };
        run(
            &mut p,
            &RunEntities {
                reserves: &[view],
                ..Default::default()
            },
        )
        .failures
        .iter()
        .any(|f| f.id == "TEMPO-RESERVE-CHANNEL-SOLVENCY")
    };

    // owed = Σ(deposit − settled)
    assert!(fires(100, &[(80, 0), (50, 0)])); // owes 130 > holds 100 -> fires
    assert!(!fires(130, &[(80, 0), (50, 0)])); // owes 130 == holds 130 -> ok
    assert!(!fires(200, &[(80, 0), (50, 0)])); // holds 200 > owes 130 -> ok
    assert!(!fires(10, &[(80, 80), (50, 50)])); // fully settled, owes 0 -> ok
    assert!(!fires(0, &[])); // no channels -> ok
}
