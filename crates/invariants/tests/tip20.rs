//! TIP20 invariant behaviour tests (mirrors `src/tip20/`).
//!
//! Uses the canonical `HashMapStorageProvider` (no bespoke mock). Violating
//! states are injected at the **authoritative** `tempo_precompiles::tip20::slots::*`
//! constants — reusing the layout source of truth rather than redefining it.
//! One test per invariant, covering all combinations.

use alloy_primitives::{U256, address};
use tempo_invariants::{RunEntities, run};
use tempo_precompiles::{
    storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider},
    tip20::slots,
};

#[test]
fn supply_cap() {
    // Seed a token's supply slots and report whether the cap check fired. The
    // address carries the `0x20C0` TIP-20 prefix, required because the runner
    // builds tokens via `from_address_unchecked` (asserts `is_tip20()` in debug).
    let fires = |total_supply: u64, supply_cap: u64| {
        let t = address!("0x20C0000000000000000000000000000000000001");
        let mut p = HashMapStorageProvider::new(1);
        p.sstore(t, slots::TOTAL_SUPPLY, U256::from(total_supply))
            .unwrap();
        p.sstore(t, slots::SUPPLY_CAP, U256::from(supply_cap))
            .unwrap();
        run(
            &mut p,
            &RunEntities {
                tip20_tokens: &[t],
                ..Default::default()
            },
        )
        .failures
        .iter()
        .any(|f| f.id == "TEMPO-TIP20-SUPPLY-CAP")
    };

    assert!(fires(3_000, 2_000)); // over cap -> fires
    assert!(!fires(1_000, 2_000)); // under cap -> ok
    assert!(!fires(2_000, 2_000)); // exactly at cap -> ok
    assert!(!fires(9_999, 0)); // no cap set -> ignored
}

#[test]
fn optin_supply() {
    let fires = |total_supply: u64, opted_in: u64| {
        let t = address!("0x20C0000000000000000000000000000000000001");
        let mut p = HashMapStorageProvider::new(1);
        p.sstore(t, slots::TOTAL_SUPPLY, U256::from(total_supply))
            .unwrap();
        p.sstore(t, slots::OPTED_IN_SUPPLY, U256::from(opted_in))
            .unwrap();
        run(
            &mut p,
            &RunEntities {
                tip20_tokens: &[t],
                ..Default::default()
            },
        )
        .failures
        .iter()
        .any(|f| f.id == "TEMPO-TIP20-OPTIN-SUPPLY")
    };

    assert!(fires(1_000, 1_500)); // opted-in over total -> fires
    assert!(!fires(1_000, 800)); // opted-in under total -> ok
    assert!(!fires(1_000, 1_000)); // opted-in equals total -> ok
    assert!(!fires(1_000, 0)); // none opted in -> ok
}
