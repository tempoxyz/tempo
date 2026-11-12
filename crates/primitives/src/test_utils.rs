//! Seeded random fixtures for tests.
//!
//! Each test thread draws from its own RNG, seeded from `TEMPO_TEST_SEED` when set and randomly
//! otherwise. A panic on a thread that used it prints the seed, so the failure can be replayed.

use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use core::cell::RefCell;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::sync::Once;

std::thread_local! {
    static RNG: RefCell<Option<(u64, StdRng)>> = const { RefCell::new(None) };
}

/// Runs `f` with this thread's test RNG, seeding it on first use.
fn with_rng<T>(f: impl FnOnce(&mut StdRng) -> T) -> T {
    static PRINT_SEED_ON_PANIC: Once = Once::new();
    PRINT_SEED_ON_PANIC.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // `try_borrow` because the panic may come from inside `with_rng`.
            let seed = RNG.try_with(|rng| Some(rng.try_borrow().ok()?.as_ref()?.0));
            if let Ok(Some(seed)) = seed {
                std::eprintln!("replay with TEMPO_TEST_SEED={seed}");
            }
            previous(info);
        }));
    });
    RNG.with_borrow_mut(|rng| {
        let (_, rng) = rng.get_or_insert_with(|| {
            let seed = std::env::var("TEMPO_TEST_SEED").map_or_else(
                |_| rand::random(),
                |seed| seed.parse().expect("TEMPO_TEST_SEED must be a u64"),
            );
            (seed, StdRng::seed_from_u64(seed))
        });
        f(rng)
    })
}

/// Returns `N` random addresses from the test RNG.
pub fn actors<const N: usize>() -> [Address; N] {
    actors_vec(N).try_into().unwrap()
}

/// Returns `n` random addresses from the test RNG.
pub fn actors_vec(n: usize) -> Vec<Address> {
    with_rng(|rng| {
        (0..n)
            .map(|_| Address::from(rng.random::<[u8; 20]>()))
            .collect()
    })
}

/// Returns `N` random amounts, each at least 1, sorted largest first, whose total stays below
/// `u128::MAX` (the TIP-20 supply cap).
pub fn amounts<const N: usize>() -> [U256; N] {
    amounts_vec(N).try_into().unwrap()
}

/// Returns `n` random amounts with the same guarantees as [`amounts`].
pub fn amounts_vec(n: usize) -> Vec<U256> {
    let mut amounts: Vec<_> = with_rng(|rng| {
        (0..n)
            .map(|_| U256::from(rng.random_range(1..u128::MAX / n as u128)))
            .collect()
    });
    amounts.sort_unstable_by(|a, b| b.cmp(a));
    amounts
}
