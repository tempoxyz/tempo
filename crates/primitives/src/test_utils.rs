//! Seeded random fixtures for tests.
//!
//! Each test thread draws from its own RNG, seeded from `TEMPO_TEST_SEED` when set and randomly
//! otherwise. A panic on a thread that used it prints the seed, so the failure can be replayed.
//! The seed covers only values drawn through these fixtures, not `Address::random()` and the like.

use alloc::vec::Vec;
use alloy_primitives::{Address, B256, U256};
use alloy_signer_local::PrivateKeySigner;
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
    let mut amounts = with_rng(|rng| {
        core::array::from_fn(|_| U256::from(rng.random_range(1..u128::MAX / N as u128)))
    });
    amounts.sort_unstable_by(|a, b| b.cmp(a));
    amounts
}

/// Returns `N` random signers from the test RNG.
pub fn signers<const N: usize>() -> [PrivateKeySigner; N] {
    signers_vec(N).try_into().unwrap()
}

/// Returns `n` random signers from the test RNG.
pub fn signers_vec(n: usize) -> Vec<PrivateKeySigner> {
    with_rng(|rng| {
        (0..n)
            .map(|_| {
                // A random 32-byte scalar is zero or above the curve order with probability ~2^-128.
                PrivateKeySigner::from_bytes(&B256::from(rng.random::<[u8; 32]>()))
                    .expect("random bytes are a valid secp256k1 key")
            })
            .collect()
    })
}
