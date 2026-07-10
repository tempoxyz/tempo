//! TIP-1040 temporary storage layout and gas policy.
//!
//! Pure helpers shared by the [`PrecompileStorageProvider`](super::PrecompileStorageProvider)
//! implementations of `temporary_store`/`temporary_load`; the account layout lives on
//! [`tempo_primitives::TemporaryStorageAccount`].

use alloy::primitives::{Address, B256, U256, keccak256};
use revm::interpreter::SStoreResult;

/// Gas cost for `temporaryStore` when the slot is zero in the current epoch.
pub const STORE_GAS_NEW: u64 = 40_000;

/// Gas cost for `temporaryStore` when the slot is nonzero in the current epoch and cold
/// (`COLD_SLOAD_COST` + `SSTORE_RESET_GAS`).
pub const STORE_GAS_EXISTING_COLD: u64 = 2_100 + 5_000;

/// Gas cost for `temporaryStore` when the slot is nonzero in the current epoch and warm
/// (`WARM_STORAGE_READ_COST` + `SSTORE_WRITE_GAS_DELTA`). Also the minimum store cost,
/// pre-charged before touching storage.
pub const STORE_GAS_EXISTING_WARM: u64 = 200;

/// Derives the storage slot for a `(namespace, key)` pair: `keccak256(namespace || key)`.
///
/// The namespace is the isolation boundary — ABI dispatch passes `msg.sender`, so two
/// callers can never collide. Unmetered, like [`Mapping`](super::Mapping) slot
/// derivation; TIP-1040 prices the hash into the flat operation costs.
pub fn slot(namespace: Address, key: B256) -> U256 {
    let mut buf = [0u8; 52];
    buf[..20].copy_from_slice(namespace.as_slice());
    buf[20..].copy_from_slice(key.as_slice());
    keccak256(buf).into()
}

/// Returns the TIP-1040 gas for a store given the slot's value transition and cold flag.
pub fn store_gas(result: &SStoreResult, is_cold: bool) -> u64 {
    if result.present_value.is_zero() {
        STORE_GAS_NEW
    } else if is_cold {
        STORE_GAS_EXISTING_COLD
    } else {
        STORE_GAS_EXISTING_WARM
    }
}
