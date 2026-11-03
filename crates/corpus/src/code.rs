//! Contract bytecode shared across block records, verified against its hash once.

use alloy_primitives::{B256, Bytes, keccak256};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::LazyLock};

/// Not evicted: fill and replay read code back right after inserting it, so eviction could
/// fail a capture mid-block. Its size is bounded by the chain's distinct bytecode, which is
/// far below the record budget.
static CODE: LazyLock<RwLock<HashMap<[u8; 32], Bytes>>> = LazyLock::new(Default::default);

/// Whether verified bytecode for `hash` is cached.
pub fn has_code(hash: &[u8; 32]) -> bool {
    CODE.read().contains_key(hash)
}

/// Verified bytecode for `hash`, if cached.
pub fn code_bytes(hash: &[u8; 32]) -> Option<Bytes> {
    CODE.read().get(hash).cloned()
}

/// Verifies `code` against `hash` and caches it. An identical cached copy is compared
/// byte for byte instead of hashed again.
pub fn insert_code(hash: &[u8; 32], code: &[u8]) -> eyre::Result<()> {
    if let Some(cached) = CODE.read().get(hash) {
        eyre::ensure!(cached.as_ref() == code, "corpus code hash mismatch");
        return Ok(());
    }
    eyre::ensure!(
        keccak256(code).0 == *hash || (*hash == [0; 32] && code.is_empty()),
        "corpus code hash mismatch {}",
        B256::from(*hash)
    );
    CODE.write().insert(*hash, Bytes::copy_from_slice(code));
    Ok(())
}
