//! Exact-target Ethereum secure-MPT proofs and bounded authenticated raw-state caching.
//!
//! Verification authenticates values against a caller-selected root, NOT that root's finality,
//! ancestry, execution validity, chain identity, or freshness. Consumers own root authority,
//! transport budgets, synchronization and application acceptance before cache publication.
//! Verification is no_std/alloc-compatible; the host cache requires `std`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloy_primitives::{Address, B256};

mod proof;
pub use proof::*;

#[cfg(feature = "cache")]
mod cache;
#[cfg(feature = "cache")]
pub use cache::*;

#[cfg(feature = "test-utils")]
pub mod test_utils;

/// An account and its raw 32-byte storage index (not the hashed trie path).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StorageReadKey {
    pub account: Address,
    pub slot: B256,
}

impl StorageReadKey {
    pub const fn new(account: Address, slot: B256) -> Self {
        Self { account, slot }
    }
}

/// Deduplicated exact targets. Empty slot sets request account-only authentication.
pub type ProofTargets = BTreeMap<Address, BTreeSet<B256>>;
