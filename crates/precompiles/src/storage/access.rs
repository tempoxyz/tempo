//! Optional storage access tracking for speculative call-body reuse.
//!
//! Journal caches and reverted calls can hide dependencies from a database wrapper.
//! This scope records attempts before accessing the journal and survives call reverts.

use alloy::primitives::{Address, U256, map::HashSet};
use scoped_tls::scoped_thread_local;
use std::{cell::RefCell, time::Duration};

// None observes native increments without collecting call-body dependencies.
scoped_thread_local!(static ACCESSES: Option<RefCell<StorageAccesses>>);

/// Journal storage accessed while executing a transaction's calls.
#[derive(Debug, Default)]
pub struct StorageAccesses {
    /// Includes reads and writes: SSTORE's original value affects gas and refunds.
    pub slots: HashSet<(Address, U256)>,
    /// Account creation/destruction requires a full replay when dependencies change.
    pub unsupported: bool,
    /// Time spent in the worker's database proxy, including coordinator waits.
    pub database_time: Duration,
}

/// Run a call body with access recording, restoring the previous scope on unwind.
pub fn record<R>(f: impl FnOnce() -> R) -> (R, StorageAccesses) {
    let accesses = Some(RefCell::default());
    let result = ACCESSES.set(&accesses, f);
    let Some(accesses) = accesses else {
        unreachable!("body recorder always collects storage accesses")
    };
    (result, accesses.into_inner())
}

/// Observe native accesses without replacing an enclosing call-body recorder.
pub(crate) fn record_native<R>(f: impl FnOnce() -> R) -> R {
    if ACCESSES.is_set() {
        f()
    } else {
        ACCESSES.set(&None, f)
    }
}

/// Whether database reads belong to a recorded call body.
#[inline]
pub fn is_recording() -> bool {
    ACCESSES.is_set() && ACCESSES.with(Option::is_some)
}

/// Separate database round trips from execution when deciding whether a body is
/// expensive enough to cache. This estimate never affects validity checks.
pub fn record_database_time(elapsed: Duration) {
    if ACCESSES.is_set() {
        ACCESSES.with(|accesses| {
            if let Some(accesses) = accesses {
                accesses.borrow_mut().database_time += elapsed;
            }
        });
    }
}

/// Record a journal read or write, including accesses served from its cache.
#[inline]
pub fn storage(address: Address, key: U256) {
    if ACCESSES.is_set() {
        super::native_increment::storage(address, key);
        ACCESSES.with(|accesses| {
            if let Some(accesses) = accesses {
                accesses.borrow_mut().slots.insert((address, key));
            }
        });
    }
    super::fee_updates::storage(address, key);
}

/// Disable call-body reuse for an operation that can clear account storage.
pub fn unsupported() {
    if ACCESSES.is_set() {
        super::native_increment::unsupported();
        ACCESSES.with(|accesses| {
            if let Some(accesses) = accesses {
                accesses.borrow_mut().unsupported = true;
            }
        });
    }
    super::fee_updates::unsupported();
}
