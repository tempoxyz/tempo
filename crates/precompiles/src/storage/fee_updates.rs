//! Arithmetic performed by unmetered native fee collection.
//!
//! Workers may rebase these updates only when every other access to the same
//! slot is absent. Ordinary reads and writes, including reverted ones, disqualify
//! a slot. Keep individual operations: a net increment can hide an intermediate
//! overflow when the maximum fee is collected before the refund.

use alloy::primitives::{
    Address, U256,
    map::{HashMap, HashSet},
};
use scoped_tls::scoped_thread_local;
use std::cell::RefCell;

type Key = (Address, U256);

scoped_thread_local!(static RECORDING: RefCell<Recording>);
scoped_thread_local!(static UPDATE: Option<Key>);

/// A checked arithmetic operation in native fee collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeDelta {
    /// Collect maximum fees or accumulate actual fees.
    Add(U256),
    /// Return unused fees from the fee manager.
    Sub(U256),
}

/// A sequence of fee-only accesses to one storage slot.
#[derive(Debug)]
pub struct FeeUpdate {
    /// Account containing the slot.
    pub address: Address,
    /// Full-width storage slot.
    pub slot: U256,
    operations: Vec<FeeDelta>,
}

impl FeeUpdate {
    /// Apply every arithmetic check in order, including intermediate overflow.
    pub fn apply(&self, mut value: U256) -> Option<U256> {
        for operation in &self.operations {
            value = match operation {
                FeeDelta::Add(amount) => value.checked_add(*amount)?,
                FeeDelta::Sub(amount) => value.checked_sub(*amount)?,
            };
        }
        Some(value)
    }
}

#[derive(Default)]
struct Recording {
    updates: HashMap<Key, Vec<FeeDelta>>,
    observed: HashSet<Key>,
    unsupported: bool,
}

/// Record a standard worker transaction. The caller must use standard gas
/// parameters and instrument EVM storage and account-creation instructions.
pub fn record<R>(f: impl FnOnce() -> R) -> (R, Vec<FeeUpdate>) {
    // A nested transaction must not hide accesses from its parent's recorder.
    unsupported();
    let recording = RefCell::default();
    let result = UPDATE.set(&None, || RECORDING.set(&recording, f));
    let Recording {
        updates,
        observed,
        unsupported,
    } = recording.into_inner();
    let updates = if unsupported {
        Vec::new()
    } else {
        updates
            .into_iter()
            .filter_map(|((address, slot), operations)| {
                (!observed.contains(&(address, slot))).then_some(FeeUpdate {
                    address,
                    slot,
                    operations,
                })
            })
            .collect()
    };
    (result, updates)
}

/// Run exactly one checked read/modify/write from the internal fee path.
/// This must not surround metered contract calls or expose the read value.
#[inline]
pub(crate) fn update<E>(
    key: Option<Key>,
    delta: FeeDelta,
    f: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    let Some(key) = key else {
        return f();
    };
    let result = UPDATE.set(&Some(key), f);
    if result.is_ok() {
        RECORDING.with(|recording| {
            recording
                .borrow_mut()
                .updates
                .entry(key)
                .or_default()
                .push(delta)
        });
    } else {
        // A failed storage write can have changed the journal before returning
        // its error. A caller may catch/revert it and still return a result.
        RECORDING.with(|recording| recording.borrow_mut().observed.insert(key));
    }
    result
}

/// Avoid computing annotation keys outside speculative workers.
#[inline]
pub(crate) fn recording_key(f: impl FnOnce() -> Key) -> Option<Key> {
    RECORDING.is_set().then(f)
}

/// Record all non-fee observations, including writes and reverted accesses.
#[inline]
pub(crate) fn storage(address: Address, slot: U256) {
    if RECORDING.is_set() && (!UPDATE.is_set() || UPDATE.with(|key| *key != Some((address, slot))))
    {
        RECORDING.with(|recording| recording.borrow_mut().observed.insert((address, slot)));
    }
}

/// Account creation or destruction may bypass individual storage accesses.
#[inline]
pub(crate) fn unsupported() {
    if RECORDING.is_set() {
        RECORDING.with(|recording| recording.borrow_mut().unsupported = true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(key: Key, delta: FeeDelta) {
        update(recording_key(|| key), delta, || {
            storage(key.0, key.1);
            storage(key.0, key.1);
            Ok::<_, ()>(())
        })
        .unwrap();
    }

    #[test]
    fn preserves_intermediate_arithmetic_checks() {
        let key = (Address::ZERO, U256::ZERO);
        let (_, updates) = record(|| {
            operation(key, FeeDelta::Add(U256::from(10)));
            operation(key, FeeDelta::Sub(U256::from(9)));
        });
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].apply(U256::from(7)), Some(U256::from(8)));
        assert_eq!(updates[0].apply(U256::MAX - U256::ONE), None);
        let (_, updates) = record(|| operation(key, FeeDelta::Sub(U256::ONE)));
        assert_eq!(updates[0].apply(U256::ZERO), None);
    }

    #[test]
    fn observations_before_between_and_after_updates_disqualify_the_slot() {
        let key = (Address::ZERO, U256::ZERO);
        for at in 0..3 {
            let (_, updates) = record(|| {
                for step in 0..3 {
                    if step == at {
                        storage(key.0, key.1);
                    }
                    operation(key, FeeDelta::Add(U256::ONE));
                }
                if at == 2 {
                    storage(key.0, key.1);
                }
            });
            assert!(updates.is_empty());
        }
    }

    #[test]
    fn unrelated_slots_do_not_disqualify_updates() {
        let key = (Address::ZERO, U256::ZERO);
        let (_, updates) = record(|| {
            storage(key.0, U256::ONE);
            operation(key, FeeDelta::Add(U256::ONE));
        });
        assert_eq!(updates.len(), 1);
        let (_, updates) = record(|| {
            operation(key, FeeDelta::Add(U256::ONE));
            unsupported();
        });
        assert!(updates.is_empty());
    }

    #[test]
    fn recording_scopes_restore_on_unwind() {
        let key = (Address::ZERO, U256::ZERO);
        let (_, updates) = record(|| {
            let result = std::panic::catch_unwind(|| {
                update::<()>(recording_key(|| key), FeeDelta::Add(U256::ONE), || {
                    panic!("fee update")
                })
            });
            assert!(result.is_err());
            storage(key.0, key.1);
            operation(key, FeeDelta::Add(U256::ONE));
        });
        assert!(updates.is_empty());
        assert!(!RECORDING.is_set());
        assert!(!UPDATE.is_set());
    }

    #[test]
    fn failed_updates_and_nested_recording_disqualify_reuse() {
        let key = (Address::ZERO, U256::ZERO);
        let (_, updates) = record(|| {
            operation(key, FeeDelta::Add(U256::ONE));
            let result = update(recording_key(|| key), FeeDelta::Add(U256::ONE), || Err(()));
            assert!(result.is_err());
        });
        assert!(updates.is_empty());
        let (_, updates) = record(|| {
            operation(key, FeeDelta::Add(U256::ONE));
            let (_, nested) = record(|| {
                storage(key.0, key.1);
                operation(key, FeeDelta::Add(U256::ONE));
            });
            assert!(nested.is_empty());
        });
        assert!(updates.is_empty());
    }
}
