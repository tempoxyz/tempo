//! A narrow witness for one metered native storage increment.
//!
//! The caller selects the target before executing the entire transaction and
//! must separately require a supported call shape and a successful result. This
//! recorder observes journal accesses, including warm and reverted accesses;
//! database reads alone cannot establish exclusive use of the incremented slot.

use super::SstoreTransitionFlags;
use alloy::primitives::{Address, U256};
use revm::interpreter::{SStoreResult, StateLoad};
use scoped_tls::scoped_thread_local;
use std::cell::RefCell;

scoped_thread_local!(static RECORDING: RefCell<Recording>);

/// The sole storage increment eligible for recording in a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeIncrementTarget {
    /// Account containing the slot.
    pub address: Address,
    /// Full-width storage slot.
    pub slot: U256,
    /// Positive amount added by the native operation.
    pub delta: U256,
}

/// One successful, exclusively accessed, metered clean nonzero increment.
///
/// This certifies the operation only. Before reusing a transaction, its owner
/// must also validate every other read and match this witness to the original
/// database dependency and final successful result's storage slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeIncrementWitness {
    /// Selected account, slot and increment.
    pub target: NativeIncrementTarget,
    /// Transaction-original value observed by SSTORE.
    pub original: U256,
    /// Value observed by SLOAD and immediately before SSTORE.
    pub present: U256,
    /// Value written by SSTORE.
    pub new: U256,
    /// Whether the increment's SLOAD was cold.
    pub load_is_cold: bool,
    /// Whether the increment's SSTORE was cold.
    pub store_is_cold: bool,
    /// All original/present/new equality and zero classes used by metering.
    pub flags: SstoreTransitionFlags,
}

impl NativeIncrementWitness {
    /// Rebase only when checked arithmetic and every captured metering class
    /// remain unchanged. Zero crossings, dirty writes and warm loads fall back.
    pub fn rebase(&self, original: U256) -> Option<U256> {
        if !self.load_is_cold
            || self.store_is_cold
            || self.target.delta.is_zero()
            || self.original.is_zero()
            || self.original != self.present
            || self.original.checked_add(self.target.delta) != Some(self.new)
            || self.flags
                != SstoreTransitionFlags::from_values(self.original, self.present, self.new)
            || self.flags != SstoreTransitionFlags::ORIGINAL_EQ_PRESENT
            || original.is_zero()
        {
            return None;
        }
        let new = original.checked_add(self.target.delta)?;
        (SstoreTransitionFlags::from_values(original, original, new) == self.flags).then_some(new)
    }
}

struct Recording {
    target: NativeIncrementTarget,
    attempts: u8,
    active: bool,
    completed: bool,
    invalid: bool,
    load: Option<(U256, bool)>,
    store: Option<(SStoreResult, bool)>,
}

impl Recording {
    fn matches(&self, address: Address, slot: U256) -> bool {
        self.target.address == address && self.target.slot == slot
    }

    fn finish(self) -> Option<NativeIncrementWitness> {
        if self.invalid || self.active || !self.completed || self.attempts != 1 {
            return None;
        }
        let (load, load_is_cold) = self.load?;
        let (store, store_is_cold) = self.store?;
        if load != store.present_value {
            return None;
        }
        let witness = NativeIncrementWitness {
            target: self.target,
            original: store.original_value,
            present: store.present_value,
            new: store.new_value,
            load_is_cold,
            store_is_cold,
            flags: SstoreTransitionFlags::from_values(
                store.original_value,
                store.present_value,
                store.new_value,
            ),
        };
        witness.rebase(witness.original).map(|_| witness)
    }
}

/// Record the entire transaction, restoring any previous scope on unwind.
///
/// Nested recording disqualifies both scopes. A returned witness describes only
/// the metered increment; callers must discard it if the transaction failed or
/// its final storage/dependencies do not match. No state or gas is changed here.
/// Construct native storage providers inside this scope to capture metering.
pub fn record<R>(
    target: NativeIncrementTarget,
    f: impl FnOnce() -> R,
) -> (R, Option<NativeIncrementWitness>) {
    let nested = RECORDING.is_set();
    unsupported();
    let recording = RefCell::new(Recording {
        target,
        attempts: 0,
        active: false,
        completed: false,
        invalid: nested,
        load: None,
        store: None,
    });
    let result = super::access::record_native(|| RECORDING.set(&recording, f));
    (result, recording.into_inner().finish())
}

/// Whether newly constructed providers need to capture increment metering.
#[inline]
pub(crate) fn is_recording() -> bool {
    RECORDING.is_set()
}

/// Observe all target accesses independently of the unmetered fee exemption.
#[inline]
pub(crate) fn storage(address: Address, slot: U256) {
    if RECORDING.is_set() {
        RECORDING.with(|recording| {
            let mut recording = recording.borrow_mut();
            if recording.matches(address, slot) && !recording.active {
                recording.invalid = true;
            }
        });
    }
}

/// Lifecycle changes and reverted native checkpoints cannot use this witness.
#[inline]
pub(crate) fn unsupported() {
    if RECORDING.is_set() {
        RECORDING.with(|recording| recording.borrow_mut().invalid = true);
    }
}

/// Run the implementation of a single native Sinc, including all its metering.
#[inline]
pub(crate) fn sinc<E>(
    address: Address,
    slot: U256,
    delta: U256,
    f: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    if !RECORDING.is_set() {
        return f();
    }
    RECORDING.with(|recording| {
        {
            let mut state = recording.borrow_mut();
            if !state.matches(address, slot) {
                drop(state);
                return f();
            }
            state.attempts = state.attempts.saturating_add(1);
            let invalid = state.active || state.attempts != 1 || state.target.delta != delta;
            state.invalid |= invalid;
            state.active = true;
        }
        // A panic caught by the caller must not leave a successful witness, even
        // if another increment is attempted in the same recording scope.
        let mut guard = IncrementGuard {
            recording,
            finished: false,
        };
        let result = f();
        {
            let mut state = recording.borrow_mut();
            state.active = false;
            state.completed = result.is_ok();
            state.invalid |= result.is_err();
        }
        guard.finished = true;
        result
    })
}

struct IncrementGuard<'a> {
    recording: &'a RefCell<Recording>,
    finished: bool,
}

impl Drop for IncrementGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let mut state = self.recording.borrow_mut();
            state.active = false;
            state.invalid = true;
        }
    }
}

/// Capture the actual journal SLOAD, including its transaction warmness.
#[inline]
pub(crate) fn loaded(address: Address, slot: U256, load: &StateLoad<U256>) {
    if RECORDING.is_set() {
        RECORDING.with(|recording| {
            let mut state = recording.borrow_mut();
            if state.matches(address, slot) {
                let invalid = !state.active || state.load.is_some() || state.store.is_some();
                state.invalid |= invalid;
                state.load = Some((load.data, load.is_cold));
            }
        });
    }
}

/// Capture the actual journal SSTORE; completion is certified only after sinc
/// returns, since storage-credit accounting and gas checks can still fail.
#[inline]
pub(crate) fn stored(address: Address, slot: U256, store: &StateLoad<SStoreResult>) {
    if RECORDING.is_set() {
        RECORDING.with(|recording| {
            let mut state = recording.borrow_mut();
            if state.matches(address, slot) {
                let invalid = !state.active || state.load.is_none() || state.store.is_some();
                state.invalid |= invalid;
                state.store = Some((store.data.clone(), store.is_cold));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{access, fee_updates};

    fn target() -> NativeIncrementTarget {
        NativeIncrementTarget {
            address: Address::repeat_byte(0x44),
            slot: U256::from(3),
            delta: U256::ONE,
        }
    }

    fn journal_accesses(target: NativeIncrementTarget) {
        access::storage(target.address, target.slot);
        loaded(
            target.address,
            target.slot,
            &StateLoad::new(U256::from(10), true),
        );
        access::storage(target.address, target.slot);
        stored(
            target.address,
            target.slot,
            &StateLoad::new(
                SStoreResult {
                    original_value: U256::from(10),
                    present_value: U256::from(10),
                    new_value: U256::from(11),
                },
                false,
            ),
        );
    }

    fn increment(target: NativeIncrementTarget) {
        sinc(target.address, target.slot, target.delta, || {
            journal_accesses(target);
            Ok::<_, ()>(())
        })
        .unwrap();
    }

    #[test]
    fn rebase_preserves_clean_nonzero_metering_and_checks_overflow() {
        let (_, witness) = record(target(), || increment(target()));
        let witness = witness.unwrap();
        assert_eq!(witness.rebase(U256::from(20)), Some(U256::from(21)));
        assert_eq!(witness.rebase(U256::ZERO), None);
        assert_eq!(witness.rebase(U256::MAX), None);
        assert_eq!(witness.flags, SstoreTransitionFlags::ORIGINAL_EQ_PRESENT);
        for modified in [
            NativeIncrementWitness {
                original: U256::from(9),
                ..witness
            },
            NativeIncrementWitness {
                present: U256::from(9),
                ..witness
            },
            NativeIncrementWitness {
                new: U256::from(12),
                ..witness
            },
            NativeIncrementWitness {
                load_is_cold: false,
                ..witness
            },
            NativeIncrementWitness {
                store_is_cold: true,
                ..witness
            },
            NativeIncrementWitness {
                flags: SstoreTransitionFlags::empty(),
                ..witness
            },
        ] {
            assert_eq!(modified.rebase(U256::from(20)), None);
        }
    }

    #[test]
    fn target_observations_before_or_after_and_repeated_attempts_reject() {
        let target = target();
        for before in [true, false] {
            let (_, witness) = record(target, || {
                if before {
                    access::storage(target.address, target.slot);
                }
                increment(target);
                if !before {
                    access::storage(target.address, target.slot);
                }
            });
            assert!(witness.is_none());
        }
        let (_, witness) = record(target, || {
            increment(target);
            increment(target);
        });
        assert!(witness.is_none());
        let (_, witness) = record(target, || {
            access::storage(target.address, target.slot + U256::ONE);
            increment(target);
        });
        assert!(witness.is_some());
    }

    #[test]
    fn fee_exemptions_never_hide_native_observations_or_native_accesses() {
        let target = target();
        let (((), fees), witness) = record(target, || {
            fee_updates::record(|| {
                fee_updates::update(
                    Some((target.address, target.slot)),
                    fee_updates::FeeDelta::Add(U256::ONE),
                    || {
                        access::storage(target.address, target.slot);
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
                increment(target);
            })
        });
        assert!(
            witness.is_none(),
            "fee access must disqualify native witness"
        );
        assert!(fees.is_empty(), "native access must disqualify fee update");
    }

    #[test]
    fn native_scopes_preserve_body_recording_and_database_time() {
        let target = target();
        let elapsed = std::time::Duration::from_micros(7);
        assert!(!access::is_recording());
        let (((), body), witness) = record(target, || {
            assert!(!access::is_recording());
            access::record_database_time(elapsed);
            let recorded = access::record(|| {
                assert!(access::is_recording());
                access::record_database_time(elapsed);
                increment(target);
            });
            assert!(!access::is_recording());
            access::record_database_time(elapsed);
            recorded
        });
        assert!(witness.is_some());
        assert_eq!(body.slots.len(), 1);
        assert!(body.slots.contains(&(target.address, target.slot)));
        assert_eq!(body.database_time, elapsed);
        assert!(!access::is_recording());

        let (((), witness), body) = access::record(|| {
            let recorded = record(target, || {
                assert!(access::is_recording());
                access::record_database_time(elapsed);
                increment(target);
            });
            assert!(access::is_recording());
            recorded
        });
        assert!(witness.is_some());
        assert_eq!(body.slots.len(), 1);
        assert!(body.slots.contains(&(target.address, target.slot)));
        assert_eq!(body.database_time, elapsed);
        assert!(!access::is_recording());

        let result = std::panic::catch_unwind(|| {
            record(target, || {
                assert!(!access::is_recording());
                panic!("unwind native-only scope")
            })
        });
        assert!(result.is_err());
        assert!(!access::is_recording());
        let ((), body) = access::record(|| {
            assert!(access::is_recording());
            access::record_database_time(elapsed);
        });
        assert!(body.slots.is_empty());
        assert_eq!(body.database_time, elapsed);
    }

    #[test]
    fn failed_metering_missing_or_repeated_loads_and_wrong_delta_reject() {
        let target = target();
        for case in 0..5 {
            let (_, witness) = record(target, || {
                let delta = if case == 4 {
                    U256::from(2)
                } else {
                    target.delta
                };
                let _ = sinc(target.address, target.slot, delta, || {
                    if case != 1 {
                        journal_accesses(target);
                    }
                    if case == 2 {
                        loaded(
                            target.address,
                            target.slot,
                            &StateLoad::new(U256::from(10), true),
                        );
                    }
                    if case == 3 {
                        access::unsupported();
                    }
                    if case == 0 { Err(()) } else { Ok(()) }
                });
            });
            assert!(witness.is_none(), "case {case}");
        }
    }

    #[test]
    fn nested_recording_and_caught_increment_unwind_reject_and_restore_scope() {
        let target = target();
        let (_, witness) = record(target, || {
            increment(target);
            let (_, nested) = record(target, || increment(target));
            assert!(nested.is_none());
        });
        assert!(witness.is_none());
        let (_, witness) = record(target, || {
            let result = std::panic::catch_unwind(|| {
                sinc::<()>(target.address, target.slot, target.delta, || {
                    journal_accesses(target);
                    panic!("unwind after journal write, before metering completion")
                })
            });
            assert!(result.is_err());
        });
        assert!(witness.is_none());
        assert!(!RECORDING.is_set());
        let (_, witness) = record(target, || increment(target));
        assert!(witness.is_some());
    }
}
