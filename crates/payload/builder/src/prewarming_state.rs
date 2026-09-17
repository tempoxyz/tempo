//! Builder-only thread-local state on the shared prewarming pool.
//!
//! The `builder-prewarm` coordinator serializes builds, joins their scoped leaves,
//! and clears every worker before starting the next build. No context IDs are
//! needed. A lease moves the EVM out of TLS so same-thread nested Rayon work can
//! use its own EVM without holding a RefCell borrow across execution.
use std::{cell::RefCell, thread::LocalKey};

pub(super) struct Slot<T> {
    // A missing state can also mean that a leaf is currently using it. In that
    // case the proactive initializer must leave the outstanding lease alone.
    initialized: bool,
    state: Option<T>,
}

impl<T> Slot<T> {
    pub(super) const fn new() -> Self {
        Self {
            initialized: false,
            state: None,
        }
    }

    #[cfg(test)]
    pub(super) fn state(&self) -> Option<&T> {
        self.state.as_ref()
    }
}

pub(super) fn initialize<T: 'static>(
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    init: impl FnOnce() -> T,
) {
    let initialized = slot.with_borrow_mut(|slot| std::mem::replace(&mut slot.initialized, true));
    if !initialized {
        put(slot, init());
    }
}

// Construct and drop EVMs outside the RefCell borrow: providers can run nested work.
fn put<T: 'static>(slot: &'static LocalKey<RefCell<Slot<T>>>, state: T) {
    let retired = slot.with_borrow_mut(|slot| slot.state.replace(state));
    drop(retired);
}

pub(super) fn clear<T: 'static>(slot: &'static LocalKey<RefCell<Slot<T>>>) {
    let retired = slot.replace(Slot::new());
    drop(retired);
}

pub(super) fn with_state<T: 'static, R>(
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    init: impl FnOnce() -> T,
    f: impl FnOnce(&mut T) -> R,
) -> R {
    let state = slot.with_borrow_mut(|slot| {
        slot.initialized = true;
        slot.state.take()
    });
    let mut lease = Lease {
        slot,
        state: Some(state.unwrap_or_else(init)),
    };
    f(lease
        .state
        .as_mut()
        .expect("lease retains state until drop"))
}

struct Lease<T: 'static> {
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    state: Option<T>,
}

impl<T> Drop for Lease<T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Do not cache an interrupted transaction's partially mutated EVM.
            clear(self.slot);
        } else if let Some(state) = self.state.take() {
            put(self.slot, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    thread_local! {
        static TEST: RefCell<Slot<usize>> = const { RefCell::new(Slot::new()) };
    }

    #[test]
    fn nested_calls_lease_independent_state_without_borrowing() {
        clear(&TEST);
        initialize(&TEST, || 11);
        with_state(
            &TEST,
            || unreachable!(),
            |outer| {
                assert_eq!(*outer, 11);
                with_state(
                    &TEST,
                    || 22,
                    |inner| {
                        assert_eq!(*inner, 22);
                        *inner = 23;
                    },
                );
                *outer = 12;
            },
        );
        assert_eq!(with_state(&TEST, || unreachable!(), |v| *v), 12);
        clear(&TEST);
    }

    #[test]
    fn proactive_initialization_preserves_early_leaf_and_outstanding_lease() {
        clear(&TEST);
        with_state(&TEST, || 11, |v| *v = 12);
        initialize(&TEST, || panic!("must preserve early leaf"));
        with_state(
            &TEST,
            || unreachable!(),
            |v| {
                initialize(&TEST, || panic!("must preserve leased state"));
                assert_eq!(*v, 12);
            },
        );
        clear(&TEST);
    }

    #[test]
    fn initializer_panic_allows_lazy_reinitialization() {
        clear(&TEST);
        assert!(std::panic::catch_unwind(|| initialize(&TEST, || panic!("initializer"))).is_err());
        assert!(TEST.with_borrow(|slot| slot.state.is_none()));
        assert_eq!(with_state(&TEST, || 12, |v| *v), 12);
        clear(&TEST);
    }

    #[test]
    fn panic_discards_state_and_next_build_reinitializes() {
        clear(&TEST);
        let result = std::panic::catch_unwind(|| {
            with_state(&TEST, || 11, |_| panic!("synthetic leaf panic"));
        });
        assert!(result.is_err());
        assert!(TEST.with_borrow(|slot| slot.state.is_none() && !slot.initialized));
        initialize(&TEST, || 22);
        assert_eq!(with_state(&TEST, || unreachable!(), |v| *v), 22);
        clear(&TEST);
    }

    #[test]
    fn replaced_state_destructor_runs_outside_slot_borrow() {
        struct Reenter(Option<Arc<AtomicBool>>);
        thread_local! {
            static DROP_TEST: RefCell<Slot<Reenter>> = const { RefCell::new(Slot::new()) };
        }
        impl Drop for Reenter {
            fn drop(&mut self) {
                if let Some(called) = self.0.take() {
                    with_state(
                        &DROP_TEST,
                        || Self(None),
                        |_| called.store(true, Ordering::Relaxed),
                    );
                }
            }
        }
        let called = Arc::new(AtomicBool::new(false));
        initialize(&DROP_TEST, || Reenter(Some(called.clone())));
        clear(&DROP_TEST);
        assert!(called.load(Ordering::Relaxed));
        clear(&DROP_TEST);
    }
}
