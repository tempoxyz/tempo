//! Builder-owned thread-local state, independent of the engine's shared worker slot.
//!
//! The named builder coordinator serializes contexts and joins scoped leaves before
//! cleanup. The existing stop allocation identifies that context without retaining
//! it strongly; a Weak reference prevents allocation-address reuse while a lease or
//! slot still refers to it. Leases also tolerate same-thread nested Rayon work:
//! the nested call can use a separate state while its caller's EVM is unavailable.
use std::{
    cell::RefCell,
    sync::{Arc, Weak, atomic::AtomicBool},
    thread::LocalKey,
};

pub(super) struct Slot<T> {
    owner: Option<Weak<AtomicBool>>,
    state: Option<T>,
}

impl<T> Slot<T> {
    pub(super) const fn new() -> Self {
        Self {
            owner: None,
            state: None,
        }
    }
    #[cfg(test)]
    pub(super) fn state(&self) -> Option<&T> {
        self.state.as_ref()
    }

    fn owns(&self, owner: &Weak<AtomicBool>) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|current| current.ptr_eq(owner))
    }
}

// Dropping or constructing an EVM can access providers and run other work. Never
// retain a RefCell borrow across either operation, nor across the selected call.
pub(super) fn initialize<T: 'static>(
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    owner: &Arc<AtomicBool>,
    init: impl FnOnce() -> T,
) {
    let owner = Arc::downgrade(owner);
    let (claimed, old) = slot.with_borrow_mut(|slot| {
        // A leaf can initialize before the proactive broadcast, or temporarily
        // lease the state while servicing that broadcast. Preserve both cases.
        if slot.owns(&owner) {
            return (false, None);
        }
        slot.owner = Some(owner.clone());
        (true, slot.state.take())
    });
    drop(old);
    if !claimed {
        return;
    }
    let state = init();
    put(slot, &owner, state);
}

fn put<T: 'static>(slot: &'static LocalKey<RefCell<Slot<T>>>, owner: &Weak<AtomicBool>, state: T) {
    let retired = slot.with_borrow_mut(|slot| {
        if slot.owns(owner) {
            slot.state.replace(state)
        } else {
            Some(state)
        }
    });
    drop(retired);
}

pub(super) fn clear<T: 'static>(
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    owner: &Weak<AtomicBool>,
) {
    let retired = slot.with_borrow_mut(|slot| {
        if slot.owns(owner) {
            slot.owner = None;
            slot.state.take()
        } else {
            None
        }
    });
    drop(retired);
}

pub(super) fn with_state<T: 'static, R>(
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    owner: &Arc<AtomicBool>,
    init: impl FnOnce() -> T,
    f: impl FnOnce(&mut T) -> R,
) -> R {
    let owner = Arc::downgrade(owner);
    let (state, retired) = slot.with_borrow_mut(|slot| {
        let state = slot.state.take();
        if slot.owns(&owner) {
            (state, None)
        } else {
            slot.owner = Some(owner.clone());
            (None, state)
        }
    });
    drop(retired);
    let state = state.unwrap_or_else(init);
    let mut lease = Lease {
        slot,
        owner,
        state: Some(state),
    };
    f(lease
        .state
        .as_mut()
        .expect("lease retains state until drop"))
}

struct Lease<T: 'static> {
    slot: &'static LocalKey<RefCell<Slot<T>>>,
    owner: Weak<AtomicBool>,
    state: Option<T>,
}
impl<T> Drop for Lease<T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // An interrupted call must not cache its partially mutated EVM.
            clear(self.slot, &self.owner);
        } else if let Some(state) = self.state.take() {
            // A nested call may have installed another context; never restore
            // this older lease over that newer context's state.
            put(self.slot, &self.owner, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    thread_local! { static TEST: RefCell<Slot<usize>> = const { RefCell::new(Slot::new()) }; }
    fn owner() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
    #[test]
    fn nested_calls_lease_independent_state_without_borrowing() {
        let a = owner();
        initialize(&TEST, &a, || 11);
        with_state(
            &TEST,
            &a,
            || unreachable!(),
            |outer| {
                assert_eq!(*outer, 11);
                with_state(
                    &TEST,
                    &a,
                    || 22,
                    |inner| {
                        assert_eq!(*inner, 22);
                        *inner = 23;
                    },
                );
                *outer = 12;
            },
        );
        assert_eq!(with_state(&TEST, &a, || unreachable!(), |v| *v), 12);
        clear(&TEST, &Arc::downgrade(&a));
    }
    #[test]
    fn proactive_initialization_preserves_early_leaf_and_outstanding_lease() {
        let a = owner();
        with_state(&TEST, &a, || 11, |v| *v = 12);
        initialize(&TEST, &a, || panic!("must preserve early leaf"));
        with_state(
            &TEST,
            &a,
            || unreachable!(),
            |v| {
                initialize(&TEST, &a, || panic!("must preserve leased state"));
                assert_eq!(*v, 12);
            },
        );
        clear(&TEST, &Arc::downgrade(&a));
    }
    #[test]
    fn own_clear_prevents_outstanding_lease_from_repopulating() {
        let a = owner();
        with_state(&TEST, &a, || 11, |_| clear(&TEST, &Arc::downgrade(&a)));
        assert!(TEST.with_borrow(|slot| slot.state.is_none() && slot.owner.is_none()));
    }
    #[test]
    fn initializer_panic_does_not_cache_a_value() {
        let a = owner();
        assert!(
            std::panic::catch_unwind(|| initialize(&TEST, &a, || panic!("initializer"))).is_err()
        );
        assert!(TEST.with_borrow(|slot| slot.state.is_none()));
        assert_eq!(with_state(&TEST, &a, || 12, |v| *v), 12);
        clear(&TEST, &Arc::downgrade(&a));
    }
    #[test]
    fn newer_context_survives_old_lease_return_and_clear() {
        let a = owner();
        let b = owner();
        with_state(&TEST, &a, || 11, |_| initialize(&TEST, &b, || 22));
        clear(&TEST, &Arc::downgrade(&a));
        assert_eq!(with_state(&TEST, &b, || unreachable!(), |v| *v), 22);
        clear(&TEST, &Arc::downgrade(&b));
    }
    #[test]
    fn panic_discards_only_its_own_state_and_next_context_reinitializes() {
        let a = owner();
        let b = owner();
        let result = std::panic::catch_unwind(|| {
            with_state(&TEST, &a, || 11, |_| panic!("synthetic leaf panic"))
        });
        assert!(result.is_err());
        assert_eq!(with_state(&TEST, &a, || 12, |v| *v), 12);
        let result = std::panic::catch_unwind(|| {
            with_state(
                &TEST,
                &a,
                || unreachable!(),
                |_| {
                    initialize(&TEST, &b, || 22);
                    panic!("old context panic")
                },
            )
        });
        assert!(result.is_err());
        assert_eq!(with_state(&TEST, &b, || unreachable!(), |v| *v), 22);
        clear(&TEST, &Arc::downgrade(&b));
    }
    #[test]
    fn constructor_can_replace_context_without_old_return_overwriting_it() {
        let a = owner();
        let b = owner();
        initialize(&TEST, &a, || {
            initialize(&TEST, &b, || 22);
            11
        });
        assert_eq!(with_state(&TEST, &b, || unreachable!(), |v| *v), 22);
        clear(&TEST, &Arc::downgrade(&b));
    }
    #[test]
    fn replaced_state_destructor_runs_outside_slot_borrow() {
        struct Reenter(Option<Arc<AtomicBool>>);
        thread_local! { static DROP_TEST: RefCell<Slot<Reenter>>=const {RefCell::new(Slot::new())}; }
        impl Drop for Reenter {
            fn drop(&mut self) {
                if let Some(owner) = self.0.take() {
                    with_state(
                        &DROP_TEST,
                        &owner,
                        || Reenter(None),
                        |_| owner.store(true, Ordering::Relaxed),
                    );
                }
            }
        }
        let a = owner();
        initialize(&DROP_TEST, &a, || Reenter(Some(a.clone())));
        let b = owner();
        initialize(&DROP_TEST, &b, || Reenter(None));
        assert!(a.load(Ordering::Relaxed));
        clear(&DROP_TEST, &Arc::downgrade(&a));
        clear(&DROP_TEST, &Arc::downgrade(&b));
    }
}
