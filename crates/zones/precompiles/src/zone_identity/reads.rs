//! Recording the delegated reads `ZoneIdentity` allows while simulating at an earlier block.

use core::cell::RefCell;

use alloy_primitives::{Address, map::HashSet};

std::thread_local! {
    /// Reads recorded by the [`audit_reads`] call running on this thread.
    static AUDIT: RefCell<Option<HashSet<DelegatedRead>>> = const { RefCell::new(None) };
}

/// A read of `account`'s state by another address, `reader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DelegatedRead {
    /// The address reading.
    pub reader: Address,
    /// The account read.
    pub account: Address,
}

/// Runs `f` allowing and returning every delegated read; its output stands if latest allows them.
pub fn audit_reads<R>(f: impl FnOnce() -> R) -> (R, HashSet<DelegatedRead>) {
    /// Ends the audit even if `f` panics.
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            AUDIT.set(None);
        }
    }

    let previous = AUDIT.replace(Some(HashSet::default()));
    debug_assert!(previous.is_none(), "`audit_reads` calls must not nest");
    let _guard = Guard;
    (f(), AUDIT.take().expect("set until the guard drops"))
}

/// Whether `read` proceeds: `allowed`, or true while audited, recording it.
pub(super) fn admit(read: DelegatedRead, allowed: bool) -> bool {
    AUDIT.with_borrow_mut(|audit| {
        audit.as_mut().map_or(allowed, |reads| {
            reads.insert(read);
            true
        })
    })
}
