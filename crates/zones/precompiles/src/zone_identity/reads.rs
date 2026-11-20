//! Auditing of the delegated reads `ZoneIdentity` grants while simulating at an earlier block.

use core::cell::RefCell;

use alloy_primitives::{Address, map::HashSet};

std::thread_local! {
    /// State of the [`audit_reads`] call running on this thread.
    static AUDIT: RefCell<Option<Audit>> = const { RefCell::new(None) };
}

/// A read of `account`'s state by `reader`, an admin or reader of `account`'s org.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DelegatedRead {
    /// The org's admin or reader.
    pub reader: Address,
    /// The member read.
    pub account: Address,
}

/// Runs `f` with the `denied` reads refused, returning its output and the delegated reads granted.
/// For simulations at an earlier block only. Calls must not nest.
pub fn audit_reads<R>(
    denied: HashSet<DelegatedRead>,
    f: impl FnOnce() -> R,
) -> (R, HashSet<DelegatedRead>) {
    let guard = AuditGuard::start(denied);
    let output = f();
    (output, guard.finish())
}

/// Whether an allowed `read` proceeds: false if denied, else recorded as granted.
pub(super) fn admit(read: DelegatedRead) -> bool {
    AUDIT.with_borrow_mut(|audit| match audit {
        None => true,
        Some(audit) if audit.denied.contains(&read) => false,
        Some(audit) => {
            audit.granted.insert(read);
            true
        }
    })
}

/// State of an [`audit_reads`] call.
struct Audit {
    denied: HashSet<DelegatedRead>,
    granted: HashSet<DelegatedRead>,
}

/// This thread's [`Audit`] while alive. Clears it on drop, so a panic leaves none behind.
struct AuditGuard;

impl AuditGuard {
    fn start(denied: HashSet<DelegatedRead>) -> Self {
        AUDIT.with_borrow_mut(|audit| {
            debug_assert!(audit.is_none(), "`audit_reads` calls must not nest");
            *audit = Some(Audit {
                denied,
                granted: Default::default(),
            });
        });
        Self
    }

    /// Ends the audit, returning the reads it granted.
    fn finish(self) -> HashSet<DelegatedRead> {
        AUDIT.take().expect("set until the guard drops").granted
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        AUDIT.set(None);
    }
}
