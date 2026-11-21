//! Deciding the delegated reads `ZoneIdentity` answers while simulating at an earlier block.

use core::cell::RefCell;

use alloy_primitives::{
    Address,
    map::{HashMap, HashSet},
};

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

/// Runs `f` with delegated reads answered by `decided`, and allowed where it has no answer, also
/// returning those undecided reads. For simulations at an earlier block only. Calls must not nest.
pub fn audit_reads<R>(
    decided: HashMap<DelegatedRead, bool>,
    f: impl FnOnce() -> R,
) -> (R, HashSet<DelegatedRead>) {
    let guard = AuditGuard::start(decided);
    (f(), guard.finish())
}

/// Whether `read` proceeds: its decided answer, else true, recording it as undecided.
pub(super) fn admit(read: DelegatedRead, allowed: bool) -> bool {
    AUDIT.with_borrow_mut(|audit| match audit {
        // Reading one's own account is not delegated.
        Some(audit) if read.reader != read.account => {
            // Lets one run reach every read. Its output stands only if latest allows them too.
            audit.decided.get(&read).copied().unwrap_or_else(|| {
                audit.undecided.insert(read);
                true
            })
        }
        _ => allowed,
    })
}

/// State of an [`audit_reads`] call.
struct Audit {
    decided: HashMap<DelegatedRead, bool>,
    undecided: HashSet<DelegatedRead>,
}

/// This thread's [`Audit`] while alive. Clears it on drop, so a panic leaves none behind.
struct AuditGuard;

impl AuditGuard {
    fn start(decided: HashMap<DelegatedRead, bool>) -> Self {
        AUDIT.with_borrow_mut(|audit| {
            debug_assert!(audit.is_none(), "`audit_reads` calls must not nest");
            *audit = Some(Audit {
                decided,
                undecided: Default::default(),
            });
        });
        Self
    }

    fn finish(self) -> HashSet<DelegatedRead> {
        AUDIT.take().expect("set until the guard drops").undecided
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        AUDIT.set(None);
    }
}
