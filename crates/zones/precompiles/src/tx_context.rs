//! Transaction execution context for authenticated withdrawals.
//!
//! The zone outbox needs the real hash, sender, and effective fee payer of the currently executing
//! user transaction. The Zone EVM publishes them into a thread-local context before EVM execution
//! for the native outbox to read.

use alloy_primitives::{Address, B256};

/// Identity of the currently executing user transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionContext {
    /// Transaction hash.
    pub tx_hash: B256,
    /// Transaction sender (`tx.origin`).
    pub origin: Address,
    /// Effective fee payer: the sponsor when one signed the transaction, otherwise the sender.
    pub fee_payer: Address,
}

impl TransactionContext {
    /// Whether a fee payer other than the sender pays for this transaction.
    pub(crate) fn is_sponsored(&self) -> bool {
        self.fee_payer != self.origin
    }
}

#[cfg(feature = "std")]
std::thread_local! {
    static CURRENT_TRANSACTION: core::cell::RefCell<Option<TransactionContext>> =
        const { core::cell::RefCell::new(None) };
}

/// Guard that clears the current transaction context when dropped.
#[cfg(feature = "std")]
pub struct TransactionContextGuard;

#[cfg(feature = "std")]
impl Drop for TransactionContextGuard {
    fn drop(&mut self) {
        CURRENT_TRANSACTION.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Publish the current transaction context for EVM execution.
#[cfg(feature = "std")]
pub fn set_current_transaction(context: TransactionContext) -> TransactionContextGuard {
    CURRENT_TRANSACTION.with(|slot| *slot.borrow_mut() = Some(context));
    TransactionContextGuard
}

/// Return the current transaction context, when published by the EVM.
#[cfg(feature = "std")]
pub(crate) fn current_transaction() -> Option<TransactionContext> {
    CURRENT_TRANSACTION.with(|slot| *slot.borrow())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_and_clears_current_transaction() {
        let context = TransactionContext {
            tx_hash: B256::repeat_byte(0x42),
            origin: Address::repeat_byte(0x12),
            fee_payer: Address::repeat_byte(0x24),
        };

        let guard = set_current_transaction(context);
        assert_eq!(current_transaction(), Some(context));

        drop(guard);
        assert_eq!(current_transaction(), None, "guard must clear the context");
    }
}
