//! Transaction execution context for authenticated withdrawals and L1 reads.
//!
//! The zone outbox needs the real hash and effective fee payer of the currently executing user
//! transaction, and the L1 state provider needs to know why it is executing. The Zone EVM
//! publishes these into a thread-local context before EVM execution.

use std::{cell::RefCell, thread_local};

use alloy_primitives::{Address, B256};

thread_local! {
    static CURRENT_TRANSACTION: RefCell<Option<TransactionContext>> = const { RefCell::new(None) };
}

/// Why the Zone EVM is executing the current transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionOrigin {
    /// Block building or validation, whose L1 reads must eventually succeed.
    Canonical,
    /// Cache prewarming, whose execution output is discarded.
    Prewarming,
    /// A non-committing RPC simulation.
    Simulation,
}

#[derive(Clone, Copy)]
struct TransactionContext {
    tx_hash: B256,
    fee_payer: Address,
    origin: ExecutionOrigin,
}

/// Guard that clears the current transaction context when dropped.
pub struct TransactionContextGuard;

impl Drop for TransactionContextGuard {
    fn drop(&mut self) {
        CURRENT_TRANSACTION.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Publish the current transaction hash, effective fee payer, and execution origin for EVM
/// execution.
pub fn set_current_transaction(
    tx_hash: B256,
    fee_payer: Address,
    origin: ExecutionOrigin,
) -> TransactionContextGuard {
    CURRENT_TRANSACTION.with(|slot| {
        *slot.borrow_mut() = Some(TransactionContext {
            tx_hash,
            fee_payer,
            origin,
        });
    });
    TransactionContextGuard
}

/// Return the current transaction hash and effective fee payer, when published by the EVM.
pub(crate) fn current_transaction() -> Option<(B256, Address)> {
    CURRENT_TRANSACTION.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|context| (context.tx_hash, context.fee_payer))
    })
}

/// Returns why the EVM is executing a transaction on this thread.
///
/// [`ExecutionOrigin::Canonical`] outside EVM execution and for system transactions, so a reader
/// on any other thread gets the canonical behavior.
pub fn execution_origin() -> ExecutionOrigin {
    CURRENT_TRANSACTION.with(|slot| {
        slot.borrow()
            .map_or(ExecutionOrigin::Canonical, |context| context.origin)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_and_clears_current_transaction() {
        let tx_hash = B256::repeat_byte(0x42);
        let fee_payer = Address::repeat_byte(0x24);

        let guard = set_current_transaction(tx_hash, fee_payer, ExecutionOrigin::Canonical);
        assert_eq!(current_transaction(), Some((tx_hash, fee_payer)));
        assert_eq!(execution_origin(), ExecutionOrigin::Canonical);
        drop(guard);
        assert_eq!(current_transaction(), None, "guard must clear the context");

        let guard = set_current_transaction(tx_hash, fee_payer, ExecutionOrigin::Simulation);
        assert_eq!(execution_origin(), ExecutionOrigin::Simulation);
        drop(guard);
        assert_eq!(
            execution_origin(),
            ExecutionOrigin::Canonical,
            "guard must clear the origin"
        );
    }
}
