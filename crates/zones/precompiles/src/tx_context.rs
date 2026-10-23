//! Transaction execution context for authenticated withdrawals.
//!
//! The Zone EVM publishes the real hash and effective fee payer before user transaction execution.
//! Withdrawal attempts are tracked here, outside the EVM journal, so caught call-frame reverts
//! cannot restore the transaction's single withdrawal allowance.

use std::{cell::RefCell, thread_local};

use alloy_primitives::{Address, B256};
use tempo_contracts::zones::ZoneOutboxError;
use tempo_precompiles::storage::StorageCtx;

use crate::ZoneResult;

thread_local! {
    static CURRENT_TRANSACTION: RefCell<Option<TransactionContext>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy)]
struct TransactionContext {
    tx_hash: B256,
    fee_payer: Address,
    withdrawal_attempted: bool,
}

/// Guard that clears the current transaction context when dropped.
pub struct TransactionContextGuard;

impl Drop for TransactionContextGuard {
    fn drop(&mut self) {
        CURRENT_TRANSACTION.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Publish the current transaction hash and fee payer with a fresh withdrawal allowance.
pub fn set_current_transaction(tx_hash: B256, fee_payer: Address) -> TransactionContextGuard {
    CURRENT_TRANSACTION.with(|slot| {
        *slot.borrow_mut() = Some(TransactionContext {
            tx_hash,
            fee_payer,
            withdrawal_attempted: false,
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

/// From T13, consume one withdrawal attempt across success and all call-frame reverts.
pub(crate) fn consume_withdrawal_attempt() -> ZoneResult<()> {
    if !StorageCtx.spec().is_t13() {
        return Ok(());
    }
    CURRENT_TRANSACTION.with(|slot| {
        let mut slot = slot.borrow_mut();
        let context = slot
            .as_mut()
            .filter(|context| !context.tx_hash.is_zero())
            .ok_or_else(ZoneOutboxError::invalid_current_tx_hash)?;
        if context.withdrawal_attempted {
            return Err(ZoneOutboxError::withdrawal_already_attempted().into());
        }
        context.withdrawal_attempted = true;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn withdrawal_allowance_requires_context_and_resets_for_each_execution() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                consume_withdrawal_attempt(),
                Err(ZoneOutboxError::invalid_current_tx_hash().into())
            );
            // Simulations may reuse the same synthetic hash; each execution still gets an allowance.
            for _ in 0..2 {
                let guard = set_current_transaction(B256::repeat_byte(0xff), Address::ZERO);
                assert_eq!(
                    current_transaction(),
                    Some((B256::repeat_byte(0xff), Address::ZERO))
                );
                assert_eq!(consume_withdrawal_attempt(), Ok(()));
                assert_eq!(
                    consume_withdrawal_attempt(),
                    Err(ZoneOutboxError::withdrawal_already_attempted().into())
                );
                drop(guard);
                assert_eq!(current_transaction(), None);
            }
            let _guard = set_current_transaction(B256::ZERO, Address::ZERO);
            assert_eq!(
                consume_withdrawal_attempt(),
                Err(ZoneOutboxError::invalid_current_tx_hash().into())
            );
        });
    }

    #[test]
    fn withdrawal_allowance_is_not_consumed_before_t13() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            assert_eq!(consume_withdrawal_attempt(), Ok(()));
            let _guard = set_current_transaction(B256::repeat_byte(0xff), Address::ZERO);
            assert_eq!(consume_withdrawal_attempt(), Ok(()));
            assert_eq!(consume_withdrawal_attempt(), Ok(()));
        });
    }
}
