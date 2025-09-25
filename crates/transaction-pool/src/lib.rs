//! Tempo transaction implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::Transaction;
use alloy_primitives::U256;
use reth_transaction_pool::{
    Pool, Priority, TransactionOrdering, TransactionValidationTaskExecutor,
    blobstore::DiskFileBlobStore,
};

use crate::{
    transaction::TempoPooledTransaction,
    validator::TempoTransactionValidator,
};

pub mod transaction;
pub mod validator;

pub type TempoTransactionPool<Client, S = DiskFileBlobStore> = Pool<
    TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
    TempoPriorityOrdering,
    S,
>;

/// Priority ordering for the Tempo transaction pool.
///
/// The transactions are ordered by non payment txs first, followed by their coinbase tip.
/// The higher the coinbase tip is, the higher the priority of the transaction.
#[derive(Debug, Default, Clone)]
pub struct TempoPriorityOrdering;

/// Tempo priority ordering attributes
///
/// The ordering of fields here is important.
#[derive(Debug, Default, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct TempoPriority {
    is_payment: bool,
    effective_tip_per_gas: Option<U256>,
}

impl TransactionOrdering for TempoPriorityOrdering {
    type PriorityValue = TempoPriority;
    type Transaction = TempoPooledTransaction;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        let effective_tip_per_gas = transaction.effective_tip_per_gas(base_fee).map(U256::from);

        Some(TempoPriority {
            is_payment: transaction.is_payment(),
            effective_tip_per_gas,
        })
        .into()
    }
}

#[cfg(test)]
mod test {
    use alloy_primitives::uint;

    use super::*;

    #[test]
    fn test_non_payment_priority() {
        let payment = TempoPriority {
            is_payment: true,
            effective_tip_per_gas: Some(U256::from(100u64)),
        };

        let non_payment = TempoPriority {
            is_payment: false,
            effective_tip_per_gas: Some(U256::from(10000u64)),
        };

        assert!(non_payment > payment);
    }

    #[test]
    fn test_priority_fee() {
        let high_fee = Some(uint!(1000_U256));
        let low_fee = Some(uint!(10_U256));

        let payment_high_fee = TempoPriority {
            is_payment: true,
            effective_tip_per_gas: high_fee,
        };

        let payment_low_fee = TempoPriority {
            is_payment: true,
            effective_tip_per_gas: low_fee,
        };

        let non_payment_high_fee = TempoPriority {
            is_payment: false,
            effective_tip_per_gas: high_fee,
        };
        let non_payment_low_fee = TempoPriority {
            is_payment: false,
            effective_tip_per_gas: low_fee,
        };

        assert!(payment_high_fee > payment_low_fee);
        assert!(non_payment_high_fee > non_payment_low_fee);
    }
}
