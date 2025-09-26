//! Tempo transaction implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::Transaction;
use reth_transaction_pool::{
    Pool, Priority, TransactionOrdering, TransactionValidationTaskExecutor,
    blobstore::DiskFileBlobStore,
};

use crate::{transaction::TempoPooledTransaction, validator::TempoTransactionValidator};

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
    non_payment: bool,
    effective_tip_per_gas: u128,
}

impl TransactionOrdering for TempoPriorityOrdering {
    type PriorityValue = TempoPriority;
    type Transaction = TempoPooledTransaction;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        if let Some(effective_tip_per_gas) = transaction.effective_tip_per_gas(base_fee) {
            Some(TempoPriority {
                non_payment: !transaction.is_payment(),
                effective_tip_per_gas,
            })
            .into()
        } else {
            Priority::None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_non_payment_priority() {
        let payment = TempoPriority {
            non_payment: false,
            effective_tip_per_gas: 100,
        };

        let non_payment = TempoPriority {
            non_payment: true,
            effective_tip_per_gas: 10000,
        };

        assert!(non_payment > payment);
    }

    #[test]
    fn test_priority_fee() {
        let high_fee = 10000;
        let low_fee = 10;

        let payment_high_fee = TempoPriority {
            non_payment: false,
            effective_tip_per_gas: high_fee,
        };

        let payment_low_fee = TempoPriority {
            non_payment: false,
            effective_tip_per_gas: low_fee,
        };

        let non_payment_high_fee = TempoPriority {
            non_payment: true,
            effective_tip_per_gas: high_fee,
        };
        let non_payment_low_fee = TempoPriority {
            non_payment: true,
            effective_tip_per_gas: low_fee,
        };

        assert!(payment_high_fee > payment_low_fee);
        assert!(non_payment_high_fee > non_payment_low_fee);
    }
}
