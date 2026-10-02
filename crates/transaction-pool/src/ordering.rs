//! Transaction ordering for Tempo's pool.

use reth_transaction_pool::{PoolTransaction, Priority, TransactionOrdering};
use std::marker::PhantomData;

/// Orders transactions by effective coinbase tip using a compact priority value.
#[derive(Debug)]
pub struct TempoTipOrdering<T>(PhantomData<T>);

impl<T> TransactionOrdering for TempoTipOrdering<T>
where
    T: PoolTransaction + 'static,
{
    type PriorityValue = u64;
    type Transaction = T;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        transaction
            .effective_tip_per_gas(base_fee)
            .map(|priority| priority.try_into().unwrap_or(u64::MAX))
            .into()
    }
}

impl<T> Default for TempoTipOrdering<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> Clone for TempoTipOrdering<T> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{TempoTipOrdering, TransactionOrdering};
    use crate::test_utils::TxBuilder;

    #[test]
    fn priority_saturates_to_u64_max() {
        let tx = TxBuilder::default()
            .max_fee(u128::MAX)
            .max_priority_fee(u128::MAX)
            .build();

        assert_eq!(
            TempoTipOrdering::default().priority(&tx, 0),
            reth_transaction_pool::Priority::Value(u64::MAX)
        );
    }
}
