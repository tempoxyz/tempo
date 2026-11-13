//! Per-authority transaction counts for the 2D pool's per-authority limit.

use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{
    Address,
    map::{AddressMap, hash_map},
};

/// Number of pooled transactions per authority; see [`TempoPooledTransaction::authorities`].
///
/// A transaction counts once against each distinct account it names. Entries are removed when
/// their count reaches zero, so the map is bounded by the pool's transaction count.
#[derive(Debug, Default)]
pub(crate) struct AuthorityCounts(AddressMap<usize>);

impl AuthorityCounts {
    /// Returns the number of counted transactions that name `authority`.
    pub(crate) fn get(&self, authority: &Address) -> usize {
        self.0.get(authority).copied().unwrap_or_default()
    }

    /// Returns an authority of `transaction` that already has `max` counted transactions.
    pub(crate) fn at_capacity(
        &self,
        max: usize,
        transaction: &TempoPooledTransaction,
    ) -> Option<Address> {
        distinct_authorities(transaction).find(|authority| self.get(authority) >= max)
    }

    /// Counts `transaction` against each of its authorities.
    pub(crate) fn add(&mut self, transaction: &TempoPooledTransaction) {
        for authority in distinct_authorities(transaction) {
            *self.0.entry(authority).or_default() += 1;
        }
    }

    /// Reverts [`Self::add`].
    pub(crate) fn remove(&mut self, transaction: &TempoPooledTransaction) {
        for authority in distinct_authorities(transaction) {
            if let hash_map::Entry::Occupied(mut entry) = self.0.entry(authority) {
                *entry.get_mut() -= 1;
                if *entry.get() == 0 {
                    entry.remove();
                }
            }
        }
    }
}

/// Yields each distinct authority of `transaction` once.
fn distinct_authorities(transaction: &TempoPooledTransaction) -> impl Iterator<Item = Address> {
    let authorities = transaction.authorities();
    (0..authorities.len()).filter_map(move |index| {
        authorities[index].filter(|authority| !authorities[..index].contains(&Some(*authority)))
    })
}
