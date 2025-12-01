//! Transaction pool metrics for the AA2D pool.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge},
};

/// AA2D pool metrics
#[derive(Metrics, Clone)]
#[metrics(scope = "transaction_pool.aa_2d")]
pub struct AA2dPoolMetrics {
    /// Total number of transactions in the AA2D pool
    pub total_transactions: Gauge,

    /// Number of pending (executable) transactions in the AA2D pool
    pub pending_transactions: Gauge,

    /// Number of queued (non-executable) transactions in the AA2D pool
    pub queued_transactions: Gauge,

    /// Number of unique addresses with tracked nonce keys
    pub tracked_addresses: Gauge,

    /// Total number of tracked (address, nonce_key) pairs
    pub tracked_nonce_keys: Gauge,

    /// Number of transactions inserted into the AA2D pool
    pub inserted_transactions: Counter,

    /// Number of transactions removed from the AA2D pool
    pub removed_transactions: Counter,

    /// Number of transactions promoted from queued to pending
    pub promoted_transactions: Counter,

    /// Number of transactions demoted from pending to queued
    pub demoted_transactions: Counter,
}

impl AA2dPoolMetrics {
    /// Update the transaction count metrics
    #[inline]
    pub fn set_transaction_counts(&self, total: usize, pending: usize, queued: usize) {
        self.total_transactions.set(total as f64);
        self.pending_transactions.set(pending as f64);
        self.queued_transactions.set(queued as f64);
    }

    /// Update the nonce key tracking metrics
    #[inline]
    pub fn inc_nonce_key_count(&self, nonce_keys: usize) {
        self.tracked_nonce_keys.increment(nonce_keys as f64);
    }
    /// Update the nonce key tracking metrics
    #[inline]
    pub fn set_tracked_address_count(&self, addresses: usize) {
        self.tracked_addresses.set(addresses as f64);
    }

    /// Increment the inserted transactions counter
    #[inline]
    pub fn inc_inserted(&self) {
        self.inserted_transactions.increment(1);
    }

    /// Increment the removed transactions counter
    #[inline]
    pub fn inc_removed(&self, count: usize) {
        self.removed_transactions.increment(count as u64);
    }

    /// Increment the promoted transactions counter
    #[inline]
    pub fn inc_promoted(&self, count: usize) {
        self.promoted_transactions.increment(count as u64);
    }

    /// Increment the demoted transactions counter
    #[inline]
    pub fn inc_demoted(&self, count: usize) {
        self.demoted_transactions.increment(count as u64);
    }
}
