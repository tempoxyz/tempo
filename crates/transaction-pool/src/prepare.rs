//! Additional tasks for preparing executable transactions.

use crate::transaction::TempoPooledTransaction;
use rayon::ThreadPoolBuilder;
use reth_transaction_pool::NewTransactionEvent;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::Receiver;

/// Minimum batch size during low throughput before processing.
const MIN_BATCH_SIZE: usize = 128;

/// Maximum batch size to collect in a single recv_many call.
const MAX_BATCH_SIZE: usize = 4096;

/// Threshold in transactions per second above which we use eager batching.
const HIGH_THROUGHPUT_THRESHOLD: f64 = 256.0;

/// Time window for measuring transaction rate.
const RATE_MEASUREMENT_WINDOW: Duration = Duration::from_secs(1);

/// Prepares pending transactions by pre-computing their tx env..
///
/// This function receives transactions from a channel and batches them for efficient
/// CPU-bound processing. Pre-computing the tx environment avoids the cost during
/// payload building.
///
/// Batching is adaptive based on measured transaction rate:
/// - High throughput (>256 tx/s): Process immediately with whatever is available (1-4096 txs)
/// - Low throughput (≤256 tx/s): Wait to accumulate 128+ transactions before processing
/// - This ensures low latency during bursts and efficient batching during normal load
pub async fn prepare_pooled_transactions(
    mut transactions: Receiver<NewTransactionEvent<TempoPooledTransaction>>,
) {
    // Create dedicated thread pool for transaction preparation
    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(prepare_pool_size())
            .thread_name(|i| format!("tempo-tx-prepare-{i}"))
            .build()
            .expect("failed to create rayon thread pool"),
    );

    let mut batch = Vec::with_capacity(MIN_BATCH_SIZE);
    let mut rate_tracker = RateTracker::new();

    loop {
        let is_high_throughput = rate_tracker.is_high_throughput();

        if is_high_throughput {
            // High throughput: grab what's available and process immediately
            let count = transactions.recv_many(&mut batch, MAX_BATCH_SIZE).await;
            if count == 0 {
                // Channel closed
                return;
            }
            rate_tracker.record(count);
        } else {
            // Low throughput: wait to accumulate MIN_BATCH_SIZE before processing
            while batch.len() < MIN_BATCH_SIZE {
                let count = transactions.recv_many(&mut batch, MAX_BATCH_SIZE).await;
                if count == 0 {
                    // Channel closed
                    return;
                }
                rate_tracker.record(count);
            }
        }

        // Process batch on dedicated rayon thread pool (fire and forget)
        let batch_size = batch.len();
        let batch_to_process = std::mem::take(&mut batch);
        pool.spawn(move || {
            use rayon::prelude::*;
            batch_to_process.par_iter().for_each(|tx| {
                tx.transaction.transaction.prepare_tx_env();
            });
        });

        // Allocate capacity based on recent batch size, clamped to reasonable bounds
        let next_capacity = batch_size.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE);
        batch = Vec::with_capacity(next_capacity);
    }
}

/// Number of threads in the dedicated rayon pool for transaction preparation.
///
/// Set to half of available CPUs to leave resources for other tasks.
fn prepare_pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 2).max(1))
        .unwrap_or(1)
}

/// Tracks transaction rate over a sliding window.
struct RateTracker {
    /// Transactions received in the current measurement window.
    count: usize,
    /// Start of the current measurement window.
    window_start: Instant,
    /// Measured transactions per second.
    rate: f64,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            rate: 0.0,
        }
    }

    /// Record received transactions and update the rate measurement.
    fn record(&mut self, count: usize) {
        self.count += count;
        let elapsed = self.window_start.elapsed();

        // Update rate measurement if window elapsed
        if elapsed >= RATE_MEASUREMENT_WINDOW {
            self.rate = self.count as f64 / elapsed.as_secs_f64();
            self.count = 0;
            self.window_start = Instant::now();
        }
    }

    /// Returns true if we're in high throughput mode.
    fn is_high_throughput(&self) -> bool {
        self.rate > HIGH_THROUGHPUT_THRESHOLD
    }
}
