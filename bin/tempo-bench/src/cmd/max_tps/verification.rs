use alloy::primitives::TxHash;
use alloy::providers::Provider;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Statistics tracked by the verification service
#[derive(Debug, Clone)]
pub struct VerificationStats {
    /// Total transactions sent to verification
    pub total_sent: Arc<AtomicU64>,
    /// Transactions confirmed with receipts
    pub confirmed: Arc<AtomicU64>,
    /// Transactions still pending verification
    pub pending: Arc<AtomicU64>,
    /// Transactions that failed verification after max attempts
    pub failed: Arc<AtomicU64>,
}

impl VerificationStats {
    pub fn new() -> Self {
        Self {
            total_sent: Arc::new(AtomicU64::new(0)),
            confirmed: Arc::new(AtomicU64::new(0)),
            pending: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn total_sent(&self) -> u64 {
        self.total_sent.load(Ordering::Relaxed)
    }

    pub fn confirmed(&self) -> u64 {
        self.confirmed.load(Ordering::Relaxed)
    }

    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// Configuration for the verification service
pub struct VerificationConfig {
    /// Maximum number of verification attempts before giving up
    pub max_attempts: u32,
    /// Delay between verification attempts (in milliseconds)
    pub retry_delay_ms: u64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self { max_attempts: 20, retry_delay_ms: 500 }
    }
}

/// A transaction pending verification
#[derive(Debug, Clone)]
struct PendingTx {
    hash: TxHash,
    attempts: u32,
}

/// Transaction verification service that runs in the background
pub struct VerificationService<P> {
    provider: P,
    config: VerificationConfig,
    stats: VerificationStats,
    rx: mpsc::UnboundedReceiver<TxHash>,
    queue: VecDeque<PendingTx>,
}

impl<P> VerificationService<P>
where
    P: Provider + Clone + 'static,
{
    /// Create a new verification service
    pub fn new(
        provider: P,
        config: VerificationConfig,
        stats: VerificationStats,
        rx: mpsc::UnboundedReceiver<TxHash>,
    ) -> Self {
        Self { provider, config, stats, rx, queue: VecDeque::new() }
    }

    /// Run the verification service loop
    pub async fn run(mut self) {
        info!("Starting transaction verification service");
        let mut last_log = std::time::Instant::now();

        loop {
            // Process incoming tx hashes (non-blocking)
            while let Ok(tx_hash) = self.rx.try_recv() {
                self.stats.total_sent.fetch_add(1, Ordering::Relaxed);
                self.stats.pending.fetch_add(1, Ordering::Relaxed);

                self.queue.push_back(PendingTx { hash: tx_hash, attempts: 0 });
            }

            // Check if we have transactions to verify
            if self.queue.is_empty() {
                // Check if sender has closed the channel (benchmark finished)
                if self.rx.is_closed() {
                    info!("Verification channel closed, shutting down");
                    break;
                }

                // Wait a bit before checking again
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Verify the next transaction in the queue
            if let Some(mut pending_tx) = self.queue.pop_front() {
                pending_tx.attempts += 1;

                // Try to get the receipt with a quick timeout (10ms)
                let receipt_result = timeout(
                    Duration::from_millis(10),
                    self.provider.get_transaction_receipt(pending_tx.hash),
                )
                .await;

                match receipt_result {
                    Ok(Ok(Some(receipt))) => {
                        // Transaction was mined!
                        self.stats.confirmed.fetch_add(1, Ordering::Relaxed);
                        self.stats.pending.fetch_sub(1, Ordering::Relaxed);

                        debug!(
                            "Transaction {} confirmed in block {:?} (attempts: {})",
                            pending_tx.hash, receipt.block_number, pending_tx.attempts
                        );
                    }
                    Ok(Ok(None)) => {
                        // No receipt yet - check if we should retry
                        if pending_tx.attempts >= self.config.max_attempts {
                            // Give up on this transaction
                            self.stats.failed.fetch_add(1, Ordering::Relaxed);
                            self.stats.pending.fetch_sub(1, Ordering::Relaxed);

                            warn!(
                                "Transaction {} not found after {} attempts, marking as failed",
                                pending_tx.hash, pending_tx.attempts
                            );
                        } else {
                            // Push back to the end of the queue for retry
                            self.queue.push_back(pending_tx);
                        }
                    }
                    Ok(Err(e)) => {
                        // Error fetching receipt - permanent failure, don't retry
                        error!(
                            "Error fetching receipt for {}: {} (attempt {}), marking as failed",
                            pending_tx.hash, e, pending_tx.attempts
                        );
                        self.stats.failed.fetch_add(1, Ordering::Relaxed);
                        self.stats.pending.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        // Timeout - keep retrying indefinitely
                        debug!(
                            "Receipt fetch timed out for {} (attempt {}), retrying",
                            pending_tx.hash, pending_tx.attempts
                        );
                        self.queue.push_back(pending_tx);
                    }
                }
            }

            // Log stats periodically
            if last_log.elapsed() >= Duration::from_secs(5) {
                info!(
                    "Verification stats - Total: {}, Confirmed: {}, Pending: {}, Failed: {}",
                    self.stats.total_sent(),
                    self.stats.confirmed(),
                    self.stats.pending(),
                    self.stats.failed()
                );
                last_log = std::time::Instant::now();
            }

            // Small delay between verification attempts
            tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
        }

        // Final stats
        info!(
            "Verification service shutdown - Final stats: Total: {}, Confirmed: {}, Pending: {}, Failed: {}",
            self.stats.total_sent(),
            self.stats.confirmed(),
            self.stats.pending(),
            self.stats.failed()
        );
    }
}

/// Create a verification service channel and spawn the service in a blocking task
pub fn spawn_verification_service<P>(
    provider: P,
    config: VerificationConfig,
    stats: VerificationStats,
) -> (mpsc::UnboundedSender<TxHash>, tokio::task::JoinHandle<()>)
where
    P: Provider + Clone + Send + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();

    let service = VerificationService::new(provider, config, stats, rx);
    let handle = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime for verification");

        rt.block_on(async move {
            service.run().await;
        });
    });

    (tx, handle)
}
