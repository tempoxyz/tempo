//! At-least-once outbox delivery worker.
//!
//! Delivery is intentionally independent from `monitor_head`: rows are emitted only after they
//! are durable and are marked delivered only after the sink has acknowledged delivery.

mod jsonl;
pub use jsonl::JsonlOutboxSink;

use crate::store::{DeliveryRecord, MonitorStore, OutboxRow, Result as StoreResult};
use std::{future::Future, pin::Pin, time::Duration};
use thiserror::Error;
use tokio::time::sleep;
use tracing::error;

pub type OutboxDeliveryResult<T> = std::result::Result<T, OutboxDeliveryError>;

#[derive(Debug, Error)]
pub enum OutboxDeliveryError {
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("system clock is before unix epoch: {0}")]
    Clock(#[from] std::time::SystemTimeError),
}

pub trait OutboxSink {
    fn deliver<'a>(
        &'a self,
        row: &'a OutboxRow,
    ) -> Pin<Box<dyn Future<Output = OutboxDeliveryResult<DeliveryRecord>> + Send + 'a>>;
}

#[derive(Clone, Debug)]
pub struct OutboxWorkerConfig {
    pub enabled: bool,
    pub batch_size: usize,
    pub poll_interval: Duration,
}

impl Default for OutboxWorkerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size: 100,
            poll_interval: Duration::from_secs(5),
        }
    }
}

pub struct OutboxWorker<S, K> {
    store: S,
    sink: K,
    config: OutboxWorkerConfig,
}

impl<S, K> OutboxWorker<S, K> {
    pub fn new(store: S, sink: K, config: OutboxWorkerConfig) -> Self {
        Self {
            store,
            sink,
            config,
        }
    }
}

impl<S, K> OutboxWorker<S, K>
where
    S: MonitorStore,
    K: OutboxSink,
{
    pub async fn run_forever(&self) -> StoreResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        loop {
            let delivered = self.tick().await?;
            if delivered == 0 {
                sleep(self.config.poll_interval).await;
            }
        }
    }

    pub async fn tick(&self) -> StoreResult<usize> {
        if !self.config.enabled || self.config.batch_size == 0 {
            return Ok(0);
        }

        let rows = self.store.pending_outbox(self.config.batch_size)?;
        let mut delivered = 0;
        for row in rows {
            match self.sink.deliver(&row).await {
                Ok(record) => {
                    self.store.mark_outbox_delivered(row.sequence, record)?;
                    delivered += 1;
                }
                Err(err) => {
                    error!(
                        sequence = row.sequence,
                        block_number = row.block.number,
                        block_hash = %row.block.hash,
                        error = %err,
                        "outbox delivery failed; row remains pending"
                    );
                }
            }
        }
        Ok(delivered)
    }
}
