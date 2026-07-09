//! JSONL outbox sink.
//!
//! The sink appends to `<tempo datadir>/monitor-outbox.jsonl` in the `tempo-monitor` binary.
//! It writes one newline-terminated JSON object and flushes before returning a delivery record.

use crate::store::{DeliveryRecord, OutboxDeliveryResult, OutboxRow, OutboxSink};
use alloy_primitives::keccak256;
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    future::Future,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const JSONL_SINK_NAME: &str = "jsonl";
const JSONL_SCHEMA: &str = "tempo.monitor.outbox.v1";

/// File sink that appends one flushed JSON object per delivered outbox row.
#[derive(Debug)]
pub struct JsonlOutboxSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl JsonlOutboxSink {
    /// Open or create the JSONL file, creating parent directories if needed.
    pub fn open(path: impl AsRef<Path>) -> OutboxDeliveryResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Return the configured JSONL path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_line(&self, json: &[u8]) -> OutboxDeliveryResult<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|err| std::io::Error::other(format!("jsonl sink mutex poisoned: {err}")))?;
        writer.write_all(json)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }
}

impl OutboxSink for JsonlOutboxSink {
    fn deliver<'a>(
        &'a self,
        row: &'a OutboxRow,
    ) -> Pin<Box<dyn Future<Output = OutboxDeliveryResult<DeliveryRecord>> + Send + 'a>> {
        Box::pin(async move {
            let event_digest = event_digest(row)?;
            let delivered_at_unix_ms = unix_ms()?;
            let receipt = idempotency_key(row, &event_digest);
            let json = serde_json::to_vec(&JsonlOutboxLine {
                schema: JSONL_SCHEMA,
                idempotency_key: receipt.clone(),
                sequence: row.sequence,
                block: JsonlBlockRef {
                    number: row.block.number,
                    hash: row.block.hash,
                },
                event_digest,
                event: &row.event,
                delivered_at_unix_ms,
            })?;
            self.write_line(&json)?;
            Ok(DeliveryRecord {
                delivered_at_unix_ms,
                sink: JSONL_SINK_NAME.into(),
                receipt,
            })
        })
    }
}

#[derive(Serialize)]
struct JsonlOutboxLine<'a> {
    schema: &'static str,
    idempotency_key: String,
    sequence: u64,
    block: JsonlBlockRef,
    event_digest: String,
    event: &'a crate::store::OutboxEvent,
    delivered_at_unix_ms: u64,
}

#[derive(Serialize)]
struct JsonlBlockRef {
    number: u64,
    hash: alloy_primitives::B256,
}

fn unix_ms() -> OutboxDeliveryResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn event_digest(row: &OutboxRow) -> OutboxDeliveryResult<String> {
    Ok(format!("{}", keccak256(serde_json::to_vec(&row.event)?)))
}

fn idempotency_key(row: &OutboxRow, event_digest: &str) -> String {
    format!("tempo-monitor:{}:{event_digest}", row.sequence)
}
