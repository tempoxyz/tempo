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

#[derive(Debug)]
pub struct JsonlOutboxSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl JsonlOutboxSink {
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

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl OutboxSink for JsonlOutboxSink {
    fn deliver<'a>(
        &'a self,
        row: &'a OutboxRow,
    ) -> Pin<Box<dyn Future<Output = OutboxDeliveryResult<DeliveryRecord>> + Send + 'a>> {
        Box::pin(async move {
            let delivered_at_unix_ms = unix_ms()?;
            let receipt = idempotency_key(row)?;
            let line = JsonlOutboxLine {
                schema: JSONL_SCHEMA,
                idempotency_key: receipt.clone(),
                sequence: row.sequence,
                block: JsonlBlockRef {
                    number: row.block.number,
                    hash: row.block.hash,
                },
                event_digest: event_digest(row)?,
                event: &row.event,
                delivered_at_unix_ms,
            };
            let json = serde_json::to_vec(&line)?;
            {
                let mut writer = self.writer.lock().expect("jsonl sink mutex poisoned");
                writer.write_all(&json)?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
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

fn idempotency_key(row: &OutboxRow) -> OutboxDeliveryResult<String> {
    Ok(format!(
        "tempo-monitor:{}:{}",
        row.sequence,
        event_digest(row)?
    ))
}
