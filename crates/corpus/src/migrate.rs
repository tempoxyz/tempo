//! One-off migration of a corpus written before single-block records: rewrites every block and
//! metadata record of a published range into the current shape, copies its transaction and code
//! records unchanged, and publishes one checkpoint and catalog once everything is written.
//!
//! Needs no archive DB and executes nothing. The source corpus is only read, through its pinned
//! checkpoint, and its blake3 record digests are checked one last time.

use crate::{
    store::{
        self, CONTEXT_KEY, CURSOR_KEY, CaseRecord, Catalog, Context, Cursor, MAX_RECORD_BYTES,
        Record, Store,
    },
    types::{Block, Info, Input, Phases},
};
use alloy_primitives::B256;
use eyre::OptionExt;
use serde::Deserialize;
use slatedb::{
    Db, DbReader, DbReaderMode, WriteBatch,
    config::{CompressionCodec, DbReaderOptions, GarbageCollectorOptions, ScanOptions, Settings},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::task::JoinSet;
use tracing::info;
use wincode::SchemaRead;

/// Blocks each scan task migrates at once.
const SEGMENT_BLOCKS: u64 = 10_000;
const LEGACY_CONTEXT_KEY: &[u8] = b"reth-corpus-context";
const LEGACY_CURSOR_KEY: &[u8] = b"reth-corpus-cursor";

/// Migrates the published blocks in `range` (all of them when `None`) of the corpus at `source`
/// into a new corpus at `dest`, which must not exist yet, reading with `workers` parallel scans. A
/// failed run leaves `dest` claimed but unpublished: migrate into a new prefix instead.
pub async fn migrate(
    source: Store,
    dest: Store,
    range: Option<Range<u64>>,
    workers: usize,
) -> eyre::Result<()> {
    let started = Instant::now();
    let (catalog, _) = source
        .catalog()
        .await?
        .ok_or_eyre("no source corpus catalog")?;
    // A running legacy fill retires the checkpoint this reads, so only a finished corpus migrates.
    eyre::ensure!(
        catalog.complete,
        "source corpus is not complete; its writer may still be running"
    );
    let published = catalog.context.start..catalog.cursor.next;
    let range = range.unwrap_or(published.clone());
    eyre::ensure!(
        !range.is_empty() && range.start >= published.start && range.end <= published.end,
        "migration range outside the published source corpus"
    );
    eyre::ensure!(
        dest.catalog().await?.is_none(),
        "destination corpus already exists"
    );
    let reader = Arc::new(
        DbReader::open(
            source.data(),
            source.objects.clone(),
            DbReaderMode::Checkpoint(
                catalog
                    .checkpoint
                    .as_ref()
                    .ok_or_eyre("source corpus has no published checkpoint")?
                    .parse()?,
            ),
            DbReaderOptions {
                object_store_max_retries: store::SLATEDB_RETRIES,
                ..Default::default()
            },
        )
        .await?,
    );
    let result = run(&reader, &catalog, &dest, range, workers.max(1)).await;
    reader.close().await?;
    let (blocks, legacy_bytes, migrated_bytes) = result?;
    info!(
        blocks,
        legacy_bytes,
        migrated_bytes,
        seconds = started.elapsed().as_secs_f64(),
        "Migrated corpus published"
    );
    Ok(())
}

async fn run(
    reader: &Arc<DbReader>,
    source: &Catalog,
    dest: &Store,
    range: Range<u64>,
    workers: usize,
) -> eyre::Result<(u64, u64, u64)> {
    for (key, expected) in [
        (LEGACY_CONTEXT_KEY, serde_json::to_vec(&source.context)?),
        (LEGACY_CURSOR_KEY, serde_json::to_vec(&source.cursor)?),
    ] {
        let stored = reader
            .get(key)
            .await?
            .ok_or_eyre("source checkpoint has no legacy context/cursor")?;
        eyre::ensure!(
            stored.as_ref() == expected,
            "source checkpoint/catalog context or cursor mismatch"
        );
    }
    let (first, last) = (
        cursor_at(reader, source, range.start).await?,
        cursor_at(reader, source, range.end).await?,
    );
    let context = Context {
        start: range.start,
        end: range.end,
        parent: B256::from(first.parent).to_string(),
        tip: B256::from(last.parent).to_string(),
        first_tx: first.tx,
        end_tx: last.tx,
        ..source.context.clone()
    };
    let mut catalog = Catalog {
        cursor: Cursor::initial(&context)?,
        context,
        checkpoint: None,
        records: Vec::new(),
        complete: false,
        generation: 1,
    };
    let version = dest.publish(&catalog, None).await?;
    let db = Db::builder(dest.data(), dest.objects.clone())
        .with_settings(Settings {
            object_store_max_retries: store::SLATEDB_RETRIES,
            compression_codec: Some(CompressionCodec::Zstd),
            // Compaction rewrites the whole corpus several times: reclaim superseded files as it
            // goes. Nothing reads them, since the only checkpoint is published at the end.
            garbage_collector_options: Some(GarbageCollectorOptions {
                // Boundaries fence stalled writers, and need conditional overwrites local stores lack.
                boundary_files_enabled: false,
                object_store_max_retries: store::SLATEDB_RETRIES,
                ..Default::default()
            }),
            ..Default::default()
        })
        .build()
        .await?;
    let result = async {
        let next = Arc::new(AtomicU64::new(range.start));
        let mut tasks = JoinSet::new();
        for _ in 0..workers {
            let (reader, db, next, source) =
                (reader.clone(), db.clone(), next.clone(), source.clone());
            let end = range.end;
            tasks.spawn(async move {
                let mut totals = Totals::default();
                loop {
                    let from = next.fetch_add(SEGMENT_BLOCKS, Ordering::Relaxed);
                    if from >= end {
                        return eyre::Ok(totals);
                    }
                    let to = from.saturating_add(SEGMENT_BLOCKS).min(end);
                    totals.add(segment(&reader, &db, &source, from, to).await?);
                }
            });
        }
        let mut totals = Totals::default();
        while let Some(result) = tasks.join_next().await {
            totals.add(result??);
        }
        eyre::ensure!(
            totals.blocks == range.end - range.start,
            "migrated block coverage mismatch"
        );
        // Code is shared across blocks: copy each hash the range reads once, unchanged.
        let hashes: Vec<_> = totals.code.iter().copied().collect();
        let mut copies = JoinSet::new();
        for part in hashes.chunks(hashes.len().div_ceil(workers).max(1)) {
            let (reader, db, part) = (reader.clone(), db.clone(), part.to_vec());
            copies.spawn(async move {
                let (mut batch, mut batch_bytes, mut copied) = (WriteBatch::new(), 0, 0u64);
                for hash in part {
                    let key = store::code_key(&hash);
                    let value = reader
                        .get(key)
                        .await?
                        .ok_or_else(|| eyre::eyre!("missing source code {}", B256::from(hash)))?;
                    copied += value.len() as u64;
                    batch_bytes += value.len();
                    batch.put(key, value);
                    if batch_bytes >= MAX_RECORD_BYTES {
                        db.write(std::mem::replace(&mut batch, WriteBatch::new()))
                            .await?;
                        batch_bytes = 0;
                    }
                }
                if !batch.is_empty() {
                    db.write(batch).await?;
                }
                eyre::Ok(copied)
            });
        }
        let mut code = 0;
        while let Some(result) = copies.join_next().await {
            code += result??;
        }
        db.put(CONTEXT_KEY, serde_json::to_vec(&catalog.context)?)
            .await?;
        db.put(CURSOR_KEY, serde_json::to_vec(&last)?).await?;
        catalog.cursor = last;
        catalog.checkpoint = Some(dest.checkpoint(&db).await?);
        catalog.complete = true;
        dest.publish(&catalog, Some(version)).await?;
        dest.reader(&catalog).await?.close().await?;
        info!(code, hashes = totals.code.len(), "Copied corpus code");
        eyre::Ok((
            totals.blocks,
            totals.legacy_bytes + code,
            totals.migrated_bytes + code,
        ))
    }
    .await;
    let closed = db.close().await;
    let totals = result?;
    closed?;
    Ok(totals)
}

/// What scan tasks migrated: blocks, the legacy and migrated bytes of their records, and the
/// code hashes they read.
#[derive(Default)]
struct Totals {
    blocks: u64,
    legacy_bytes: u64,
    migrated_bytes: u64,
    code: BTreeSet<[u8; 32]>,
}

impl Totals {
    fn add(&mut self, other: Self) {
        self.blocks += other.blocks;
        self.legacy_bytes += other.legacy_bytes;
        self.migrated_bytes += other.migrated_bytes;
        self.code.extend(other.code);
    }
}

/// Migrates blocks [`from`, `to`) with one metadata, block and transaction scan each, checking
/// the legacy hash chain, ordinals, sizes and digests.
async fn segment(
    reader: &DbReader,
    db: &Db,
    source: &Catalog,
    from: u64,
    to: u64,
) -> eyre::Result<Totals> {
    let mut cursor = cursor_at(reader, source, from).await?;
    let last = cursor_at(reader, source, to).await?;
    let options = ScanOptions::default().with_read_ahead_bytes(1024 * 1024);
    let mut metadata = reader
        .scan_with_options(store::metadata_key(from)..store::metadata_key(to), &options)
        .await?;
    let mut blocks = reader
        .scan_with_options(store::key(from)..store::key(to), &options)
        .await?;
    // None when the segment has no transactions: an empty scan range is rejected.
    let mut transactions = if cursor.tx == last.tx {
        None
    } else {
        Some(
            reader
                .scan_with_options(
                    store::transaction_key(cursor.tx)..store::transaction_key(last.tx),
                    &options,
                )
                .await?,
        )
    };
    let mut migrated = cursor.clone();
    let mut totals = Totals {
        blocks: to - from,
        ..Default::default()
    };
    let (mut batch, mut batch_bytes) = (WriteBatch::new(), 0);
    for number in from..to {
        let entry = metadata
            .next()
            .await?
            .ok_or_else(|| eyre::eyre!("metadata gap at {number}"))?;
        eyre::ensure!(
            entry.key.as_ref() == store::metadata_key(number)
                && entry.value.len() <= MAX_RECORD_BYTES,
            "metadata scan key/size mismatch at {number}"
        );
        let legacy: LegacyRecord = serde_json::from_slice(&entry.value)?;
        legacy.advance(&mut cursor, number)?;
        let block = blocks
            .next()
            .await?
            .ok_or_else(|| eyre::eyre!("missing block record at {number}"))?;
        eyre::ensure!(
            block.key.as_ref() == store::key(number)
                && block.value.len() == legacy.block_bytes
                && blake3::hash(&block.value).to_hex().as_str() == legacy.digest,
            "legacy block record integrity mismatch at {number}"
        );
        for (i, expected) in legacy.cases.iter().enumerate() {
            let case = match transactions.as_mut() {
                Some(scan) => scan.next().await?,
                None => None,
            }
            .ok_or_eyre("missing transaction record")?;
            eyre::ensure!(
                case.key.as_ref() == store::transaction_key(legacy.first_tx + i as u64)
                    && case.value.len() == expected.bytes
                    && blake3::hash(&case.value).to_hex().as_str() == expected.digest,
                "legacy transaction record integrity mismatch at {number}"
            );
            batch_bytes += case.value.len();
            batch.put(case.key, case.value);
        }
        let input = upgrade(wincode::config::deserialize_exact(
            &block.value,
            store::WINCODE,
        )?)?;
        totals.code.extend(&input.code);
        let payload = wincode::config::serialize(&input, store::WINCODE)?;
        let record = Record {
            number,
            parent: legacy.parent,
            hash: legacy.tip,
            bytes: legacy.bytes - legacy.block_bytes + payload.len(),
            block_bytes: payload.len(),
            transactions: legacy.transactions,
            gas: legacy.gas,
            first_tx: legacy.first_tx,
            cases: legacy
                .cases
                .iter()
                .map(|case| CaseRecord {
                    index: case.index,
                    bytes: case.bytes,
                })
                .collect(),
        };
        eyre::ensure!(
            record.bytes <= MAX_RECORD_BYTES,
            "migrated record too large"
        );
        // The digest only shows the bytes are unchanged: tie the input to its record too.
        store::decode(&payload, &record)?;
        migrated.advance(&record)?;
        let record_json = serde_json::to_vec(&record)?;
        totals.legacy_bytes += (legacy.bytes + entry.value.len()) as u64;
        totals.migrated_bytes += (record.bytes + record_json.len()) as u64;
        batch_bytes += payload.len() + record_json.len();
        batch.put(store::key(number), payload);
        batch.put(store::metadata_key(number), record_json);
        if batch_bytes >= MAX_RECORD_BYTES {
            db.write(std::mem::replace(&mut batch, WriteBatch::new()))
                .await?;
            batch_bytes = 0;
        }
    }
    eyre::ensure!(
        cursor == last
            && migrated == last
            && metadata.next().await?.is_none()
            && blocks.next().await?.is_none()
            && match transactions.as_mut() {
                Some(scan) => scan.next().await?.is_none(),
                None => true,
            },
        "legacy segment boundary mismatch at {to}"
    );
    if !batch.is_empty() {
        db.write(batch).await?;
    }
    Ok(totals)
}

/// The boundary before `block`, which must be within the published source range.
async fn cursor_at(reader: &DbReader, source: &Catalog, block: u64) -> eyre::Result<Cursor> {
    if block == source.context.start {
        return Cursor::initial(&source.context);
    }
    if block == source.cursor.next {
        return Ok(source.cursor.clone());
    }
    let bytes = reader
        .get(store::metadata_key(block))
        .await?
        .ok_or_else(|| eyre::eyre!("missing block metadata at {block}"))?;
    let record: LegacyRecord = serde_json::from_slice(&bytes)?;
    eyre::ensure!(record.start == block, "metadata key/range mismatch");
    Ok(Cursor {
        next: block,
        tx: record.first_tx,
        parent: record.parent,
    })
}

/// A single-block legacy chunk in the current shape: one block, one pre-block value per key.
fn upgrade(legacy: LegacyChunk) -> eyre::Result<Input> {
    let at = legacy
        .start
        .checked_sub(1)
        .ok_or_eyre("invalid corpus range")?;
    eyre::ensure!(
        legacy.end == legacy.start + 1 && legacy.blocks.len() == 1,
        "legacy record holds more than one block"
    );
    Ok(Input {
        number: legacy.start,
        parent: legacy.parent,
        block: legacy.blocks.into_iter().next().expect("one block"),
        accounts: single(legacy.accounts, at)?,
        storage: single(legacy.storage, at)?,
        code: legacy.code,
        hashes: legacy.hashes,
        phases: legacy.phases,
    })
}

/// The pre-block value of every key, which must be its only version, at `at`.
fn single<K: Ord, V>(
    versions: BTreeMap<K, Vec<(u64, V)>>,
    at: u64,
) -> eyre::Result<BTreeMap<K, V>> {
    versions
        .into_iter()
        .map(|(key, versions)| {
            let [(version, value)] = <[_; 1]>::try_from(versions)
                .map_err(|_| eyre::eyre!("legacy record holds several state versions"))?;
            eyre::ensure!(
                version == at,
                "legacy state version is not the pre-block state"
            );
            Ok((key, value))
        })
        .collect()
}

/// The block record layout before single-block records.
#[derive(SchemaRead)]
struct LegacyChunk {
    start: u64,
    end: u64,
    parent: [u8; 32],
    blocks: Vec<Block>,
    accounts: BTreeMap<[u8; 20], Vec<(u64, Option<Info>)>>,
    storage: LegacyStorage,
    code: BTreeSet<[u8; 32]>,
    hashes: BTreeMap<u64, [u8; 32]>,
    phases: Option<Phases>,
}

type LegacyStorage = BTreeMap<([u8; 20], [u8; 32]), Vec<(u64, [u8; 32])>>;

/// The metadata record layout before single-block records, with blake3 digests.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRecord {
    start: u64,
    end: u64,
    parent: [u8; 32],
    tip: [u8; 32],
    bytes: usize,
    block_bytes: usize,
    digest: String,
    transactions: u64,
    gas: u64,
    first_tx: u64,
    cases: Vec<LegacyCaseRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCaseRecord {
    index: u64,
    bytes: usize,
    digest: String,
}

impl LegacyRecord {
    /// Checks this record continues `cursor` at `number`, then advances it past the record.
    fn advance(&self, cursor: &mut Cursor, number: u64) -> eyre::Result<()> {
        let indexed = self
            .cases
            .iter()
            .enumerate()
            .all(|(i, case)| case.index == i as u64 && case.bytes > 0);
        let bytes = self
            .cases
            .iter()
            .try_fold(self.block_bytes, |sum, case| sum.checked_add(case.bytes));
        let tx = self.first_tx.checked_add(self.transactions);
        eyre::ensure!(
            self.start == number
                && number == cursor.next
                && self.end == number + 1
                && self.parent == cursor.parent
                && self.first_tx == cursor.tx
                && self.transactions == self.cases.len() as u64
                && indexed
                && self.block_bytes > 0
                && self.bytes <= MAX_RECORD_BYTES
                && bytes == Some(self.bytes)
                && tx.is_some(),
            "legacy metadata chain/coverage mismatch at {number}"
        );
        *cursor = Cursor {
            next: self.end,
            tx: tx.expect("checked above"),
            parent: self.tip,
        };
        Ok(())
    }
}
