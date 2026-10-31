//! One-time migration of a legacy corpus to the current format: changesets become bitmaps
//! over the witness and each transaction stores its full state delta instead of a digest.
//!
//! Needs no archive DB. Each block is re-executed from its own record to recover the deltas;
//! every recovered output must match the legacy digests, and the block must still pass
//! consensus and the historical changesets. Code is copied unchanged.

use crate::{
    execute::{decode_block, execute_block, verify_changesets},
    store::{
        self, CONTEXT_KEY, CURSOR_KEY, Catalog, Context, Cursor, MAX_RECORD_BYTES, MetadataPages,
        PayloadScan, Record, Store,
    },
    types::{Chunk, LegacyCase, LegacyChunk},
    view::View,
};
use alloy_primitives::B256;
use bytes::Bytes;
use slatedb::{
    Db, DbReader, WriteBatch,
    config::{CompressionCodec, Settings},
};
use std::{collections::HashSet, sync::Arc};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tracing::info;

/// Records per checkpoint and catalog publication, as in fill.
const RECORDS_PER_PUBLISH: usize = 10 * store::PAGE_RECORDS;

/// Migrates blocks [from, to) of the complete legacy corpus at `source` into a new corpus at
/// `dest`, which must not exist yet.
pub async fn migrate(
    source: Store,
    dest: Store,
    from: Option<u64>,
    to: Option<u64>,
    config: &TempoEvmConfig,
    consensus: &TempoConsensus,
) -> eyre::Result<()> {
    let (catalog, _) = source
        .catalog()
        .await?
        .ok_or_else(|| eyre::eyre!("no source corpus catalog"))?;
    eyre::ensure!(catalog.complete, "source corpus is not complete");
    let context = &catalog.context;
    let from = from.unwrap_or(context.start);
    let to = to.unwrap_or(context.end).min(context.end);
    eyre::ensure!(
        from >= context.start && from < to,
        "migration range outside the source corpus"
    );
    eyre::ensure!(
        dest.catalog().await?.is_none(),
        "destination corpus already exists"
    );
    let reader = source.reader(&catalog).await?;
    let result = run(&reader, &catalog, &dest, from, to, config, consensus).await;
    reader.close().await?;
    result
}

async fn cursor_at(reader: &DbReader, catalog: &Catalog, block: u64) -> eyre::Result<Cursor> {
    if block == catalog.context.start {
        return Cursor::initial(&catalog.context);
    }
    if block == catalog.context.end {
        return Ok(catalog.cursor.clone());
    }
    let record = store::metadata(reader, block).await?;
    Ok(Cursor {
        next: block,
        tx: record.first_tx,
        parent: record.parent,
    })
}

/// One block migrated to the current format.
struct Migrated {
    payload: Vec<u8>,
    cases: Vec<Vec<u8>>,
    record: Record,
}

/// Upgrades one legacy block payload to the bitmap format.
fn upgrade_chunk(bytes: &[u8], record: &Record) -> eyre::Result<Arc<Chunk>> {
    eyre::ensure!(
        bytes.len() == record.block_bytes && blake3::hash(bytes).to_hex().as_str() == record.digest,
        "legacy record integrity mismatch"
    );
    let legacy: LegacyChunk = wincode::deserialize_exact(bytes)?;
    let chunk = legacy.upgrade()?;
    chunk.validate()?;
    Ok(Arc::new(chunk))
}

/// Re-executes one upgraded block from its record and rebuilds its transaction records with
/// full deltas, checking them against the legacy ones.
fn migrate_block(
    config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    chunk: &Arc<Chunk>,
    legacy_cases: &[Bytes],
    record: &Record,
) -> eyre::Result<Migrated> {
    eyre::ensure!(
        legacy_cases.len() == record.cases.len(),
        "transaction count mismatch"
    );
    let legacy = legacy_cases
        .iter()
        .zip(&record.cases)
        .enumerate()
        .map(|(i, (bytes, expected))| {
            eyre::ensure!(
                bytes.len() == expected.bytes
                    && blake3::hash(bytes).to_hex().as_str() == expected.digest,
                "legacy transaction record integrity mismatch"
            );
            let case: LegacyCase = wincode::deserialize_exact(bytes)?;
            eyre::ensure!(
                case.ordinal == record.first_tx + i as u64 && case.index == expected.index,
                "legacy transaction ordinal/index mismatch"
            );
            Ok(case)
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    let block = decode_block(&chunk.blocks[0], chunk.start, B256::from(chunk.parent))?;
    let executed = execute_block(
        config,
        consensus,
        View::new(chunk.clone()),
        &block,
        record.first_tx,
        None,
    )?;
    eyre::ensure!(
        chunk.phases.as_ref() == Some(&executed.phases),
        "block {}: phase delta mismatch",
        chunk.start
    );
    verify_changesets(&executed.bundle, &chunk.changeset()?, chunk.start)?;
    eyre::ensure!(
        executed.transactions.len() == legacy.len()
            && executed.transactions.len() as u64 == record.transactions
            && executed.gas == record.gas,
        "block {}: transaction/gas totals mismatch",
        chunk.start
    );
    let payload = wincode::serialize(chunk.as_ref())?;
    let mut upgraded = record.clone();
    upgraded.block_bytes = payload.len();
    upgraded.digest = blake3::hash(&payload).to_hex().to_string();
    let mut cases = Vec::with_capacity(legacy.len());
    for ((old, actual), entry) in legacy
        .iter()
        .zip(&executed.transactions)
        .zip(&mut upgraded.cases)
    {
        let bytes = wincode::serialize(&old.upgrade(actual)?)?;
        eyre::ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "migrated transaction too large"
        );
        entry.bytes = bytes.len();
        entry.digest = blake3::hash(&bytes).to_hex().to_string();
        cases.push(bytes);
    }
    upgraded.bytes = upgraded.block_bytes + cases.iter().map(Vec::len).sum::<usize>();
    eyre::ensure!(
        upgraded.bytes <= MAX_RECORD_BYTES,
        "migrated record too large"
    );
    for (i, bytes) in cases.iter().enumerate() {
        store::decode_case(bytes, &upgraded.cases[i], record.first_tx + i as u64)?;
    }
    store::decode(&payload, &upgraded)?;
    Ok(Migrated {
        payload,
        cases,
        record: upgraded,
    })
}

/// Runs `f` over `items` across the available cores, preserving order.
fn parallel<T: Sync, R: Send>(
    items: &[T],
    f: impl Fn(&T) -> eyre::Result<R> + Sync,
) -> eyre::Result<Vec<R>> {
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let per = items.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = items
            .chunks(per)
            .map(|items| scope.spawn(move || items.iter().map(f).collect::<eyre::Result<Vec<_>>>()))
            .collect();
        let mut out = Vec::with_capacity(items.len());
        for handle in handles {
            out.extend(
                handle
                    .join()
                    .map_err(|_| eyre::eyre!("migration worker panicked"))??,
            );
        }
        Ok(out)
    })
}

async fn run(
    reader: &DbReader,
    source: &Catalog,
    dest: &Store,
    from: u64,
    to: u64,
    config: &TempoEvmConfig,
    consensus: &TempoConsensus,
) -> eyre::Result<()> {
    let first = cursor_at(reader, source, from).await?;
    let last = cursor_at(reader, source, to).await?;
    let context = Context {
        chain_id: source.context.chain_id,
        genesis: source.context.genesis.clone(),
        forks: source.context.forks.clone(),
        start: from,
        end: to,
        parent: B256::from(first.parent).to_string(),
        tip: B256::from(last.parent).to_string(),
        first_tx: first.tx,
        end_tx: last.tx,
    };
    let mut catalog = Catalog {
        cursor: Cursor::initial(&context)?,
        context,
        checkpoint: None,
        records: Vec::new(),
        complete: false,
        generation: 1,
    };
    let mut version = dest.publish(&catalog, None).await?;
    let db = Db::builder(dest.path.clone().join("data"), dest.objects.clone())
        .with_settings(Settings {
            object_store_max_retries: store::SLATEDB_RETRIES,
            compression_codec: Some(CompressionCodec::Zstd),
            garbage_collector_options: None,
            ..Default::default()
        })
        .build()
        .await?;
    let result = async {
        db.put(CONTEXT_KEY, serde_json::to_vec(&catalog.context)?)
            .await?;
        let mut pages = MetadataPages::open(reader, first, to).await?;
        let mut batch = WriteBatch::new();
        let mut batch_bytes = 0usize;
        let mut written_code = HashSet::new();
        let (mut legacy_bytes, mut migrated_bytes) = (0u64, 0u64);
        while pages.cursor.next < to {
            let records = pages.next_page().await?;
            let mut payloads = PayloadScan::open(reader, &records).await?;
            let mut fetched = Vec::with_capacity(records.len());
            for record in &records {
                fetched.push((record, payloads.next(record).await?));
            }
            payloads.finish().await?;
            let chunks = parallel(&fetched, |(record, (block, _))| {
                upgrade_chunk(block, record)
            })?;
            // Execution reads code from the shared cache; load what this page needs first.
            for chunk in &chunks {
                store::resolve_code(reader, chunk).await?;
            }
            let work: Vec<_> = fetched
                .iter()
                .zip(&chunks)
                .map(|((record, (_, cases)), chunk)| (*record, cases, chunk))
                .collect();
            let migrated = parallel(&work, |(record, cases, chunk)| {
                migrate_block(config, consensus, chunk, cases, record)
            })?;
            for ((record, _), (chunk, block)) in fetched.iter().zip(chunks.iter().zip(migrated)) {
                legacy_bytes += record.bytes as u64;
                migrated_bytes += block.record.bytes as u64;
                for hash in &chunk.code {
                    if !written_code.insert(*hash) {
                        continue;
                    }
                    let key = store::code_key(hash);
                    let code = reader
                        .get(key)
                        .await?
                        .ok_or_else(|| eyre::eyre!("missing source code {}", B256::from(*hash)))?;
                    batch_bytes += code.len();
                    batch.put(key, code);
                }
                batch_bytes += block.payload.len();
                batch.put(store::key(record.start), block.payload);
                let metadata = serde_json::to_vec(&block.record)?;
                batch_bytes += metadata.len();
                batch.put(store::metadata_key(record.start), metadata);
                for (i, case) in block.cases.into_iter().enumerate() {
                    batch_bytes += case.len();
                    batch.put(store::transaction_key(record.first_tx + i as u64), case);
                }
                catalog.records.push(block.record);
                let done = record.end == to;
                let seal = done || catalog.records.len() >= RECORDS_PER_PUBLISH;
                if (seal || batch_bytes >= MAX_RECORD_BYTES) && !batch.is_empty() {
                    db.write(std::mem::replace(&mut batch, WriteBatch::new()))
                        .await?;
                    batch_bytes = 0;
                }
                if seal {
                    catalog.seal()?;
                    db.put(CURSOR_KEY, serde_json::to_vec(&catalog.cursor)?)
                        .await?;
                    catalog.checkpoint = Some(dest.checkpoint(&db).await?);
                    catalog.complete = done;
                    version = dest.publish(&catalog, Some(version)).await?;
                    info!(
                        next = catalog.cursor.next,
                        end = to,
                        legacy_bytes,
                        migrated_bytes,
                        complete = done,
                        "Published migrated corpus page"
                    );
                }
            }
        }
        eyre::ensure!(
            pages.cursor == last && catalog.cursor == last && catalog.complete,
            "migrated corpus boundary mismatch"
        );
        eyre::Ok(())
    }
    .await;
    let closed = db.close().await;
    result?;
    closed?;
    Ok(())
}
