//! Corpus index: one Parquet row per corpus transaction, labelled with the [`targets`] it calls,
//! writes and its block reads, and selection of the blocks whose transactions touch a target.
//!
//! Labels come from the stored block and transaction records alone. Receipts are stored as
//! digests only, so logs and per-transaction read sets are not indexed.

use crate::{
    fuzz,
    store::{self, Catalog, Record, Store},
    targets,
};
use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::Address;
use arrow_array::{
    Array, ArrayRef, BinaryArray, FixedSizeBinaryArray, ListArray, RecordBatch, StructArray,
    UInt8Array, UInt32Array, UInt64Array,
};
use arrow_buffer::OffsetBuffer;
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use parquet::{
    arrow::{
        ArrowWriter, ProjectionMask,
        arrow_reader::{ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder},
    },
    basic::{Compression, ZstdLevel},
    file::{metadata::KeyValue, properties::WriterProperties},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempo_primitives::Block;

/// Version of the index schema, stored in every index footer.
pub const VERSION: u32 = 2;
/// Blocks each read task indexes. Tasks finish in order, so the file stays sorted.
const TASK_BLOCKS: u64 = 10_000;
/// Estimated encoded row group size, before compression.
const ROW_GROUP_BYTES: usize = 128 << 20;
const INDEX_VERSION_KEY: &str = "tempo.corpus.index.version";
const REGISTRY_VERSION_KEY: &str = "tempo.corpus.registry.version";
/// The source corpus's catalog (context, checkpoint and cursor), as JSON.
const CATALOG_KEY: &str = "tempo.corpus.catalog";
const RANGE_KEY: &str = "tempo.corpus.index.range";

/// Indexes the transactions of `range` of a complete corpus into the Parquet file `out`,
/// reading with `workers` parallel tasks. Returns the number of rows.
pub fn index(
    store: Store,
    catalog: Catalog,
    range: Range<u64>,
    out: &Path,
    workers: usize,
) -> eyre::Result<usize> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let reader = Arc::new(store.reader(&catalog).await?);
        let metadata = [
            (INDEX_VERSION_KEY, VERSION.to_string()),
            (REGISTRY_VERSION_KEY, targets::VERSION.to_string()),
            (CATALOG_KEY, serde_json::to_string(&catalog)?),
            (RANGE_KEY, format!("{}..{}", range.start, range.end)),
        ];
        let properties = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
            .set_max_row_group_row_count(None)
            .set_max_row_group_bytes(Some(ROW_GROUP_BYTES))
            .set_key_value_metadata(Some(
                metadata
                    .into_iter()
                    .map(|(key, value)| KeyValue::new(key.to_owned(), value))
                    .collect(),
            ));
        // Dictionaries for the low-cardinality columns only.
        let properties = ["block", "tx_index", "charged_gas", "created"]
            .into_iter()
            .fold(properties, |properties, column| {
                properties.set_column_dictionary_enabled(column.into(), false)
            })
            .build();
        let mut writer = ArrowWriter::try_new(File::create(out)?, schema(), Some(properties))?;
        let mut tasks = futures::stream::iter(range.clone().step_by(TASK_BLOCKS as usize))
            .map(|start| {
                let (reader, context) = (reader.clone(), catalog.context.clone());
                let end = (start + TASK_BLOCKS).min(range.end);
                tokio::spawn(async move {
                    let from = store::cursor_at(&reader, &context, start).await?;
                    let to = store::cursor_at(&reader, &context, end).await?;
                    let mut rows = Rows::default();
                    store::for_each_published(&reader, from, &to, false, |record, block, cases| {
                        rows.push(record, &block, &cases)
                    })
                    .await?;
                    rows.batch()
                })
            })
            .buffered(workers);
        let mut rows = 0;
        while let Some(batch) = tasks.try_next().await? {
            let batch = batch?;
            rows += batch.num_rows();
            writer.write(&batch)?;
        }
        writer.close()?;
        drop(tasks);
        Arc::into_inner(reader)
            .expect("read tasks finished")
            .close()
            .await?;
        Ok(rows)
    })
}

/// The block list of the blocks with a transaction in `blocks` that calls target `bit`, or with
/// `writes` that writes it, read from the index files `paths`. One section per corpus, blocks
/// sorted.
pub fn select(
    paths: &[PathBuf],
    bit: u8,
    writes: bool,
    blocks: Range<u64>,
) -> eyre::Result<String> {
    let mask = 1u64 << bit;
    // Keyed by range and tip: corpora of one chain that end at the same block share a tip.
    let mut corpora = BTreeMap::<(u64, u64, String), (Catalog, BTreeSet<u64>)>::new();
    for path in paths {
        let (catalog, _, batches) = read(path, &["block", "calls", "writes"])?;
        let selected = &mut corpora
            .entry((
                catalog.context.start,
                catalog.context.end,
                catalog.context.tip.clone(),
            ))
            .or_insert_with(|| (catalog, BTreeSet::new()))
            .1;
        for batch in batches {
            let batch = batch?;
            let block = column::<UInt64Array>(&batch, "block")?;
            let calls = column::<ListArray>(&batch, "calls")?;
            let written = column::<UInt64Array>(&batch, "writes")?;
            let called = call_column::<UInt8Array>(calls, "target")?;
            let offsets = calls.value_offsets();
            for row in 0..batch.num_rows() {
                let number = block.value(row);
                let touched = if writes {
                    written.value(row) & mask != 0
                } else {
                    (offsets[row] as usize..offsets[row + 1] as usize)
                        .any(|call| called.is_valid(call) && called.value(call) == bit)
                };
                if touched && blocks.contains(&number) {
                    selected.insert(number);
                }
            }
        }
    }
    Ok(corpora
        .values()
        .map(|(catalog, blocks)| fuzz::block_list(catalog, &Vec::from_iter(blocks.iter().copied())))
        .collect())
}

/// The source catalog and indexed range of the index file `path`, and its `columns`' batches.
/// Fails unless the file is an index of this schema and registry version.
pub(crate) fn read(
    path: &Path,
    columns: &[&str],
) -> eyre::Result<(Catalog, String, ParquetRecordBatchReader)> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    let metadata: BTreeMap<_, _> = builder
        .metadata()
        .file_metadata()
        .key_value_metadata()
        .into_iter()
        .flatten()
        .map(|entry| {
            (
                entry.key.as_str(),
                entry.value.as_deref().unwrap_or_default(),
            )
        })
        .collect();
    let get = |key| {
        metadata
            .get(key)
            .copied()
            .ok_or_else(|| eyre::eyre!("{} has no {key}", path.display()))
    };
    eyre::ensure!(
        get(INDEX_VERSION_KEY)? == VERSION.to_string()
            && get(REGISTRY_VERSION_KEY)? == targets::VERSION.to_string(),
        "{} has another index or target registry version",
        path.display()
    );
    let catalog: Catalog = serde_json::from_str(get(CATALOG_KEY)?)?;
    let range = get(RANGE_KEY)?.to_owned();
    let columns = columns
        .iter()
        .map(|name| builder.schema().index_of(name).ok())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| eyre::eyre!("{} is not a corpus index", path.display()))?;
    let projection = ProjectionMask::roots(builder.parquet_schema(), columns);
    Ok((catalog, range, builder.with_projection(projection).build()?))
}

/// The `name` field of every call in `calls`.
pub(crate) fn call_column<'a, T: Array + 'static>(
    calls: &'a ListArray,
    name: &str,
) -> eyre::Result<&'a T> {
    calls
        .values()
        .as_any()
        .downcast_ref::<StructArray>()
        .and_then(|calls| calls.column_by_name(name))
        .and_then(|column| column.as_any().downcast_ref())
        .ok_or_else(|| eyre::eyre!("index call column {name} missing or mistyped"))
}

pub(crate) fn column<'a, T: Array + 'static>(
    batch: &'a RecordBatch,
    name: &str,
) -> eyre::Result<&'a T> {
    batch
        .column_by_name(name)
        .and_then(|column| column.as_any().downcast_ref())
        .ok_or_else(|| eyre::eyre!("index column {name} missing or mistyped"))
}

fn call_fields() -> Fields {
    Fields::from(vec![
        Field::new("target", DataType::UInt8, true),
        Field::new("selector", DataType::FixedSizeBinary(4), true),
        Field::new("to", DataType::FixedSizeBinary(20), true),
        Field::new("input", DataType::Binary, true),
    ])
}

/// One row per transaction. `calls` holds every call of a batched Tempo transaction, each with
/// its target bit (null when unlabelled), selector and, for a labelled target, calldata, and a
/// creation as a call with null `to` and selector. `writes` masks the targets its state delta changes and `block_reads` those its
/// block's witness reads. `status` is 0 on success.
fn schema() -> SchemaRef {
    let address = DataType::FixedSizeBinary(20);
    Arc::new(Schema::new(vec![
        Field::new("block", DataType::UInt64, false),
        Field::new("tx_index", DataType::UInt32, false),
        Field::new("block_hash", DataType::FixedSizeBinary(32), false),
        Field::new("tx_type", DataType::UInt8, false),
        Field::new("sender", address.clone(), false),
        Field::new(
            "calls",
            DataType::List(Arc::new(Field::new_list_field(
                DataType::Struct(call_fields()),
                false,
            ))),
            false,
        ),
        Field::new("writes", DataType::UInt64, false),
        Field::new("block_reads", DataType::UInt64, false),
        Field::new("status", DataType::UInt8, false),
        Field::new("charged_gas", DataType::UInt64, false),
        Field::new("gas_limit", DataType::UInt64, false),
        Field::new("created", address.clone(), true),
        Field::new("fee_token", address, true),
        Field::new("nonce_key", DataType::FixedSizeBinary(32), true),
    ]))
}

/// Index rows of a block range, column by column.
#[derive(Default)]
struct Rows {
    block: Vec<u64>,
    tx_index: Vec<u32>,
    block_hash: Vec<[u8; 32]>,
    tx_type: Vec<u8>,
    sender: Vec<[u8; 20]>,
    calls: Vec<usize>,
    call_target: Vec<Option<u8>>,
    call_selector: Vec<Option<[u8; 4]>>,
    call_to: Vec<Option<Address>>,
    call_input: Vec<Option<Bytes>>,
    writes: Vec<u64>,
    block_reads: Vec<u64>,
    status: Vec<u8>,
    charged_gas: Vec<u64>,
    gas_limit: Vec<u64>,
    created: Vec<Option<[u8; 20]>>,
    fee_token: Vec<Option<Address>>,
    nonce_key: Vec<Option<[u8; 32]>>,
}

impl Rows {
    /// Adds a row for every transaction of a published block.
    fn push(&mut self, record: &Record, block: &Bytes, cases: &[Bytes]) -> eyre::Result<()> {
        let stored = store::decode(block, record)?;
        let input = &stored.block;
        let transactions = alloy_rlp::decode_exact::<Block>(&input.rlp)?
            .body
            .transactions;
        eyre::ensure!(
            transactions.len() == cases.len() && transactions.len() == input.senders.len(),
            "block {} transaction count mismatch",
            record.number
        );
        let reads = stored
            .accounts
            .keys()
            .chain(stored.storage.keys().map(|(address, _)| address))
            .fold(0, |mask, address| mask | targets::mask(&(*address).into()));
        for (i, ((transaction, sender), bytes)) in transactions
            .iter()
            .zip(&input.senders)
            .zip(cases)
            .enumerate()
        {
            let case = store::decode_case(bytes, &record.cases[i], record.first_tx + i as u64)?;
            let calls = self.call_to.len();
            for (kind, data) in transaction.calls() {
                let to = kind.to().copied();
                let target = to.as_ref().and_then(targets::classify);
                self.call_target.push(target);
                self.call_selector.push(to.and(data.first_chunk().copied()));
                self.call_input.push(target.map(|_| data.0.clone()));
                self.call_to.push(to);
            }
            self.calls.push(self.call_to.len() - calls);
            self.block.push(record.number);
            self.tx_index.push(u32::try_from(case.index)?);
            self.block_hash.push(record.hash);
            self.tx_type.push(transaction.ty());
            self.sender.push(*sender);
            self.writes.push(
                case.delta
                    .0
                    .iter()
                    .flat_map(|commit| commit.keys())
                    .fold(0, |mask, address| mask | targets::mask(&(*address).into())),
            );
            self.block_reads.push(reads);
            self.status.push(case.status);
            self.charged_gas.push(case.charged_gas);
            self.gas_limit.push(transaction.gas_limit());
            self.created.push(case.created);
            self.fee_token.push(transaction.fee_token());
            self.nonce_key
                .push(transaction.nonce_key().map(|key| key.to_be_bytes()));
        }
        Ok(())
    }

    fn batch(self) -> eyre::Result<RecordBatch> {
        let calls = StructArray::try_new(
            call_fields(),
            vec![
                Arc::new(UInt8Array::from(self.call_target)),
                fixed(self.call_selector, 4)?,
                fixed(self.call_to, 20)?,
                Arc::new(BinaryArray::from_iter(self.call_input)),
            ],
            None,
        )?;
        let calls = ListArray::try_new(
            Arc::new(Field::new_list_field(
                DataType::Struct(call_fields()),
                false,
            )),
            OffsetBuffer::from_lengths(self.calls),
            Arc::new(calls),
            None,
        )?;
        Ok(RecordBatch::try_new(
            schema(),
            vec![
                Arc::new(UInt64Array::from(self.block)),
                Arc::new(UInt32Array::from(self.tx_index)),
                fixed(self.block_hash.into_iter().map(Some), 32)?,
                Arc::new(UInt8Array::from(self.tx_type)),
                fixed(self.sender.into_iter().map(Some), 20)?,
                Arc::new(calls),
                Arc::new(UInt64Array::from(self.writes)),
                Arc::new(UInt64Array::from(self.block_reads)),
                Arc::new(UInt8Array::from(self.status)),
                Arc::new(UInt64Array::from(self.charged_gas)),
                Arc::new(UInt64Array::from(self.gas_limit)),
                fixed(self.created, 20)?,
                fixed(self.fee_token, 20)?,
                fixed(self.nonce_key, 32)?,
            ],
        )?)
    }
}

fn fixed<T: AsRef<[u8]>>(
    values: impl IntoIterator<Item = Option<T>>,
    size: i32,
) -> eyre::Result<ArrayRef> {
    Ok(Arc::new(
        FixedSizeBinaryArray::try_from_sparse_iter_with_size(values.into_iter(), size)?,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        store::{
            CaseRecord, Cursor, key, metadata_key,
            tests::{catalog, in_memory, open_db},
            transaction_key,
        },
        types::{self, Case, Change, Delta, Input, Outputs},
    };
    use alloy_consensus::{BlockBody, SignableTransaction, TxLegacy};
    use alloy_primitives::{B256, Signature, TxKind, U256};
    use tempo_contracts::precompiles::{
        PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    };
    use tempo_primitives::{TempoHeader, TempoTransaction, TempoTxEnvelope, transaction::Call};

    fn call(to: Address, selector: [u8; 4]) -> Call {
        Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: selector.into(),
        }
    }

    /// Publishes a corpus of the given blocks: each block's transactions with the address each
    /// one writes.
    pub(crate) fn corpus(
        blocks: Vec<Vec<(TempoTxEnvelope, Address)>>,
    ) -> eyre::Result<(Store, Catalog)> {
        let store = in_memory("index");
        let mut catalog = catalog(1, 0, 0);
        catalog.context.end = 1 + blocks.len() as u64;
        catalog.complete = false;
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let db = open_db(&store, &catalog).await?;
            let mut cursor = Cursor::initial(&catalog.context)?;
            for (number, transactions) in (1..).zip(blocks) {
                let senders = vec![[number as u8; 20]; transactions.len()];
                let (transactions, written): (Vec<_>, Vec<_>) = transactions.into_iter().unzip();
                let block = types::Block {
                    hash: [number as u8; 32],
                    rlp: alloy_rlp::encode(Block {
                        header: TempoHeader::default(),
                        body: BlockBody {
                            transactions,
                            ommers: vec![],
                            withdrawals: None,
                        },
                    }),
                    senders,
                    changed_accounts: vec![],
                    changed_storage: vec![],
                };
                let input = Input {
                    number,
                    parent: cursor.parent,
                    block,
                    accounts: [(STABLECOIN_DEX_ADDRESS.into_array(), None)].into(),
                    storage: Default::default(),
                    code: Default::default(),
                    hashes: Default::default(),
                    phases: None,
                };
                let cases = (0..).zip(written).map(|(index, address)| {
                    let change = Change {
                        info: None,
                        created: false,
                        storage: Default::default(),
                        code: None,
                    };
                    let case = Case {
                        ordinal: cursor.tx + index,
                        index,
                        hash: [0; 32],
                        before: vec![],
                        status: 1,
                        charged_gas: 21_000,
                        created: None,
                        delta: Delta(vec![[(address.into_array(), change)].into()]),
                        outputs: Outputs {
                            outcome: [0; 16],
                            receipt: [0; 16],
                            after: [0; 16],
                        },
                    };
                    wincode::config::serialize(&case, store::WINCODE)
                });
                let cases = cases.collect::<Result<Vec<_>, _>>()?;
                let bytes = wincode::config::serialize(&input, store::WINCODE)?;
                let record = Record {
                    number,
                    parent: input.parent,
                    hash: input.block.hash,
                    bytes: bytes.len() + cases.iter().map(Vec::len).sum::<usize>(),
                    block_bytes: bytes.len(),
                    transactions: cases.len() as u64,
                    gas: 0,
                    first_tx: cursor.tx,
                    cases: (0..)
                        .zip(&cases)
                        .map(|(index, case)| CaseRecord {
                            index,
                            bytes: case.len(),
                        })
                        .collect(),
                };
                for (ordinal, case) in (cursor.tx..).zip(&cases) {
                    db.put(transaction_key(ordinal), case).await?;
                }
                db.put(key(number), bytes).await?;
                db.put(metadata_key(number), serde_json::to_vec(&record)?)
                    .await?;
                cursor.advance(&record)?;
            }
            catalog.context.end_tx = cursor.tx;
            catalog.context.tip = B256::from(cursor.parent).to_string();
            catalog.cursor = cursor;
            db.put(store::CONTEXT_KEY, serde_json::to_vec(&catalog.context)?)
                .await?;
            db.put(store::CURSOR_KEY, serde_json::to_vec(&catalog.cursor)?)
                .await?;
            catalog.checkpoint = Some(store.checkpoint(&db).await?);
            catalog.complete = true;
            store.publish(&catalog, None).await?;
            db.close().await?;
            eyre::Ok(())
        })?;
        Ok((store, catalog))
    }

    #[test]
    fn selects_blocks_by_called_and_written_targets() -> eyre::Result<()> {
        let legacy = TempoTxEnvelope::Legacy(
            TxLegacy {
                to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                input: [1, 2, 3, 4, 5].into(),
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        let batch = TempoTxEnvelope::AA(
            TempoTransaction {
                fee_token: Some(PATH_USD_ADDRESS),
                calls: vec![
                    call(TIP_FEE_MANAGER_ADDRESS, [9; 4]),
                    call(PATH_USD_ADDRESS, [8; 4]),
                ],
                ..Default::default()
            }
            .into_signed(Signature::test_signature().into()),
        );
        let (store, catalog) = corpus(vec![
            vec![(legacy, STABLECOIN_DEX_ADDRESS)],
            vec![(batch, PATH_USD_ADDRESS)],
            vec![],
        ])?;
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("index.parquet");
        assert_eq!(index(store, catalog.clone(), 1..4, &out, 2)?, 2);
        for (name, writes, range, blocks) in [
            ("dex", true, 0..u64::MAX, &[1][..]),
            ("feeamm", false, 0..u64::MAX, &[2]),
            ("feeamm", true, 0..u64::MAX, &[]),
            ("tip20", false, 0..u64::MAX, &[2]),
            ("tip20", true, 0..u64::MAX, &[2]),
            ("tip20", true, 0..2, &[]),
        ] {
            let bit = targets::bit(name).expect("registered target");
            let selected = select(std::slice::from_ref(&out), bit, writes, range)?;
            let expected = fuzz::block_list(&catalog, blocks);
            assert_eq!(selected, expected, "{name} writes={writes}");
            let path = dir.path().join("blocks");
            std::fs::write(&path, selected)?;
            assert_eq!(fuzz::read_blocks(&path, &catalog)?, blocks);
        }
        Ok(())
    }
}
