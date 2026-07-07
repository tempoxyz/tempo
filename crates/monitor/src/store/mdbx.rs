//! Durable MDBX implementation of the monitor store contract.

use alloy_primitives::keccak256;
use reth_db::mdbx::{DatabaseArguments, DatabaseEnv, init_db_for};
use reth_db_api::{
    cursor::DbCursorRO,
    database::Database,
    table::{Table, TableInfo},
    tables::TableSet,
    transaction::{DbTx, DbTxMut},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{path::Path, sync::Arc};

use crate::{
    facts::BlockNumHash,
    findings::FindingKey,
    store::{
        BlockCommit, BootstrapPolicy, DeliveryRecord, DeliveryStatus, FinalizedBlockRecord,
        FindingState, MigrationStatus, MonitorStore, OutboxRow, Result, SCHEMA_VERSION_V0,
        SchemaStatus, SchemaVersion, StoreError, TableMetadata, schema_v0_tables, validation,
    },
};

type Bytes = Vec<u8>;

const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
const CODEC_VERSION_V0: u32 = 0;

macro_rules! monitor_tables {
    ($($name:ident => $table_name:literal),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug)]
            pub(super) struct $name;

            impl Table for $name {
                const NAME: &'static str = $table_name;
                const DUPSORT: bool = false;
                type Key = Bytes;
                type Value = Bytes;
            }

            impl TableInfo for $name {
                fn name(&self) -> &'static str {
                    <Self as Table>::NAME
                }
                fn is_dupsort(&self) -> bool {
                    false
                }
            }
        )+

        #[derive(Debug)]
        pub(super) struct MonitorTables;

        impl TableSet for MonitorTables {
            fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
                Box::new(vec![$(Box::new($name) as Box<dyn TableInfo>),+].into_iter())
            }
        }
    };
}

monitor_tables! {
    SchemaMeta => "schema_meta",
    MonitorHead => "monitor_head",
    RebuildCursors => "rebuild_cursors",
    GlobalCoverageStatus => "global_coverage_status",
    TableCoverage => "table_coverage",
    MonitorHealth => "monitor_health",
    FinalizedBlocks => "finalized_blocks",
    BlockFactsTable => "block_facts",
    TxFactsTable => "tx_facts",
    ReceiptFactsTable => "receipt_facts",
    OrderedLogsTable => "ordered_logs",
    DirtyEntitiesTable => "dirty_entities",
    CheckResultsTable => "check_results",
    CheckCoverageTable => "check_coverage",
    FindingStateTable => "finding_state",
    ReportOutbox => "report_outbox",
    StateCacheUpdatesTable => "state_cache_updates",
    KeysetUpdatesTable => "keyset_updates",
    AggregateUpdatesTable => "aggregate_updates",
    HistoryUpdatesTable => "history_updates",
}

#[derive(Clone, Debug, Default)]
pub struct MdbxMonitorStoreConfig {
    pub bootstrap_policy: BootstrapPolicy,
    pub database_args: DatabaseArguments,
}

#[derive(Debug, Clone)]
pub struct MdbxMonitorStore {
    db: Arc<DatabaseEnv>,
    bootstrap_policy: BootstrapPolicy,
}

impl MdbxMonitorStore {
    pub fn open(path: impl AsRef<Path>, config: MdbxMonitorStoreConfig) -> Result<Self> {
        std::fs::create_dir_all(path.as_ref()).map_err(db_err)?;
        let db = init_db_for::<_, MonitorTables>(path, config.database_args).map_err(db_err)?;
        let this = Self {
            db: Arc::new(db),
            bootstrap_policy: config.bootstrap_policy,
        };
        this.initialize_schema()?;
        Ok(this)
    }

    fn initialize_schema(&self) -> Result<()> {
        let tx = self.db.tx_mut().map_err(db_err)?;
        if tx
            .get::<SchemaMeta>(SCHEMA_VERSION_KEY.to_vec())
            .map_err(db_err)?
            .is_none()
        {
            tx.put::<SchemaMeta>(SCHEMA_VERSION_KEY.to_vec(), encode(&SCHEMA_VERSION_V0)?)
                .map_err(db_err)?;
            for table in schema_v0_tables() {
                tx.put::<SchemaMeta>(table_meta_key(&table.name), encode(&table)?)
                    .map_err(db_err)?;
            }
            tx.commit().map_err(db_err)?;
            return Ok(());
        }
        let status = schema_status_in_tx(&tx)?;
        tx.commit().map_err(db_err)?;
        match status {
            SchemaStatus::Ready { .. } => Ok(()),
            SchemaStatus::Incompatible(version) => Err(StoreError::IncompatibleSchema {
                expected: SCHEMA_VERSION_V0,
                actual: version.0,
            }),
            SchemaStatus::MigrationBlocked(status) => Err(StoreError::MigrationBlocked(status)),
            SchemaStatus::Empty => Err(StoreError::InvalidCommit(
                "monitor schema metadata is incomplete".into(),
            )),
        }
    }

    fn get_decoded<T, V>(&self, key: Vec<u8>) -> Result<Option<V>>
    where
        T: Table<Key = Bytes, Value = Bytes>,
        V: DeserializeOwned,
    {
        let tx = self.db.tx().map_err(db_err)?;
        let row = tx.get::<T>(key).map_err(db_err)?.map(decode).transpose()?;
        tx.commit().map_err(db_err)?;
        Ok(row)
    }

    #[cfg(test)]
    pub(super) fn entries<T: Table>(&self) -> Result<usize> {
        let tx = self.db.tx().map_err(db_err)?;
        let entries = tx.entries::<T>().map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(entries)
    }
}

impl MonitorStore for MdbxMonitorStore {
    fn schema_status(&self) -> Result<SchemaStatus> {
        let tx = self.db.tx().map_err(db_err)?;
        let status = schema_status_in_tx(&tx)?;
        tx.commit().map_err(db_err)?;
        Ok(status)
    }

    fn monitor_head(&self) -> Result<Option<BlockNumHash>> {
        self.get_decoded::<MonitorHead, _>(b"head".to_vec())
    }

    fn commit_block(&self, commit: BlockCommit) -> Result<()> {
        validation::validate_commit(&commit)?;
        let tx = self.db.tx_mut().map_err(db_err)?;
        let current = tx
            .get::<MonitorHead>(b"head".to_vec())
            .map_err(db_err)?
            .map(decode::<BlockNumHash>)
            .transpose()?;
        let digest_key = commit_digest_key(commit.new_monitor_head);
        if let Some(existing) = tx.get::<SchemaMeta>(digest_key.clone()).map_err(db_err)? {
            if decode::<Vec<u8>>(existing)? == commit_digest(&commit)?
                && current.is_some_and(|h| h.number >= commit.new_monitor_head.number)
            {
                return Ok(());
            }
            return Err(StoreError::IdempotencyMismatch(
                "already committed block differs from reconstructed commit".into(),
            ));
        }
        if tx
            .get::<FinalizedBlocks>(u64_key(commit.new_monitor_head.number))
            .map_err(db_err)?
            .is_some()
        {
            return Err(StoreError::Continuity(
                "block number already committed with different hash".into(),
            ));
        }
        validation::validate_outbox_references(&commit, |key| {
            Ok(tx
                .get::<FindingStateTable>(finding_key(key)?)
                .map_err(db_err)?
                .is_some())
        })?;
        if let Some(prev) = current {
            if commit.new_monitor_head.number != prev.number + 1 {
                return Err(StoreError::Continuity(
                    "commit is not contiguous with monitor_head".into(),
                ));
            }
            if commit.finalized_block.reference.parent != prev.hash {
                return Err(StoreError::Continuity(
                    "commit parent hash does not match monitor_head".into(),
                ));
            }
        } else {
            validation::validate_bootstrap(self.bootstrap_policy, &commit)?;
        }

        tx.put::<FinalizedBlocks>(
            u64_key(commit.new_monitor_head.number),
            encode(&commit.finalized_block)?,
        )
        .map_err(db_err)?;
        tx.put::<BlockFactsTable>(
            block_key(commit.new_monitor_head),
            encode(&commit.block_facts)?,
        )
        .map_err(db_err)?;
        macro_rules! put_indexed {
            ($($table:ty => $rows:expr),+ $(,)?) => {
                $(put_indexed_rows::<_, $table, _>(&tx, commit.new_monitor_head, $rows)?;)+
            };
        }
        macro_rules! put_features {
            ($($table:ty => $rows:expr),+ $(,)?) => {
                $(put_feature_rows::<_, $table, _>(&tx, commit.new_monitor_head, $rows, |row| (&row.table, &row.key))?;)+
            };
        }
        put_indexed! {
            TxFactsTable => &commit.tx_facts,
            ReceiptFactsTable => &commit.receipt_facts,
            DirtyEntitiesTable => &commit.dirty_entities,
            CheckResultsTable => &commit.check_results,
            CheckCoverageTable => &commit.coverage_records,
            MonitorHealth => &commit.health_updates,
        }
        for row in &commit.ordered_logs {
            tx.put::<OrderedLogsTable>(
                log_key(row.block, row.tx_index, row.log_index),
                encode(row)?,
            )
            .map_err(db_err)?;
        }
        put_features! {
            StateCacheUpdatesTable => &commit.state_cache_updates,
            KeysetUpdatesTable => &commit.keyset_updates,
            AggregateUpdatesTable => &commit.aggregate_updates,
            HistoryUpdatesTable => &commit.history_updates,
        }
        for transition in &commit.finding_updates {
            let state = FindingState {
                key: transition.key.clone(),
                status: transition.to.clone(),
                last_transition: transition.clone(),
                last_seen: transition.at,
            };
            tx.put::<FindingStateTable>(finding_key(&transition.key)?, encode(&state)?)
                .map_err(db_err)?;
        }
        let first_outbox_sequence = next_outbox_sequence(&tx)?;
        for (offset, event) in commit.outbox_events.iter().enumerate() {
            let sequence = first_outbox_sequence
                .checked_add(u64::try_from(offset).map_err(|_| {
                    StoreError::InvalidCommit("outbox offset exceeds u64::MAX".into())
                })?)
                .ok_or_else(|| StoreError::InvalidCommit("outbox sequence overflow".into()))?;
            let row = OutboxRow {
                sequence,
                block: commit.new_monitor_head,
                event: event.clone(),
                delivery: DeliveryStatus::Pending,
                attempts: 0,
            };
            tx.put::<ReportOutbox>(u64_key(sequence), encode(&row)?)
                .map_err(db_err)?;
        }
        tx.put::<SchemaMeta>(digest_key, encode(&commit_digest(&commit)?)?)
            .map_err(db_err)?;
        tx.put::<MonitorHead>(b"head".to_vec(), encode(&commit.new_monitor_head)?)
            .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    fn finalized_block(&self, number: u64) -> Result<Option<FinalizedBlockRecord>> {
        self.get_decoded::<FinalizedBlocks, _>(u64_key(number))
    }

    fn finding_state(&self, key: &FindingKey) -> Result<Option<FindingState>> {
        self.get_decoded::<FindingStateTable, _>(finding_key(key)?)
    }

    fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let tx = self.db.tx().map_err(db_err)?;
        let mut cursor = tx.cursor_read::<ReportOutbox>().map_err(db_err)?;
        let mut rows = Vec::with_capacity(limit);
        for item in cursor.walk(None).map_err(db_err)? {
            let (_, v) = item.map_err(db_err)?;
            let row: OutboxRow = decode(v)?;
            if matches!(row.delivery, DeliveryStatus::Pending) {
                rows.push(row);
                if rows.len() == limit {
                    break;
                }
            }
        }
        drop(cursor);
        tx.commit().map_err(db_err)?;
        Ok(rows)
    }

    fn mark_outbox_delivered(&self, sequence: u64, delivery: DeliveryRecord) -> Result<()> {
        let tx = self.db.tx_mut().map_err(db_err)?;
        let key = u64_key(sequence);
        let mut row: OutboxRow = tx
            .get::<ReportOutbox>(key.clone())
            .map_err(db_err)?
            .map(decode)
            .transpose()?
            .ok_or_else(|| StoreError::NotFound(format!("outbox sequence {sequence}")))?;
        row.delivery = DeliveryStatus::Delivered(delivery);
        tx.put::<ReportOutbox>(key, encode(&row)?).map_err(db_err)?;
        tx.commit().map_err(db_err)
    }
}

fn put_indexed_rows<TX, T, R>(tx: &TX, block: BlockNumHash, rows: &[R]) -> Result<()>
where
    TX: DbTxMut,
    T: Table<Key = Bytes, Value = Bytes>,
    R: Serialize,
{
    for (i, row) in rows.iter().enumerate() {
        tx.put::<T>(indexed_key(block, i)?, encode(row)?)
            .map_err(db_err)?;
    }
    Ok(())
}

fn put_feature_rows<TX, T, R>(
    tx: &TX,
    block: BlockNumHash,
    rows: &[R],
    table_key: impl Fn(&R) -> (&str, &str),
) -> Result<()>
where
    TX: DbTxMut,
    T: Table<Key = Bytes, Value = Bytes>,
    R: Serialize,
{
    for (i, row) in rows.iter().enumerate() {
        let (table, key) = table_key(row);
        tx.put::<T>(feature_update_key(block, i, table, key)?, encode(row)?)
            .map_err(db_err)?;
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = b"TMON".to_vec();
    out.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    out.extend_from_slice(&CODEC_VERSION_V0.to_be_bytes());
    serde_json::to_writer(&mut out, value).map_err(codec_err)?;
    Ok(out)
}

#[cfg(test)]
pub(super) fn test_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode(value)
}

fn decode<T: DeserializeOwned>(bytes: Vec<u8>) -> Result<T> {
    if bytes.len() < 12 || &bytes[..4] != b"TMON" {
        return Err(StoreError::Codec(
            "invalid monitor row codec envelope".into(),
        ));
    }
    let schema = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if schema != SCHEMA_VERSION_V0 {
        return Err(StoreError::IncompatibleSchema {
            expected: SCHEMA_VERSION_V0,
            actual: schema,
        });
    }
    let codec = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    if codec != CODEC_VERSION_V0 {
        return Err(StoreError::Codec(format!(
            "unsupported monitor row codec version {codec}; expected {CODEC_VERSION_V0}"
        )));
    }
    serde_json::from_slice(&bytes[12..]).map_err(codec_err)
}

fn schema_status_in_tx<TX: DbTx>(tx: &TX) -> Result<SchemaStatus> {
    let Some(version_bytes) = tx
        .get::<SchemaMeta>(SCHEMA_VERSION_KEY.to_vec())
        .map_err(db_err)?
    else {
        return Ok(SchemaStatus::Empty);
    };
    let version = decode::<u32>(version_bytes)?;
    if version != SCHEMA_VERSION_V0 {
        return Ok(SchemaStatus::Incompatible(SchemaVersion(version)));
    }

    let expected = schema_v0_tables();
    for expected_table in &expected {
        let Some(actual_bytes) = tx
            .get::<SchemaMeta>(table_meta_key(&expected_table.name))
            .map_err(db_err)?
        else {
            return Ok(SchemaStatus::Incompatible(SchemaVersion(version)));
        };
        let actual = decode::<TableMetadata>(actual_bytes)?;
        if actual != *expected_table {
            if !matches!(actual.migration_status, MigrationStatus::Clean) {
                return Ok(SchemaStatus::MigrationBlocked(actual.migration_status));
            }
            return Ok(SchemaStatus::Incompatible(SchemaVersion(version)));
        }
    }

    let mut cursor = tx.cursor_read::<SchemaMeta>().map_err(db_err)?;
    for item in cursor.walk(Some(b"table/".to_vec())).map_err(db_err)? {
        let (key, value) = item.map_err(db_err)?;
        if !key.starts_with(b"table/") {
            break;
        }
        let actual = decode::<TableMetadata>(value)?;
        if !expected.contains(&actual) {
            if !matches!(actual.migration_status, MigrationStatus::Clean) {
                return Ok(SchemaStatus::MigrationBlocked(actual.migration_status));
            }
            return Ok(SchemaStatus::Incompatible(SchemaVersion(version)));
        }
    }
    Ok(SchemaStatus::Ready {
        version: SchemaVersion(version),
        tables: expected,
    })
}

fn u64_key(n: u64) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

fn table_meta_key(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(b"table/".len() + name.len());
    out.extend_from_slice(b"table/");
    out.extend_from_slice(name.as_bytes());
    out
}

fn block_key(b: BlockNumHash) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32);
    out.extend_from_slice(&b.number.to_be_bytes());
    out.extend_from_slice(b.hash.as_slice());
    out
}

fn indexed_key(b: BlockNumHash, i: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + 32 + 4);
    out.extend_from_slice(&b.number.to_be_bytes());
    out.extend_from_slice(b.hash.as_slice());
    out.extend_from_slice(&checked_u32(i, "row index")?.to_be_bytes());
    Ok(out)
}

fn log_key(b: BlockNumHash, tx: u64, log: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32 + 8 + 8);
    out.extend_from_slice(&b.number.to_be_bytes());
    out.extend_from_slice(b.hash.as_slice());
    out.extend_from_slice(&tx.to_be_bytes());
    out.extend_from_slice(&log.to_be_bytes());
    out
}

fn feature_update_key(
    block: BlockNumHash,
    index: usize,
    table: &str,
    key: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + 32 + 4 + 4 + table.len() + 4 + key.len());
    out.extend_from_slice(&block.number.to_be_bytes());
    out.extend_from_slice(block.hash.as_slice());
    out.extend_from_slice(&checked_u32(index, "feature update index")?.to_be_bytes());
    out.extend_from_slice(&checked_u32(table.len(), "feature update table length")?.to_be_bytes());
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(&checked_u32(key.len(), "feature update key length")?.to_be_bytes());
    out.extend_from_slice(key.as_bytes());
    Ok(out)
}

fn finding_key(key: &FindingKey) -> Result<Vec<u8>> {
    Ok(keccak256(serde_json::to_vec(key).map_err(codec_err)?).to_vec())
}

fn commit_digest(c: &BlockCommit) -> Result<Vec<u8>> {
    Ok(keccak256(serde_json::to_vec(c).map_err(codec_err)?).to_vec())
}

fn commit_digest_key(b: BlockNumHash) -> Vec<u8> {
    let mut out = Vec::with_capacity(b"commit_digest/".len() + 8 + 32);
    out.extend_from_slice(b"commit_digest/");
    out.extend_from_slice(&b.number.to_be_bytes());
    out.extend_from_slice(b.hash.as_slice());
    out
}

fn next_outbox_sequence<TX: DbTx>(tx: &TX) -> Result<u64> {
    let mut cursor = tx.cursor_read::<ReportOutbox>().map_err(db_err)?;
    let next = match cursor.last().map_err(db_err)? {
        Some((k, _)) if k.len() == 8 => u64::from_be_bytes(k.try_into().unwrap())
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidCommit("outbox sequence overflow".into()))?,
        _ => 1,
    };
    Ok(next)
}
fn checked_u32(value: usize, field: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| StoreError::InvalidCommit(format!("{field} exceeds u32::MAX")))
}

fn db_err(err: impl std::fmt::Display) -> StoreError {
    StoreError::Database(format!("monitor MDBX error: {err}"))
}

fn codec_err(err: impl std::fmt::Display) -> StoreError {
    StoreError::Codec(format!("monitor codec error: {err}"))
}
