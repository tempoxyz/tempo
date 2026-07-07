//! Schema metadata for the monitor-owned store.
//!
//! These types describe the proof-path tables independently of any concrete
//! backend. MDBX table creation and migrations should derive their table list
//! from this module instead of duplicating table-name strings.

use crate::invariants::meta::InvariantId;
use alloy_eips::BlockNumHash;
use serde::{Deserialize, Serialize};

/// Initial monitor store schema version.
pub const SCHEMA_VERSION_V0: u32 = 0;

/// Store-layer error used by proof-path APIs.
///
/// Continuity and invalid-commit errors are correctness failures: callers must
/// not treat them as transient delivery failures or advance `FinishedHeight`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum StoreError {
    #[error("store mutex poisoned")]
    Poisoned,
    #[error("incompatible schema: expected {expected}, got {actual}")]
    IncompatibleSchema { expected: u32, actual: u32 },
    #[error("migration blocked: {0:?}")]
    MigrationBlocked(MigrationStatus),
    #[error("continuity error: {0}")]
    Continuity(String),
    #[error("invalid commit: {0}")]
    InvalidCommit(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("idempotency mismatch: {0}")]
    IdempotencyMismatch(String),
    #[error("unknown invariant: {0:?}")]
    UnknownInvariant(InvariantId),
    #[error("not found: {0}")]
    NotFound(String),
}

/// First-commit policy for an empty monitor store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BootstrapPolicy {
    #[default]
    GenesisOnly,
    StartAt(BlockNumHash),
    AnyFirstFinalizedBlock,
}

/// Monotonic schema version for monitor-owned tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersion(pub u32);

/// Migration state recorded before monitor proof processing can proceed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    Clean,
    InProgress { name: String },
    Failed { name: String, reason: String },
}

/// Startup-visible schema state.
///
/// Only `Ready` permits normal block commits. Incompatible or blocked states
/// must halt proof-path advancement until repaired or migrated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaStatus {
    Empty,
    Incompatible(SchemaVersion),
    MigrationBlocked(MigrationStatus),
    Ready {
        version: SchemaVersion,
        tables: Vec<TableMetadata>,
    },
}

/// Reserved category for future feature-specific table namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeatureTableKind {
    StateCache,
    KeysetIndex,
    HistoryState,
    Aggregate,
    ActivityState,
}

/// High-level table role in the monitor proof path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TableCategory {
    Bookkeeping,
    Fact,
    Candidate,
    Result,
    Feature(FeatureTableKind),
}

/// Stable identifier for every foundational v0 table.
///
/// Keep table names monitor-owned. These identifiers must not alias Reth tables
/// even if a backend reuses Reth database primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TableId {
    SchemaMeta,
    MonitorHead,
    RebuildCursors,
    GlobalCoverageStatus,
    TableCoverage,
    MonitorHealth,
    FinalizedBlocks,
    BlockFacts,
    TxFacts,
    ReceiptFacts,
    OrderedLogs,
    DirtyEntities,
    CheckResults,
    CheckCoverage,
    FindingState,
    ReportOutbox,
    StateCacheUpdates,
    KeysetUpdates,
    AggregateUpdates,
    HistoryUpdates,
}

impl TableId {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SchemaMeta => "schema_meta",
            Self::MonitorHead => "monitor_head",
            Self::RebuildCursors => "rebuild_cursors",
            Self::GlobalCoverageStatus => "global_coverage_status",
            Self::TableCoverage => "table_coverage",
            Self::MonitorHealth => "monitor_health",
            Self::FinalizedBlocks => "finalized_blocks",
            Self::BlockFacts => "block_facts",
            Self::TxFacts => "tx_facts",
            Self::ReceiptFacts => "receipt_facts",
            Self::OrderedLogs => "ordered_logs",
            Self::DirtyEntities => "dirty_entities",
            Self::CheckResults => "check_results",
            Self::CheckCoverage => "check_coverage",
            Self::FindingState => "finding_state",
            Self::ReportOutbox => "report_outbox",
            Self::StateCacheUpdates => "state_cache_updates",
            Self::KeysetUpdates => "keyset_updates",
            Self::AggregateUpdates => "aggregate_updates",
            Self::HistoryUpdates => "history_updates",
        }
    }

    pub const fn category(self) -> TableCategory {
        match self {
            Self::SchemaMeta
            | Self::MonitorHead
            | Self::RebuildCursors
            | Self::GlobalCoverageStatus
            | Self::TableCoverage
            | Self::MonitorHealth => TableCategory::Bookkeeping,
            Self::FinalizedBlocks
            | Self::BlockFacts
            | Self::TxFacts
            | Self::ReceiptFacts
            | Self::OrderedLogs => TableCategory::Fact,
            Self::DirtyEntities => TableCategory::Candidate,
            Self::CheckResults | Self::CheckCoverage | Self::FindingState | Self::ReportOutbox => {
                TableCategory::Result
            }
            Self::StateCacheUpdates => TableCategory::Feature(FeatureTableKind::StateCache),
            Self::KeysetUpdates => TableCategory::Feature(FeatureTableKind::KeysetIndex),
            Self::AggregateUpdates => TableCategory::Feature(FeatureTableKind::Aggregate),
            Self::HistoryUpdates => TableCategory::Feature(FeatureTableKind::HistoryState),
        }
    }
}

/// Metadata row for one monitor-owned table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableMetadata {
    pub table: TableId,
    pub name: String,
    pub schema_version: SchemaVersion,
    pub codec_version: u32,
    pub migration_status: MigrationStatus,
    pub retention_policy: Option<String>,
    pub required_for_proof_path: bool,
    pub category: TableCategory,
}

/// Foundational v0 table inventory.
pub fn schema_v0_tables() -> Vec<TableMetadata> {
    use TableId::*;
    [
        SchemaMeta,
        MonitorHead,
        RebuildCursors,
        GlobalCoverageStatus,
        TableCoverage,
        MonitorHealth,
        FinalizedBlocks,
        BlockFacts,
        TxFacts,
        ReceiptFacts,
        OrderedLogs,
        DirtyEntities,
        CheckResults,
        CheckCoverage,
        FindingState,
        ReportOutbox,
        StateCacheUpdates,
        KeysetUpdates,
        AggregateUpdates,
        HistoryUpdates,
    ]
    .into_iter()
    .map(|table| TableMetadata {
        table,
        name: table.name().into(),
        schema_version: SchemaVersion(SCHEMA_VERSION_V0),
        codec_version: 0,
        migration_status: MigrationStatus::Clean,
        retention_policy: None,
        required_for_proof_path: !matches!(table, RebuildCursors),
        category: table.category(),
    })
    .collect()
}
