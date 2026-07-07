use super::*;
use crate::{
    coverage::{CheckOutcome, CheckResult, CoverageReason, CoverageRecord, CoverageStatus},
    entity::{DirtyEntity, DirtyReason, EntityKey},
    facts::{
        BlockFacts, BlockNumHash, BlockWithParent, FactValue, HeaderFacts, OrderedLog,
        ReceiptFacts, TxEnvelopeFacts, TxFacts,
    },
    findings::{FindingStatus, FindingTransition, MonitorHealthSignal, OutboxEventKind},
    invariants::meta::{InvariantId, Severity, ids},
};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use std::num::NonZeroU64;

fn mdbx_store(path: &std::path::Path) -> eyre::Result<MdbxMonitorStore> {
    Ok(MdbxMonitorStore::open(
        path,
        MdbxMonitorStoreConfig {
            bootstrap_policy: BootstrapPolicy::AnyFirstFinalizedBlock,
            database_args: reth_db::mdbx::DatabaseArguments::test(),
        },
    )?)
}

#[test]
fn mdbx_empty_reopen_and_schema_ready() -> eyre::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = mdbx_store(dir.path())?;
    assert!(matches!(store.schema_status()?, SchemaStatus::Ready { .. }));
    assert_eq!(store.monitor_head()?, None);
    drop(store);
    let reopened = mdbx_store(dir.path())?;
    assert!(matches!(
        reopened.schema_status()?,
        SchemaStatus::Ready { .. }
    ));
    assert_eq!(reopened.monitor_head()?, None);
    Ok(())
}

#[test]
fn mdbx_table_set_matches_schema_inventory() -> eyre::Result<()> {
    use reth_db_api::tables::TableSet;

    assert_eq!(
        super::mdbx::MonitorTables::tables()
            .map(|table| table.name().to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        schema_v0_tables()
            .into_iter()
            .map(|table| table.name)
            .collect::<std::collections::BTreeSet<_>>()
    );
    Ok(())
}

#[test]
fn mdbx_commit_reopen_idempotency_and_outbox_delivery_persist() -> eyre::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = mdbx_store(dir.path())?;
    let mut c = commit(1, b(1), b(0));
    let key = finding_key(c.new_monitor_head);
    add_open_finding(&mut c, key.clone());
    c.outbox_events.push(OutboxEvent {
        finding_key: key.clone(),
        kind: OutboxEventKind::FindingOpened {
            severity: Severity::Critical,
        },
        payload: serde_json::json!({"summary":"opened"}),
    });
    store.commit_block(c.clone())?;
    store.commit_block(c.clone())?;
    assert!(store.pending_outbox(0)?.is_empty());
    assert_eq!(store.pending_outbox(10)?.len(), 1);
    let seq = store.pending_outbox(1)?[0].sequence;
    store.mark_outbox_delivered(
        seq,
        DeliveryRecord {
            delivered_at_unix_ms: 7,
            sink: "test".into(),
            receipt: "ok".into(),
        },
    )?;
    drop(store);

    let reopened = mdbx_store(dir.path())?;
    assert_eq!(reopened.monitor_head()?, Some(c.new_monitor_head));
    assert_eq!(
        reopened.finalized_block(1)?,
        Some(c.finalized_block.clone())
    );
    assert!(matches!(
        reopened.finding_state(&key)?.expect("finding state").status,
        FindingStatus::Open
    ));
    assert!(reopened.pending_outbox(10)?.is_empty());
    reopened.commit_block(c)?;
    assert!(reopened.pending_outbox(10)?.is_empty());
    Ok(())
}

#[test]
fn mdbx_failed_commit_is_atomic_and_mismatch_detected() -> eyre::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = mdbx_store(dir.path())?;
    let c1 = commit(1, b(1), b(0));
    store.commit_block(c1.clone())?;
    assert!(matches!(
        store.commit_block(commit(3, b(3), b(1))),
        Err(StoreError::Continuity(_))
    ));
    assert_eq!(store.monitor_head()?, Some(c1.new_monitor_head));
    assert!(store.finalized_block(3)?.is_none());
    let mut changed = c1;
    changed.block_facts.header.gas_used = 99;
    assert!(matches!(
        store.commit_block(changed),
        Err(StoreError::IdempotencyMismatch(_))
    ));
    Ok(())
}

#[test]
fn mdbx_feature_updates_are_durable_and_schema_meta_is_strict() -> eyre::Result<()> {
    use reth_db_api::{
        database::Database,
        transaction::{DbTx, DbTxMut},
    };

    let dir = tempfile::tempdir()?;
    let store = mdbx_store(dir.path())?;
    let mut c = commit(1, b(1), b(0));
    populate_foundational_rows(&mut c);
    store.commit_block(c)?;
    assert_eq!(store.entries::<super::mdbx::StateCacheUpdatesTable>()?, 1);
    assert_eq!(store.entries::<super::mdbx::KeysetUpdatesTable>()?, 1);
    assert_eq!(store.entries::<super::mdbx::AggregateUpdatesTable>()?, 1);
    assert_eq!(store.entries::<super::mdbx::HistoryUpdatesTable>()?, 1);
    assert_eq!(store.entries::<super::mdbx::SchemaMeta>()?, 22);
    drop(store);

    let db = reth_db::mdbx::init_db_for::<_, super::mdbx::MonitorTables>(
        dir.path(),
        reth_db::mdbx::DatabaseArguments::test(),
    )?;
    let tx = db.tx_mut()?;
    tx.put::<super::mdbx::SchemaMeta>(
        b"schema_version".to_vec(),
        super::mdbx::test_encode(&99u32)?,
    )?;
    tx.commit()?;
    drop(db);

    assert!(matches!(
        MdbxMonitorStore::open(
            dir.path(),
            MdbxMonitorStoreConfig {
                bootstrap_policy: BootstrapPolicy::AnyFirstFinalizedBlock,
                database_args: reth_db::mdbx::DatabaseArguments::test()
            },
        ),
        Err(StoreError::IncompatibleSchema {
            expected: 0,
            actual: 99
        })
    ));
    Ok(())
}

#[test]
fn mdbx_outbox_sequence_survives_reopen_and_finished_height_restart() -> eyre::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = mdbx_store(dir.path())?;
    let mut c1 = commit(1, b(1), b(0));
    let key = finding_key(c1.new_monitor_head);
    add_open_finding(&mut c1, key.clone());
    c1.outbox_events.push(OutboxEvent {
        finding_key: key.clone(),
        kind: OutboxEventKind::CoverageGap,
        payload: serde_json::json!({}),
    });
    store.commit_block(c1.clone())?;
    drop(store);

    let reopened = mdbx_store(dir.path())?;
    assert!(reopened.monitor_head()?.is_some_and(|h| h.number >= 1));
    let mut c2 = commit(2, b(2), b(1));
    c2.outbox_events.push(OutboxEvent {
        finding_key: key,
        kind: OutboxEventKind::FindingUpdated,
        payload: serde_json::json!({}),
    });
    reopened.commit_block(c2)?;
    let pending = reopened.pending_outbox(10)?;
    assert_eq!(
        pending.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        vec![1, 2]
    );
    Ok(())
}

use tempo_hardfork::TempoHardfork;
use tempo_primitives::TempoTxType;

fn b(n: u8) -> B256 {
    B256::repeat_byte(n)
}

fn block(number: u64, hash: B256, _parent: B256) -> BlockNumHash {
    BlockNumHash { number, hash }
}

fn commit(number: u64, hash: B256, parent: B256) -> BlockCommit {
    let head = block(number, hash, parent);
    let reference = BlockWithParent::new(parent, head);
    let finalized_block = FinalizedBlockRecord {
        reference,
        timestamp: number,
        hardfork: TempoHardfork::Genesis,
    };
    let block_facts = BlockFacts {
        reference,
        hardfork: TempoHardfork::Genesis,
        header: HeaderFacts {
            timestamp: number,
            timestamp_millis: number * 1000,
            gas_used: 1,
            gas_limit: 2,
            general_gas_limit: 2,
            shared_gas_limit: 0,
            base_fee_per_gas: None,
            beneficiary: Address::ZERO,
            consensus_context: None,
        },
    };
    BlockCommit {
        finalized_block,
        block_facts,
        tx_facts: vec![],
        receipt_facts: vec![],
        ordered_logs: vec![],
        dirty_entities: vec![],
        state_cache_updates: vec![],
        keyset_updates: vec![],
        aggregate_updates: vec![],
        history_updates: vec![],
        check_results: vec![],
        coverage_records: vec![],
        finding_updates: vec![],
        health_updates: vec![],
        outbox_events: vec![],
        new_monitor_head: head,
    }
}

fn finding_key(head: BlockNumHash) -> FindingKey {
    FindingKey {
        invariant_id: InvariantId::borrowed(ids::BLOCK_TOTAL_GAS),
        entity: None,
        first_seen: head,
    }
}

fn any_store() -> InMemoryMonitorStore {
    InMemoryMonitorStore::with_bootstrap_policy(BootstrapPolicy::AnyFirstFinalizedBlock)
}

fn add_open_finding(c: &mut BlockCommit, key: FindingKey) {
    c.finding_updates.push(FindingTransition {
        key,
        from: None,
        to: FindingStatus::Open,
        at: c.new_monitor_head,
        reason: "opened".into(),
    });
}

#[test]
fn empty_store_initializes_schema_and_head_unset() -> eyre::Result<()> {
    let store = any_store();
    assert!(
        matches!(store.schema_status()? , SchemaStatus::Ready { version: SchemaVersion(0), tables } if tables.iter().any(|t| t.table == TableId::MonitorHead))
    );
    assert_eq!(store.monitor_head()?, None);
    Ok(())
}

#[test]
fn initial_commit_advances_head_and_persists_block() -> eyre::Result<()> {
    let store = any_store();
    let c = commit(1, b(1), b(0));
    store.commit_block(c.clone())?;
    assert_eq!(store.monitor_head()?, Some(c.new_monitor_head));
    assert_eq!(
        store.finalized_block(1)?.expect("finalized block"),
        c.finalized_block
    );
    Ok(())
}

#[test]
fn non_contiguous_commit_is_rejected_atomically() -> eyre::Result<()> {
    let store = any_store();
    let c1 = commit(1, b(1), b(0));
    store.commit_block(c1.clone())?;
    let gap = commit(3, b(3), b(1));
    assert!(matches!(
        store.commit_block(gap),
        Err(StoreError::Continuity(_))
    ));
    assert_eq!(store.monitor_head()?, Some(c1.new_monitor_head));
    assert!(store.finalized_block(3)?.is_none());
    Ok(())
}

#[test]
fn mismatched_parent_is_rejected() -> eyre::Result<()> {
    let store = any_store();
    store.commit_block(commit(1, b(1), b(0)))?;
    assert!(matches!(
        store.commit_block(commit(2, b(2), b(9))),
        Err(StoreError::Continuity(_))
    ));
    assert_eq!(store.monitor_head()?, Some(block(1, b(1), b(0))));
    Ok(())
}

#[test]
fn idempotent_recommit_does_not_duplicate_finding_or_outbox_rows() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    let key = finding_key(c.new_monitor_head);
    c.finding_updates.push(FindingTransition {
        key: key.clone(),
        from: None,
        to: FindingStatus::Open,
        at: c.new_monitor_head,
        reason: "opened".into(),
    });
    c.outbox_events.push(OutboxEvent {
        finding_key: key.clone(),
        kind: OutboxEventKind::FindingOpened {
            severity: Severity::Critical,
        },
        payload: serde_json::json!({"summary":"opened"}),
    });
    store.commit_block(c.clone())?;
    store.commit_block(c)?;
    assert!(matches!(
        store.finding_state(&key)?.expect("finding state").status,
        FindingStatus::Open
    ));
    assert_eq!(store.pending_outbox(10)?.len(), 1);
    Ok(())
}

#[test]
fn commit_persists_coverage_and_inconclusive_outcome() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    let coverage = CoverageRecord {
        invariant_id: InvariantId::borrowed(ids::BLOCK_TOTAL_GAS),
        block: c.new_monitor_head,
        entity: None,
        status: CoverageStatus::Degraded,
        reasons: vec![CoverageReason::TaintedTable("block_facts".into())],
    };
    let gap = crate::coverage::CoverageGap {
        status: CoverageStatus::Degraded,
        reason: CoverageReason::TaintedTable("block_facts".into()),
        detail: "tainted".into(),
    };
    c.coverage_records.push(coverage.clone());
    c.check_results.push(CheckResult {
        invariant_id: coverage.invariant_id.clone(),
        block: c.new_monitor_head,
        entity: None,
        severity: Severity::Critical,
        coverage,
        outcome: CheckOutcome::Inconclusive(gap),
    });
    store.commit_block(c)?;
    let snapshot = store.snapshot();
    assert!(matches!(
        snapshot.coverage_records[0].status,
        CoverageStatus::Degraded
    ));
    assert!(matches!(
        snapshot.check_results[0].outcome,
        CheckOutcome::Inconclusive(_)
    ));
    Ok(())
}

#[test]
fn mark_outbox_delivered_updates_delivery_state() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    let key = finding_key(c.new_monitor_head);
    add_open_finding(&mut c, key.clone());
    c.outbox_events.push(OutboxEvent {
        finding_key: key,
        kind: OutboxEventKind::CoverageGap,
        payload: serde_json::json!({}),
    });
    store.commit_block(c)?;
    let seq = store.pending_outbox(1)?[0].sequence;
    store.mark_outbox_delivered(
        seq,
        DeliveryRecord {
            delivered_at_unix_ms: 42,
            sink: "test".into(),
            receipt: "ok".into(),
        },
    )?;
    assert!(store.pending_outbox(10)?.is_empty());
    Ok(())
}

#[test]
fn head_cannot_advance_except_via_commit_api_shape() -> eyre::Result<()> {
    let store = any_store();
    assert_eq!(store.monitor_head()?, None);
    assert!(
        store
            .mark_outbox_delivered(
                99,
                DeliveryRecord {
                    delivered_at_unix_ms: 0,
                    sink: "none".into(),
                    receipt: "none".into()
                }
            )
            .is_err()
    );
    assert_eq!(store.monitor_head()?, None);
    Ok(())
}

fn populate_foundational_rows(c: &mut BlockCommit) {
    let tx_hash = b(0x44);
    c.tx_facts.push(TxFacts {
        block: c.new_monitor_head,
        tx_index: 0,
        tx_hash,
        is_system: false,
        envelope: TxEnvelopeFacts {
            tx_type: TempoTxType::AA,
            action: TxKind::Call(Address::ZERO),
            gas_limit: 21_000,
            nonce: 1,
            value: U256::from(1),
            nonce_key: None,
            valid_before: NonZeroU64::new(100),
            valid_after: None,
            fee_token: None,
        },
        sender: FactValue::Available(Address::ZERO),
        fee_payer: FactValue::Available(Address::ZERO),
        unique_intent: FactValue::Available(b(0x45)),
    });
    c.receipt_facts.push(ReceiptFacts {
        block: c.new_monitor_head,
        tx_hash,
        tx_index: 0,
        success: true,
        gas_used: FactValue::Available(21_000),
        cumulative_gas_used: 21_000,
    });
    c.ordered_logs.push(OrderedLog {
        block: c.new_monitor_head,
        tx_hash,
        tx_index: 0,
        log_index: 0,
        emitter: Address::ZERO,
        topics: vec![b(0x46)],
        data: Bytes::from_static(b"log"),
    });
    c.dirty_entities.push(DirtyEntity {
        entity: EntityKey::block(c.new_monitor_head),
        reason: DirtyReason::BlockBoundary,
        evidence: vec![],
    });
    c.state_cache_updates.push(StateCacheUpdate {
        table: "tip20_supply".into(),
        key: "token".into(),
        value: serde_json::json!(1),
    });
    c.keyset_updates.push(KeysetUpdate {
        table: "tip20_tokens".into(),
        key: "token".into(),
    });
    c.aggregate_updates.push(AggregateUpdate {
        table: "tip20_total".into(),
        key: "token".into(),
        value: serde_json::json!(1),
    });
    c.history_updates.push(HistoryUpdate {
        table: "expiring_nonce_seen".into(),
        key: "intent".into(),
        value: serde_json::json!(true),
    });
    c.health_updates.push(MonitorHealthUpdate {
        signal: MonitorHealthSignal::Healthy,
        at: c.new_monitor_head,
    });
}

#[test]
fn schema_v0_inventory_contains_required_unique_tables() -> eyre::Result<()> {
    let tables = schema_v0_tables();
    let mut names = std::collections::HashSet::new();
    for table in &tables {
        assert!(
            names.insert(table.name.clone()),
            "duplicate table {}",
            table.name
        );
    }
    for required in [
        TableId::SchemaMeta,
        TableId::MonitorHead,
        TableId::RebuildCursors,
        TableId::MonitorHealth,
        TableId::FinalizedBlocks,
        TableId::BlockFacts,
        TableId::TxFacts,
        TableId::ReceiptFacts,
        TableId::OrderedLogs,
        TableId::DirtyEntities,
        TableId::CheckResults,
        TableId::CheckCoverage,
        TableId::FindingState,
        TableId::ReportOutbox,
        TableId::StateCacheUpdates,
        TableId::KeysetUpdates,
        TableId::AggregateUpdates,
        TableId::HistoryUpdates,
    ] {
        assert!(
            tables.iter().any(|t| t.table == required),
            "missing {required:?}"
        );
    }
    assert_eq!(TableId::MonitorHead.category(), TableCategory::Bookkeeping);
    assert_eq!(TableId::TxFacts.category(), TableCategory::Fact);
    assert_eq!(TableId::DirtyEntities.category(), TableCategory::Candidate);
    assert_eq!(TableId::CheckResults.category(), TableCategory::Result);
    assert_eq!(
        TableId::StateCacheUpdates.category(),
        TableCategory::Feature(FeatureTableKind::StateCache)
    );
    Ok(())
}

#[test]
fn full_commit_shape_is_persisted_by_memory_store() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    populate_foundational_rows(&mut c);
    store.commit_block(c)?;
    let snapshot = store.snapshot();
    assert_eq!(snapshot.tx_facts.len(), 1);
    assert_eq!(snapshot.receipt_facts.len(), 1);
    assert_eq!(snapshot.ordered_logs.len(), 1);
    assert_eq!(snapshot.dirty_entities.len(), 1);
    assert_eq!(snapshot.state_cache_updates.len(), 1);
    assert_eq!(snapshot.keyset_updates.len(), 1);
    assert_eq!(snapshot.aggregate_updates.len(), 1);
    assert_eq!(snapshot.history_updates.len(), 1);
    assert_eq!(snapshot.health_updates.len(), 1);
    Ok(())
}

#[test]
fn idempotent_recommit_rejects_mismatched_rows() -> eyre::Result<()> {
    let store = any_store();
    let c = commit(1, b(1), b(0));
    store.commit_block(c.clone())?;
    let mut changed = c;
    changed.block_facts.header.gas_used = 99;
    assert!(matches!(
        store.commit_block(changed),
        Err(StoreError::IdempotencyMismatch(_))
    ));
    assert_eq!(store.monitor_head()?, Some(block(1, b(1), b(0))));
    Ok(())
}

#[test]
fn delivered_outbox_stays_delivered_after_idempotent_recommit() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    let key = finding_key(c.new_monitor_head);
    add_open_finding(&mut c, key.clone());
    c.outbox_events.push(OutboxEvent {
        finding_key: key,
        kind: OutboxEventKind::CoverageGap,
        payload: serde_json::json!({}),
    });
    store.commit_block(c.clone())?;
    let seq = store.pending_outbox(1)?[0].sequence;
    store.mark_outbox_delivered(
        seq,
        DeliveryRecord {
            delivered_at_unix_ms: 1,
            sink: "test".into(),
            receipt: "ok".into(),
        },
    )?;
    store.commit_block(c)?;
    assert!(store.pending_outbox(10)?.is_empty());
    assert_eq!(store.snapshot().outbox.len(), 1);
    Ok(())
}

#[test]
fn bootstrap_policy_is_explicit() -> eyre::Result<()> {
    let default_store = InMemoryMonitorStore::new();
    assert!(matches!(
        default_store.commit_block(commit(1, b(1), b(0))),
        Err(StoreError::Continuity(_))
    ));
    default_store.commit_block(commit(0, b(0), b(0)))?;

    let genesis_only = InMemoryMonitorStore::with_bootstrap_policy(BootstrapPolicy::GenesisOnly);
    assert!(matches!(
        genesis_only.commit_block(commit(1, b(1), b(0))),
        Err(StoreError::Continuity(_))
    ));

    let start = block(7, b(7), b(0));
    let start_at = InMemoryMonitorStore::with_bootstrap_policy(BootstrapPolicy::StartAt(start));
    assert!(matches!(
        start_at.commit_block(commit(6, b(6), b(0))),
        Err(StoreError::Continuity(_))
    ));
    start_at.commit_block(commit(7, b(7), b(0)))?;
    assert_eq!(start_at.monitor_head()?, Some(start));
    Ok(())
}

#[test]
fn invalid_commit_rows_are_rejected_before_mutation() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    c.coverage_records.push(CoverageRecord {
        invariant_id: InvariantId::borrowed(ids::BLOCK_TOTAL_GAS),
        block: block(2, b(2), b(1)),
        entity: None,
        status: CoverageStatus::Complete,
        reasons: vec![CoverageReason::CompleteInput],
    });
    assert!(matches!(
        store.commit_block(c),
        Err(StoreError::InvalidCommit(_))
    ));
    assert_eq!(store.monitor_head()?, None);
    Ok(())
}

#[test]
fn unknown_invariant_ids_are_rejected() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    c.coverage_records.push(CoverageRecord {
        invariant_id: InvariantId::new("UNKNOWN"),
        block: c.new_monitor_head,
        entity: None,
        status: CoverageStatus::Complete,
        reasons: vec![CoverageReason::CompleteInput],
    });
    assert!(matches!(
        store.commit_block(c),
        Err(StoreError::UnknownInvariant(_))
    ));
    Ok(())
}

#[test]
fn orphan_outbox_event_is_rejected_before_mutation() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    c.outbox_events.push(OutboxEvent {
        finding_key: finding_key(c.new_monitor_head),
        kind: OutboxEventKind::CoverageGap,
        payload: serde_json::json!({}),
    });
    assert!(matches!(
        store.commit_block(c),
        Err(StoreError::InvalidCommit(_))
    ));
    assert_eq!(store.monitor_head()?, None);
    assert!(store.pending_outbox(10)?.is_empty());
    Ok(())
}

#[test]
fn outbox_event_for_existing_finding_is_accepted() -> eyre::Result<()> {
    let store = any_store();
    let mut c1 = commit(1, b(1), b(0));
    let key = finding_key(c1.new_monitor_head);
    add_open_finding(&mut c1, key.clone());
    store.commit_block(c1)?;

    let mut c2 = commit(2, b(2), b(1));
    c2.outbox_events.push(OutboxEvent {
        finding_key: key,
        kind: OutboxEventKind::FindingUpdated,
        payload: serde_json::json!({"repeat": true}),
    });
    store.commit_block(c2)?;
    assert_eq!(store.pending_outbox(10)?.len(), 1);
    Ok(())
}

#[test]
fn unknown_health_invariant_ids_are_rejected() -> eyre::Result<()> {
    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    c.health_updates.push(MonitorHealthUpdate {
        signal: MonitorHealthSignal::CoverageDegraded {
            invariant_id: InvariantId::new("UNKNOWN"),
            detail: "bad".into(),
        },
        at: c.new_monitor_head,
    });
    assert!(matches!(
        store.commit_block(c),
        Err(StoreError::UnknownInvariant(_))
    ));

    let store = any_store();
    let mut c = commit(1, b(1), b(0));
    c.health_updates.push(MonitorHealthUpdate {
        signal: MonitorHealthSignal::CheckError {
            invariant_id: InvariantId::new("UNKNOWN"),
            message: "bad".into(),
        },
        at: c.new_monitor_head,
    });
    assert!(matches!(
        store.commit_block(c),
        Err(StoreError::UnknownInvariant(_))
    ));
    Ok(())
}
