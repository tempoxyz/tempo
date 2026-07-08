//! Shared validation for monitor store block commits.

use std::collections::HashSet;

use crate::{
    diagnostics::findings::{FindingKey, MonitorHealthSignal},
    invariants::meta::{InvariantId, initial_catalog},
    store::{BlockCommit, BootstrapPolicy, MonitorHealthUpdate, Result, StoreError},
};

pub(super) fn validate_bootstrap(policy: BootstrapPolicy, commit: &BlockCommit) -> Result<()> {
    match policy {
        BootstrapPolicy::AnyFirstFinalizedBlock => Ok(()),
        BootstrapPolicy::GenesisOnly if commit.new_monitor_head.number == 0 => Ok(()),
        BootstrapPolicy::GenesisOnly => Err(StoreError::Continuity(
            "bootstrap policy requires first commit to be genesis".into(),
        )),
        BootstrapPolicy::StartAt(start) if commit.new_monitor_head == start => Ok(()),
        BootstrapPolicy::StartAt(start) => Err(StoreError::Continuity(format!(
            "bootstrap policy requires first commit to be {start:?}"
        ))),
    }
}

pub(super) fn validate_commit(commit: &BlockCommit) -> Result<()> {
    let block = commit.new_monitor_head;
    if commit.finalized_block.reference != commit.block_facts.reference
        || commit.finalized_block.reference.block != block
    {
        return Err(StoreError::InvalidCommit(
            "finalized block, block facts, and new head disagree".into(),
        ));
    }
    for tx in &commit.tx_facts {
        if tx.block != block {
            return Err(StoreError::InvalidCommit(
                "tx fact references another block".into(),
            ));
        }
    }
    for receipt in &commit.receipt_facts {
        if receipt.block != block {
            return Err(StoreError::InvalidCommit(
                "receipt fact references another block".into(),
            ));
        }
    }
    for log in &commit.ordered_logs {
        if log.block != block {
            return Err(StoreError::InvalidCommit(
                "ordered log references another block".into(),
            ));
        }
    }
    let mut result_keys = HashSet::new();
    for result in &commit.check_results {
        if result.block != block || result.coverage.block != block {
            return Err(StoreError::InvalidCommit(
                "check result references another block".into(),
            ));
        }
        if result.coverage.invariant_id != result.invariant_id
            || result.coverage.entity != result.entity
        {
            return Err(StoreError::InvalidCommit(
                "check result coverage key disagrees with result key".into(),
            ));
        }
        if !result_keys.insert((result.block, &result.invariant_id, &result.entity)) {
            return Err(StoreError::InvalidCommit(
                "duplicate check result for block/invariant/entity".into(),
            ));
        }
    }
    let mut coverage_keys = HashSet::new();
    for coverage in &commit.coverage_records {
        if coverage.block != block {
            return Err(StoreError::InvalidCommit(
                "coverage record references another block".into(),
            ));
        }
        if !coverage_keys.insert((coverage.block, &coverage.invariant_id, &coverage.entity)) {
            return Err(StoreError::InvalidCommit(
                "duplicate coverage record for block/invariant/entity".into(),
            ));
        }
    }
    for transition in &commit.finding_updates {
        if transition.at != block {
            return Err(StoreError::InvalidCommit(
                "finding transition references another block".into(),
            ));
        }
    }
    for health in &commit.health_updates {
        if health.at != block {
            return Err(StoreError::InvalidCommit(
                "health update references another block".into(),
            ));
        }
    }

    let catalog = initial_catalog();
    for id in commit
        .check_results
        .iter()
        .map(|r| &r.invariant_id)
        .chain(commit.coverage_records.iter().map(|r| &r.invariant_id))
        .chain(commit.finding_updates.iter().map(|r| &r.key.invariant_id))
        .chain(
            commit
                .outbox_events
                .iter()
                .map(|r| &r.finding_key.invariant_id),
        )
        .chain(commit.health_updates.iter().filter_map(health_invariant_id))
    {
        if catalog.get(id).is_none() {
            return Err(StoreError::UnknownInvariant(id.clone()));
        }
    }
    Ok(())
}

pub(super) fn validate_outbox_references(
    commit: &BlockCommit,
    mut finding_exists: impl FnMut(&FindingKey) -> Result<bool>,
) -> Result<()> {
    let transition_keys = commit
        .finding_updates
        .iter()
        .map(|transition| &transition.key)
        .collect::<HashSet<_>>();

    for event in &commit.outbox_events {
        if !transition_keys.contains(&event.finding_key) && !finding_exists(&event.finding_key)? {
            return Err(StoreError::InvalidCommit(
                "outbox event references unknown finding".into(),
            ));
        }
    }
    Ok(())
}

fn health_invariant_id(update: &MonitorHealthUpdate) -> Option<&InvariantId> {
    match &update.signal {
        MonitorHealthSignal::CoverageDegraded { invariant_id, .. }
        | MonitorHealthSignal::CheckError { invariant_id, .. } => Some(invariant_id),
        MonitorHealthSignal::Healthy | MonitorHealthSignal::StoreLag { .. } => None,
    }
}
