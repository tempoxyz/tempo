//! Common helpers for DKG tests.

use std::time::Duration;

use commonware_codec::ReadExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_runtime::{Clock as _, Metrics as _, deterministic::Context};
use commonware_utils::NZU64;
use reth_ethereum::provider::BlockReader as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use crate::{CONSENSUS_NODE_PREFIX, TestingNode};

/// Reads the DKG outcome from a block, returns None if block doesn't exist or has no outcome.
pub(super) fn read_outcome_from_validator(
    validator: &TestingNode<Context>,
    block_num: u64,
) -> Option<OnchainDkgOutcome> {
    let provider = validator.execution_provider();
    let block = provider.block_by_number(block_num).ok()??;
    let extra_data = &block.header.inner.extra_data;

    if extra_data.is_empty() {
        return None;
    }

    Some(OnchainDkgOutcome::read(&mut extra_data.as_ref()).expect("valid DKG outcome"))
}

/// Parses a metric line, returning (metric_name, value) if valid.
pub(super) fn parse_metric_line(line: &str) -> Option<(&str, u64)> {
    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
        return None;
    }

    let mut parts = line.split_whitespace();
    let metric = parts.next()?;
    let value = parts.next()?.parse().ok()?;

    Some((metric, value))
}

/// Waits for and reads the DKG outcome from the last block of the given epoch.
pub(super) async fn wait_for_outcome(
    context: &Context,
    validators: &[TestingNode<Context>],
    epoch: u64,
    epoch_length: u64,
) -> OnchainDkgOutcome {
    let block_num = FixedEpocher::new(NZU64!(epoch_length))
        .last(Epoch::new(epoch))
        .expect("valid epoch");

    tracing::info!(epoch, block_num, "Waiting for DKG outcome");

    loop {
        context.sleep(Duration::from_secs(1)).await;

        if let Some(outcome) = read_outcome_from_validator(&validators[0], block_num) {
            tracing::info!(
                epoch,
                block_num,
                outcome_epoch = %outcome.epoch,
                is_next_full_dkg = outcome.is_next_full_dkg,
                "Read DKG outcome"
            );
            return outcome;
        }
    }
}

/// Counts how many validators have reached the target epoch.
pub(super) fn count_validators_at_epoch(context: &Context, target_epoch: u64) -> u32 {
    let metrics = context.encode();
    let mut at_epoch = 0;

    for line in metrics.lines() {
        let Some((metric, value)) = parse_metric_line(line) else {
            continue;
        };

        if metric.ends_with("_epoch_manager_latest_epoch") && value >= target_epoch {
            at_epoch += 1;
        }
    }

    at_epoch
}

/// Waits until at least `min_validators` have reached the target epoch.
pub(super) async fn wait_for_epoch(context: &Context, target_epoch: u64, min_validators: u32) {
    tracing::info!(target_epoch, min_validators, "Waiting for epoch");

    loop {
        context.sleep(Duration::from_secs(1)).await;

        if count_validators_at_epoch(context, target_epoch) >= min_validators {
            tracing::info!(target_epoch, "Validators reached epoch");
            return;
        }
    }
}

/// Asserts that no DKG ceremony failures have occurred.
pub(super) fn assert_no_dkg_failures(context: &Context) {
    let metrics = context.encode();

    for line in metrics.lines() {
        let Some((metric, value)) = parse_metric_line(line) else {
            continue;
        };

        if metric.ends_with("_dkg_manager_ceremony_failures_total") {
            assert_eq!(0, value, "DKG ceremony failed: {metric}");
        }
    }
}

/// Asserts that at least one validator has skipped rounds (indicating sync occurred).
pub(super) fn assert_skipped_rounds(context: &Context) {
    let metrics = context.encode();

    for line in metrics.lines() {
        let Some((metric, value)) = parse_metric_line(line) else {
            continue;
        };

        if metric.ends_with("_rounds_skipped_total") && value > 0 {
            return;
        }
    }

    panic!("Expected at least one validator to have skipped rounds during sync");
}
