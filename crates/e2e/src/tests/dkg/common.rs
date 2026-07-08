//! Common helpers for DKG tests.

use std::time::Duration;

use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_runtime::{Clock as _, deterministic::Context};
use commonware_utils::NZU64;
use reth_ethereum::provider::BlockReader as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use crate::{TestingNode, metrics::wait_for_metrics};

/// Returns the target epoch to wait for depending on `event_height`.
///
/// If `event_height` is less than a boundary height, then the next epoch is
/// returned. Otherwise, the one *after* the next is returned.
pub(crate) fn target_epoch(epoch_length: u64, event_height: u64) -> Epoch {
    let strat = FixedEpocher::new(NZU64!(epoch_length));
    let event_height = Height::new(event_height);
    let info = strat.containing(event_height).unwrap();
    if info.last() == event_height {
        info.epoch().next().next()
    } else {
        info.epoch().next()
    }
}

/// Reads the DKG outcome from a block, returns None if block doesn't exist or has no outcome.
pub(crate) fn read_outcome_from_validator(
    validator: &TestingNode<Context>,
    block_num: Height,
) -> Option<OnchainDkgOutcome> {
    let provider = validator.execution_provider();
    let block = provider.block_by_number(block_num.get()).ok()??;
    let extra_data = &block.header.inner.extra_data;

    if extra_data.is_empty() {
        return None;
    }

    Some(OnchainDkgOutcome::decode(extra_data.as_ref()).expect("valid DKG outcome"))
}

/// Waits for and reads the DKG outcome from the last block of the given epoch.
pub(crate) async fn wait_for_outcome(
    context: &Context,
    validators: &[TestingNode<Context>],
    epoch: u64,
    epoch_length: u64,
) -> OnchainDkgOutcome {
    let height = FixedEpocher::new(NZU64!(epoch_length))
        .last(Epoch::new(epoch))
        .expect("valid epoch");

    tracing::info!(epoch, %height, "Waiting for DKG outcome");

    loop {
        context.sleep(Duration::from_secs(1)).await;

        if let Some(outcome) = read_outcome_from_validator(&validators[0], height) {
            tracing::info!(
                epoch,
                %height,
                outcome_epoch = %outcome.epoch,
                is_next_full_dkg = outcome.is_next_full_dkg,
                "Read DKG outcome"
            );
            return outcome;
        }
    }
}

/// Waits until at least `min_validators` have reached the target epoch.
pub(crate) async fn wait_for_validators_to_reach_epoch(
    context: &Context,
    target_epoch: u64,
    min_validators: u32,
) {
    tracing::info!(target_epoch, min_validators, "Waiting for epoch");

    wait_for_metrics(context, |metrics| {
        metrics.consensus_at_epoch(target_epoch) >= min_validators as usize
    })
    .await;

    tracing::info!(target_epoch, "Validators reached epoch");
}
