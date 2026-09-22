//! Validators continue finalizing across the epoch that activates the V1 elector.

use std::time::{Duration, UNIX_EPOCH};

use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;

use crate::{
    Setup, connect_execution_peers,
    metrics::{MetricsExt as _, wait_for_metrics},
    setup_validators,
};

#[test_traced]
fn validators_transition_to_v1_elector_at_t12() {
    let _ = tempo_eyre::install();
    const EPOCH_LENGTH: u64 = 20;
    const ACTIVATION: u64 = 1;

    // Genesis selects V0 for epoch zero. Although its blocks have T12 active,
    // the V1 leader schedule starts only in epoch one.
    let setup = Setup::new()
        .how_many_signers(4)
        .epoch_length(EPOCH_LENGTH)
        .t12_time(ACTIVATION);
    let cfg = Config::default()
        .with_seed(setup.seed)
        .with_start_time(UNIX_EPOCH + Duration::from_secs(ACTIVATION));

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        wait_for_metrics(&context, |metrics| {
            metrics.consensus_at_epoch(0) == validators.len()
        })
        .await;

        let metrics = context.to_metrics();
        for validator in &validators {
            let metrics = metrics.for_scope(validator);
            assert_eq!(metrics.latest_consensus_epoch(), Some(0));
            assert_eq!(
                metrics.value::<u64>("epoch_manager_elector_version"),
                Some(0)
            );
        }

        // Check the version once all validators enter the first epoch using V1.
        wait_for_metrics(&context, |metrics| {
            metrics.consensus_at_epoch(1) == validators.len()
        })
        .await;

        let metrics = context.to_metrics();
        for validator in &validators {
            let metrics = metrics.for_scope(validator);
            assert_eq!(metrics.latest_consensus_epoch(), Some(1));
            assert_eq!(
                metrics.value::<u64>("epoch_manager_elector_version"),
                Some(1)
            );
        }

        // Reaching epoch two on every validator means all of epoch one, where the
        // V1 elector first activates, has been observed and finalized by all nodes.
        let epoch_strategy = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let target = epoch_strategy.first(Epoch::new(2)).unwrap();
        wait_for_metrics(&context, |metrics| {
            metrics.consensus_at_height(target.get()) == validators.len()
        })
        .await;
    });
}
