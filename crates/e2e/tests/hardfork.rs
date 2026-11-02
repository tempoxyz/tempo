//! Verification follows T14 at epoch boundaries without restarting validators.

use std::time::{Duration, UNIX_EPOCH};

use alloy_primitives::Sealable as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use reth_ethereum::provider::{BlockNumReader as _, BlockReader as _};
use tempo_e2e::{
    Setup,
    metrics::{MetricsExt as _, wait_for_height, wait_for_metrics},
    setup_validators,
};

#[test_traced]
fn verification_switches_to_deferred_at_t14() {
    let _ = tempo_eyre::install();
    const ACTIVATION: u64 = 1;
    const EPOCH_LENGTH: u64 = 10;
    let setup = Setup::default()
        .epoch_length(EPOCH_LENGTH)
        .t14_time(ACTIVATION);
    let config = Config::default()
        .with_seed(setup.seed)
        .with_start_time(UNIX_EPOCH + Duration::from_secs(ACTIVATION))
        .with_timeout(Some(Duration::from_secs(60)));

    Runner::from(config).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let boundary = epocher.last(Epoch::zero()).unwrap().get();

        // Marshal's processed height trails execution by a persistence batch,
        // which can span several epochs, so wait on the executed chain.
        for node in &validators {
            while node.execution_provider().best_block_number().unwrap() < 4 {
                context.sleep(Duration::from_millis(100)).await;
            }
        }
        for node in &validators {
            let metrics = context.to_metrics().for_scope(node);
            // All proposals are post-T14, but epoch zero uses the genesis timestamp.
            assert_eq!(metrics.latest_consensus_epoch(), Some(0));
            assert_eq!(
                metrics.value::<u64>("epoch_manager_deferred_verification"),
                Some(0)
            );
            assert!(
                metrics
                    .value::<u64>("application_build_duration_count")
                    .is_some()
            );
            let provider = node.execution_provider();
            let height = provider.best_block_number().unwrap();
            assert!(height < boundary);
            assert!(
                provider
                    .block_by_number(height)
                    .unwrap()
                    .unwrap()
                    .header
                    .inner
                    .timestamp
                    >= ACTIVATION
            );
            assert!(
                provider
                    .block_by_number(0)
                    .unwrap()
                    .unwrap()
                    .header
                    .inner
                    .timestamp
                    < ACTIVATION
            );
        }

        wait_for_metrics(&context, |metrics| {
            metrics.consensus_at_epoch(1) == validators.len()
        })
        .await;
        for node in &validators {
            let metrics = context.to_metrics().for_scope(node);
            assert_eq!(
                metrics.value::<u64>("epoch_manager_deferred_verification"),
                Some(1)
            );
            let block = node
                .execution_provider()
                .block_by_number(boundary)
                .unwrap()
                .unwrap();
            assert!(block.header.inner.timestamp >= ACTIVATION);
        }

        let target = epocher.first(Epoch::new(2)).unwrap().get() + 5;
        join_all(
            validators
                .iter()
                .map(|node| wait_for_height(&context, node, target)),
        )
        .await;

        let mut expected = None;
        for node in &validators {
            let metrics = context.to_metrics().for_scope(node);
            assert_eq!(
                metrics.value::<u64>("epoch_manager_deferred_verification"),
                Some(1)
            );
            assert!(
                metrics
                    .value::<u64>("application_build_duration_count")
                    .is_some()
            );
            let block = node
                .execution_provider()
                .block_by_number(target)
                .unwrap()
                .unwrap();
            assert!(block.header.inner.timestamp >= ACTIVATION);
            if let Some(hash) = expected {
                assert_eq!(block.header.hash_slow(), hash);
            } else {
                expected = Some(block.header.hash_slow());
            }
        }
    });
}
