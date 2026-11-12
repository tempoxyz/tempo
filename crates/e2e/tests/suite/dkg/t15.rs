//! A live validator network crosses T15, from which execution checks the
//! boundary DKG outcome against the parent state.

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
use reth_ethereum::provider::BlockReader as _;

use super::common::read_outcome_from_validator;
use crate::{Setup, metrics::wait_for_metrics, setup_validators};

#[test_traced]
fn validators_agree_on_boundary_outcomes_across_t15() {
    let _ = tempo_eyre::install();
    const EPOCH_LENGTH: u64 = 20;

    // T15 starts inactive and is scheduled once epoch 0's boundary is
    // finalized, so the switch lands in epoch 1 however long node startup
    // takes on the runner. Three validators tolerate no fault, so every block
    // needs all of them and none can fall behind while the others finish
    // epoch 1.
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(3)
        .epoch_length(EPOCH_LENGTH)
        .t15_time(u64::MAX);
    let cfg = Config::default()
        .with_seed(setup.seed)
        // A boundary that validators reject stalls the chain; fail instead of hanging.
        .with_timeout(Some(Duration::from_secs(120)));

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;

        wait_for_metrics(&context, |metrics| {
            metrics.assert_no_dkg_failures();
            metrics.consensus_at_epoch(1) == validators.len()
        })
        .await;
        // Stopping any validator halts the chain, so epoch 1's boundary is still
        // to come. One at a time: `stop_consensus` drains the aborted engine's
        // tasks so its storage can be reopened, which concurrent stops don't
        // guarantee.
        for node in &mut validators {
            node.stop_consensus().await;
        }
        for node in &mut validators {
            node.stop_execution().await;
        }

        // Every block so far is stamped before `activation`. Restart only once
        // the clock has reached it, so every block produced afterwards,
        // including epoch 1's boundary, is under T15.
        let activation = context
            .current()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1;
        execution_runtime.set_t15_time(activation).unwrap();
        context
            .sleep_until(UNIX_EPOCH + Duration::from_secs(activation))
            .await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;

        // Every validator has finalized epoch 2's boundary, so all of them have
        // executed the two before it.
        wait_for_metrics(&context, |metrics| {
            metrics.assert_no_dkg_failures();
            metrics.consensus_at_epoch(3) == validators.len()
        })
        .await;

        let epoch_strategy = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let players: Vec<_> = validators.iter().map(|node| node.public_key()).collect();
        for epoch in 0..2 {
            let boundary = epoch_strategy.last(Epoch::new(epoch)).unwrap();
            let blocks: Vec<_> = validators
                .iter()
                .map(|node| {
                    node.execution_provider()
                        .block_by_number(boundary.get())
                        .unwrap()
                        .expect("every validator has the boundary block")
                })
                .collect();
            assert!(
                blocks
                    .iter()
                    .all(|block| block.header.hash_slow() == blocks[0].header.hash_slow()),
                "validators disagree on the boundary block of epoch {epoch}"
            );
            let timestamp = blocks[0].header.inner.timestamp;
            tracing::info!(epoch, timestamp, activation, "boundary block");
            assert_eq!(
                timestamp >= activation,
                epoch == 1,
                "epoch {epoch}'s boundary at {timestamp} is on the wrong side of T15 at {activation}"
            );

            let outcome = read_outcome_from_validator(&validators[0], boundary).unwrap();
            assert_eq!(outcome.epoch, epoch + 1);
            assert!(!outcome.is_next_full_dkg);
            assert_eq!(outcome.next_players.len(), players.len());
            for player in &players {
                assert!(outcome.next_players.position(player).is_some());
            }
        }
    });
}
