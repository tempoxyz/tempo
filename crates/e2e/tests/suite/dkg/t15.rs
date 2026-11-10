//! A live validator network crosses T15, from which execution checks the
//! boundary DKG outcome against the parent state.

use std::time::{Duration, UNIX_EPOCH};

use alloy_primitives::Sealable as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
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
    // Epoch 0's boundary is before T15 and the later ones after it, in both
    // verification modes.
    const START: u64 = 1;
    const ACTIVATION: u64 = START + 4;
    const LAST_EPOCH: u64 = 5;

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(EPOCH_LENGTH)
        .t15_time(ACTIVATION);
    let cfg = Config::default()
        .with_seed(setup.seed)
        .with_start_time(UNIX_EPOCH + Duration::from_secs(START))
        // A boundary that validators reject stalls the chain; fail instead of hanging.
        .with_timeout(Some(Duration::from_secs(120)));

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;

        wait_for_metrics(&context, |metrics| {
            metrics.assert_no_dkg_failures();
            metrics.consensus_at_epoch(LAST_EPOCH) == validators.len()
        })
        .await;

        let epoch_strategy = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let players: Vec<_> = validators.iter().map(|node| node.public_key()).collect();
        let (mut before, mut after) = (0, 0);
        for epoch in 0..LAST_EPOCH - 1 {
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
            tracing::info!(epoch, timestamp, "boundary block");
            if timestamp < ACTIVATION {
                before += 1;
            } else {
                after += 1;
            }

            let outcome = read_outcome_from_validator(&validators[0], boundary).unwrap();
            assert_eq!(outcome.epoch, epoch + 1);
            assert!(!outcome.is_next_full_dkg);
            assert_eq!(outcome.next_players.len(), players.len());
            for player in &players {
                assert!(outcome.next_players.position(player).is_some());
            }
        }
        assert!(before > 0, "no boundary before T15");
        assert!(after > 0, "no boundary after T15");
    });
}
