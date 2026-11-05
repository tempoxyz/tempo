//! Validators vote on a boundary block whose DKG outcome verdict was pushed out
//! of the execution layer's record before consensus read it.

use std::time::Duration;

use alloy_primitives::B256;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _, Spawner as _, Supervisor as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use super::common::wait_for_validators_to_reach_epoch;
use crate::{Setup, metrics::MetricsExt, setup_validators};

#[test_traced]
fn validators_check_boundary_outcomes_again_after_their_verdicts_are_evicted() {
    let _ = tempo_eyre::install();

    let how_many_signers = 4;
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(how_many_signers)
        .epoch_length(20);
    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Keep filling every validator's record with other blocks, as
        // re-executions of unrelated boundary blocks would, so the verdicts of
        // real proposals are gone by the time consensus reads them.
        let records: Vec<_> = validators
            .iter()
            .map(|v| v.execution().evm_config.boundary_outcome_checks().clone())
            .collect();
        context.child("evictor").spawn(move |context| async move {
            let mut filler = 0u64;
            loop {
                for record in &records {
                    for _ in 0..64 {
                        filler += 1;
                        record.record(B256::left_padding_from(&filler.to_be_bytes()), true);
                    }
                }
                context.sleep(Duration::from_millis(1)).await;
            }
        });

        wait_for_validators_to_reach_epoch(&context, 3, how_many_signers).await;
        context.to_metrics().assert_no_dkg_failures();
    });
}
