//! Validators keep their verdicts on the boundary blocks they verify while
//! execution records verdicts on many other blocks, as RPC re-executions do.

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
fn other_executions_do_not_displace_boundary_verdicts() {
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

        // Keep recording verdicts on other blocks in every validator, as RPC
        // re-executions of made-up boundary blocks would. Without registration,
        // these pushed the verdicts of real proposals out of a bounded record.
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
