//! Periodic forkchoice updates when deliveries do not change the head.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{GENESIS, Harness, STARTUP_FCU, make_block, round};

#[test_traced]
fn unchanged_forkchoice_is_reaffirmed_every_eight_deliveries() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Siblings execute successfully but never move the head off genesis.
        // Cover two full batches and one further delivery to check the reset.
        for view in 1..=17 {
            h.verify(round(view), make_block(view, 1, GENESIS))
                .await
                .expect("verification should complete")
                .expect("block should be valid");
            h.run_for(Duration::from_millis(1)).await;

            assert_eq!(h.execution.new_payloads().len(), view as usize);
            let mut expected = vec![STARTUP_FCU];
            expected.extend(vec![(GENESIS, GENESIS, false); (view / 8) as usize]);
            assert_eq!(
                h.execution.fcus(),
                expected,
                "unexpected forkchoice updates after {view} deliveries",
            );
            assert_eq!(h.execution.head(), GENESIS);
        }
    });
}
