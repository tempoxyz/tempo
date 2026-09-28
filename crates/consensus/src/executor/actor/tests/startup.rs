use commonware_runtime::deterministic;

use super::*;
use crate::executor::{Config, init};
use harness::{FakeExecution, FakeMarshal, GENESIS};

#[test]
fn initialization_requires_a_reachable_finalized_floor() {
    for (execution_finalized, floor, backfill_available_through, should_start) in [
        (0, 0, 0, true),
        (1, 1, 0, true),
        (2, 1, 0, true),
        (0, 2, 2, true),
        (0, 2, 3, true),
        (1, 2, 2, true),
        (0, 2, 0, false),
        (0, 2, 1, false),
        (1, 2, 1, false),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let execution = FakeExecution::new();
            let mut digest = GENESIS;
            for height in 1..=execution_finalized {
                let block = make_block(height, height, digest);
                digest = block.digest();
                execution.seed_canonical_block(&block);
            }
            execution.set_finalized(execution_finalized, digest);

            let result = init(
                context,
                Config {
                    execution_node: execution,
                    finalized_floor: Height::new(floor),
                    finalized_tip: (round(floor), Height::new(floor), digest),
                    marshal: FakeMarshal::new(),
                    fcu_heartbeat_interval: std::time::Duration::from_secs(1),
                    public_key: None,
                    backfill_available_through: Height::new(backfill_available_through),
                },
            );

            if should_start {
                assert!(
                    result.is_ok(),
                    "{execution_finalized}/{floor}/{backfill_available_through}"
                );
            } else {
                let error = result
                    .err()
                    .expect("unreachable floor must fail initialization");
                assert_eq!(
                    error.root_cause().to_string(),
                    format!(
                        "execution layer finalized height `{execution_finalized}` cannot reach \
                         finalization archive floor `{floor}`. Run as a follower to sync to tip \
                         or restore a fresher snapshot"
                    ),
                );
            }
        });
    }
}
