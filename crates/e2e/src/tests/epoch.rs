use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

use crate::{Setup, run};

#[test_traced]
fn transitions_three_epochs() {
    let _ = tempo_eyre::install();
    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let setup = Setup {
        how_many: 5,
        seed: 0,
        linkage,
        heights_per_epoch: 2,
    };
    let _first = run(setup, |metric, value| {
        if metric.ends_with("_orchestrator_latest_epoch") {
            let value = value.parse::<u64>().unwrap();
            value >= 3
        } else {
            false
        }
    });

    std::thread::sleep(Duration::from_secs(1));
}
