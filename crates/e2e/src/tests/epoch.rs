use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

use crate::{Setup, run};

#[test_traced]
fn transitions_with_perfect_links() {
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

    let mut epoch_reached = false;
    let mut height_reached = false;
    let _first = run(setup, move |metric, value| {
        if metric.ends_with("_epoch_manager_latest_epoch") {
            let value = value.parse::<u64>().unwrap();
            epoch_reached |= value >= 3;
        }
        if metric.ends_with("_sync_processed_height") {
            let value = value.parse::<u64>().unwrap();
            height_reached |= value >= 6;
        }
        epoch_reached && height_reached
    });
}

#[test_traced]
fn transitions_with_fallible_links() {
    let _ = tempo_eyre::install();
    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 0.9,
    };

    let setup = Setup {
        how_many: 5,
        seed: 0,
        linkage,
        heights_per_epoch: 2,
    };

    let mut epoch_reached = false;
    let mut height_reached = false;
    let _first = run(setup, move |metric, value| {
        if metric.ends_with("_epoch_manager_latest_epoch") {
            let value = value.parse::<u64>().unwrap();
            epoch_reached |= value >= 3;
        }
        if metric.ends_with("_sync_processed_height") {
            let value = value.parse::<u64>().unwrap();
            height_reached |= value >= 6;
        }
        epoch_reached && height_reached
    });
}
