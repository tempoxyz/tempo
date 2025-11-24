//! Tests on chain DKG and epoch transition

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

use crate::{Setup, run};

fn assert_static_transitions(how_many: u32, epoch_length: u64, transitions: u64) {
    let _ = tempo_eyre::install();
    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let setup = Setup {
        how_many_signers: how_many,
        seed: 0,
        linkage,
        epoch_length,
        connect_execution_layer_nodes: false,
    };

    let mut epoch_reached = false;
    let mut dkg_successful = false;
    let _first = run(setup, move |metric, value| {
        if metric.ends_with("_dkg_manager_ceremony_failures_total") {
            let value = value.parse::<u64>().unwrap();
            assert!(value < 1);
        }

        if metric.ends_with("_epoch_manager_latest_epoch") {
            let value = value.parse::<u64>().unwrap();
            epoch_reached |= value >= transitions;
        }
        if metric.ends_with("_dkg_manager_ceremony_successes_total") {
            let value = value.parse::<u64>().unwrap();
            dkg_successful |= value >= transitions;
        }
        epoch_reached && dkg_successful
    });
}

#[test_traced]
fn two_validators_can_transition_once() {
    assert_static_transitions(2, 20, 1);
}

#[test_traced]
fn two_validators_can_transition_twice() {
    assert_static_transitions(2, 20, 2);
}

#[test_traced]
fn four_validators_can_transition_once() {
    assert_static_transitions(4, 20, 1);
}

#[test_traced]
fn four_validators_can_transition_twice() {
    assert_static_transitions(4, 20, 2);
}

// #[test_traced]
// fn transitions_with_fallible_links() {
//     let _ = tempo_eyre::install();
//     let linkage = Link {
//         latency: Duration::from_millis(10),
//         jitter: Duration::from_millis(1),
//         success_rate: 0.9,
//     };

//     let setup = Setup {
//         how_many: 5,
//         seed: 0,
//         linkage,
//         epoch_length: 2,
//     };

//     let mut epoch_reached = false;
//     let mut height_reached = false;
//     let _first = run(setup, move |metric, value| {
//         if metric.ends_with("_epoch_manager_latest_epoch") {
//             let value = value.parse::<u64>().unwrap();
//             epoch_reached |= value >= 3;
//         }
//         if metric.ends_with("_sync_processed_height") {
//             let value = value.parse::<u64>().unwrap();
//             height_reached |= value >= 6;
//         }
//         epoch_reached && height_reached
//     });
// }
