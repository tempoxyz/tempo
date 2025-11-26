use std::time::Duration;

use crate::{Setup, run};
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

#[test_traced]
fn only_good_links() {
    let _ = tempo_eyre::install();

    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    // FIXME(janis): figure out how to run this test in a loop.
    //
    // Opening too many databases in a row leads to errors like:
    //
    // must be able to launch execution nodes: failed initializing database
    //
    // Caused by:
    //     failed to open the database: unknown error code: 12 (12)
    //
    // for seed in 0..5 {
    for seed in 0..1 {
        let setup = Setup {
            how_many_signers: 4,
            seed,
            linkage: link.clone(),
            epoch_length: 100,
            connect_execution_layer_nodes: false,
        };
        let _first = run(setup.clone(), |metric, value| {
            // // TODO(janis): commonware calls this marshal, we call this sync.
            // // We should rename this to marshal (the actor, that is).
            if metric.ends_with("_marshal_processed_height") {
                let value = value.parse::<u64>().unwrap();
                value >= 5
            } else {
                false
            }
        });

        // FIXME(janis): there is some non-determinism and hence the runs are
        // sometimes flaky.
        //
        // let first = run(setup.clone(), |metric, value| {
        //     // // TODO(janis): commonware calls this marshal, we call this sync.
        //     // // We should rename this to marshal (the actor, that is).
        //     if metric.ends_with("_marshal_processed_height") {
        //         let value = value.parse::<u64>().unwrap();
        //         value >= 5
        //     } else {
        //         false
        //     }
        // });

        // std::thread::sleep(Duration::from_secs(1));

        // let second = run(setup.clone(), |metric, value| {
        //     // // TODO(janis): commonware calls this marshal, we call this sync.
        //     // // We should rename this to marshal (the actor, that is).
        //     if metric.ends_with("_marshal_processed_height") {
        //         let value = value.parse::<u64>().unwrap();
        //         value >= 5
        //     } else {
        //         false
        //     }
        // });
        // assert_eq!(first, second);
    }
}

#[test_traced]
fn many_bad_links() {
    let _ = tempo_eyre::install();

    let link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.75,
    };

    // FIXME(janis): figure out how to run this test in a loop.
    //
    // Opening too many databases in a row leads to errors like:
    //
    // must be able to launch execution nodes: failed initializing database
    //
    // Caused by:
    //     failed to open the database: unknown error code: 12 (12)
    //
    // for seed in 0..5 {
    for seed in 0..1 {
        let setup = Setup {
            how_many_signers: 5,
            seed,
            linkage: link.clone(),
            epoch_length: 100,
            connect_execution_layer_nodes: false,
        };
        let _first = run(setup.clone(), |metric, value| {
            // // TODO(janis): commonware calls this marshal, we call this sync.
            // // We should rename this to marshal (the actor, that is).
            if metric.ends_with("_marshal_processed_height") {
                let value = value.parse::<u64>().unwrap();
                value >= 5
            } else {
                false
            }
        });

        // FIXME(janis): the events are currently not fully deterministic, so
        // two runs will not reproduce the exact same audit.
        //
        // let first = run(setup.clone());
        // std::thread::sleep(Duration::from_secs(1));
        // let second = run(setup.clone());
        // assert_eq!(first, second);
    }
}

// TODO(janis): would be great to reach height 1000, but the way the execution
// layer is configured proposing takes roughly 1 to 2s *real time*. This means
// that <height-to-reach> * 2s (in this case, 40s) is a realistic runtime for
// this test.
#[test_traced]
fn reach_height_20_with_a_few_bad_links() {
    let _ = tempo_eyre::install();

    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let setup = Setup {
        how_many_signers: 10,
        seed: 0,
        linkage: link,
        epoch_length: 100,
        connect_execution_layer_nodes: false,
    };
    let _first = run(setup, |metric, value| {
        // // TODO(janis): commonware calls this marshal, we call this sync.
        // // We should rename this to marshal (the actor, that is).
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 20
        } else {
            false
        }
    });

    std::thread::sleep(Duration::from_secs(1));
}
