use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

use crate::{Setup, run};

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
            how_many: 5,
            seed,
            linkage: link.clone(),
            height_to_reach: 5,
        };
        let first = run(setup.clone());

        std::thread::sleep(Duration::from_secs(1));

        let second = run(setup);
        assert_eq!(first, second);
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
            how_many: 5,
            seed,
            linkage: link.clone(),
            height_to_reach: 5,
        };
        let _first = run(setup.clone());

        std::thread::sleep(Duration::from_secs(1));

        // FIXME(janis): the events are currently not fully deterministic, so
        // two runs will not reproduce the exact same audit.
        //
        // let first = run(setup.clone());
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
        how_many: 10,
        seed: 0,
        linkage: link,
        height_to_reach: 20,
    };
    let _first = run(setup);
}
