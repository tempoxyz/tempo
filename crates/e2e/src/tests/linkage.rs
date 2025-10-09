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
            // TODO(janis): smarter way to get this name in here?
            name: "linkage::success_rate_100",
            how_many: 5,
            seed,
            linkage: link.clone(),
            height_to_reach: 5,
        };
        let first = run(setup.clone());

        std::thread::sleep(Duration::from_secs(1));

        let second = run(setup);
        assert_eq!(first, second);
        println!("first: {first} second: {second}");
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
            name: "linkage::success_rate_75",
            how_many: 5,
            seed,
            linkage: link.clone(),
            height_to_reach: 25,
        };
        let _first = run(setup);
        // FIXME(janis): our events are non-deterministic; likely due to the
        // async interaction with the execution layer.
        // How to fix that?
        //
        // let second = run(setup.clone());
        // assert_eq!(first, second);
    }
}

// TODO(janis): would be great to reach height 1000, but it takes toon long right now.
// There are a lot of nullifications and view timeouts.
#[test_traced]
fn reach_height_100_with_a_few_bad_links() {
    let _ = tempo_eyre::install();

    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let setup = Setup {
        // TODO(janis): smarter way to get this name in here?
        name: "linkage::success_rate_98_up_to_height_100",
        how_many: 10,
        seed: 0,
        linkage: link,
        height_to_reach: 100,
    };
    let _first = run(setup);
}
