//! Simple tests: just start and build a few blocks.
use std::time::Duration;

use crate::{Setup, run, tests::v2_at_genesis::assert_no_v1};
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

#[test_traced]
fn single_node() {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(100)
        .t2_time(0)
        .seed(0);
    let _first = run(setup, |metric, value| {
        assert_no_v1(metric, value);
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 5
        } else {
            false
        }
    });
}

#[test_traced]
fn only_good_links() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().epoch_length(100).t2_time(0).seed(42);
    let _first = run(setup, |metric, value| {
        assert_no_v1(metric, value);
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 5
        } else {
            false
        }
    });
}

#[test_traced]
fn many_bad_links() {
    let _ = tempo_eyre::install();

    let link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.75,
    };

    let setup = Setup::new()
        .seed(42)
        .epoch_length(100)
        .t2_time(0)
        .linkage(link);

    let _first = run(setup, |metric, value| {
        assert_no_v1(metric, value);
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 5
        } else {
            false
        }
    });
}

#[test_traced]
fn reach_height_20_with_a_few_bad_links() {
    let _ = tempo_eyre::install();

    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let setup = Setup::new()
        .how_many_signers(10)
        .epoch_length(100)
        .t2_time(0)
        .linkage(link);

    run(setup, |metric, value| {
        assert_no_v1(metric, value);
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 20
        } else {
            false
        }
    });
}
