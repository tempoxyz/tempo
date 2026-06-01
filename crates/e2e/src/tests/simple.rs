//! Simple tests: just start and build a few blocks.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{Setup, run};
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

#[test_traced]
fn single_node() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(1).epoch_length(100).seed(0);
    let _first = run(setup, |metric, value| {
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 5
        } else {
            false
        }
    });
}

#[test_traced]
fn speculative_bal_build_uses_parent_bal_sidecar() {
    let _ = tempo_eyre::install();

    let saw_use = Arc::new(AtomicBool::new(false));
    let stop_saw_use = saw_use.clone();
    let saw_fallback = Arc::new(AtomicBool::new(false));
    let stop_saw_fallback = saw_fallback.clone();
    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(100)
        .seed(0)
        .speculative_bal_build(true);
    let _state = run(setup, |metric, value| {
        if metric.contains("_speculative_bal_build_used") {
            let value = value.parse::<u64>().unwrap();
            let reached = value >= 1;
            if reached {
                stop_saw_use.store(true, Ordering::Relaxed);
            }
            false
        } else if metric.contains("_speculative_bal_build_fallbacks") {
            let value = value.parse::<u64>().unwrap();
            if value > 0 {
                stop_saw_fallback.store(true, Ordering::Relaxed);
            }
            false
        } else if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 20 && stop_saw_use.load(Ordering::Relaxed)
        } else {
            false
        }
    });
    assert!(saw_use.load(Ordering::Relaxed));
    assert!(!saw_fallback.load(Ordering::Relaxed));
}

#[test_traced]
fn only_good_links() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().epoch_length(100).seed(42);
    let _first = run(setup, |metric, value| {
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

    let setup = Setup::new().seed(42).epoch_length(100).linkage(link);

    let _first = run(setup, |metric, value| {
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
        .linkage(link);

    run(setup, |metric, value| {
        if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 20
        } else {
            false
        }
    });
}
