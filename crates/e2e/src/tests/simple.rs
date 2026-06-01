//! Simple tests: just start and build a few blocks.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::{Setup, run};
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use reth_node_metrics::recorder::{PrometheusRecorder, install_prometheus_recorder};

const SPARSE_TRIE_STATE_ROOT_WAIT_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_sparse_trie_state_root_wait_duration_seconds_count";

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
    let metrics_recorder = install_prometheus_recorder();
    let initial_sparse_trie_state_root_wait_count =
        prometheus_histogram_count(metrics_recorder, SPARSE_TRIE_STATE_ROOT_WAIT_COUNT_METRIC);

    let saw_use = Arc::new(AtomicBool::new(false));
    let stop_saw_use = saw_use.clone();
    let fallback_count = Arc::new(AtomicU64::new(0));
    let stop_fallback_count = fallback_count.clone();
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
            stop_fallback_count.store(value, Ordering::Relaxed);
            false
        } else if metric.ends_with("_marshal_processed_height") {
            let value = value.parse::<u64>().unwrap();
            value >= 20 && stop_saw_use.load(Ordering::Relaxed)
        } else {
            false
        }
    });
    let final_sparse_trie_state_root_wait_count =
        prometheus_histogram_count(metrics_recorder, SPARSE_TRIE_STATE_ROOT_WAIT_COUNT_METRIC);

    assert!(saw_use.load(Ordering::Relaxed));
    assert!(
        final_sparse_trie_state_root_wait_count > initial_sparse_trie_state_root_wait_count,
        "expected sparse trie state-root wait metric to increase"
    );
    assert!(
        fallback_count.load(Ordering::Relaxed) <= 1,
        "expected at most one bootstrap fallback before BAL sidecars are available"
    );
}

fn prometheus_histogram_count(recorder: &PrometheusRecorder, metric: &str) -> u64 {
    recorder.handle().run_upkeep();
    recorder
        .handle()
        .render()
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next()? == metric).then(|| parts.next()?.parse().ok())?
        })
        .unwrap_or(0)
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
