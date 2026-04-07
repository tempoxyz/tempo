use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Context, Runner},
};
use futures::future::join_all;
use reth_node_metrics::recorder::{PrometheusRecorder, install_prometheus_recorder};

use crate::{CONSENSUS_NODE_PREFIX, Setup, connect_execution_peers, setup_validators};

const PAYLOAD_FINALIZATION_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_payload_finalization_duration_seconds_count";
const STATE_ROOT_WITH_UPDATES_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_state_root_with_updates_duration_seconds_count";
const NULLIFICATIONS_PER_LEADER_METRIC_SUFFIX: &str = "_nullifications_per_leader";

#[test_traced]
fn shared_sparse_trie_single_validator_bypasses_sync_state_root() {
    let deltas = run_payload_builder_test(&[true], 10);

    assert!(
        deltas.finalization_count > 0,
        "expected payload builder finalization metrics to increase"
    );
    assert_eq!(
        deltas.state_root_count, 0,
        "expected shared sparse trie to bypass sync state-root work"
    );
}

#[test_traced]
fn mixed_validators_build_blocks_with_and_without_shared_sparse_trie_payload_builder() {
    let deltas = run_payload_builder_test(&[true, false], 10);

    assert_eq!(
        deltas.nullification_count, 0,
        "expected mixed sparse trie configuration to build without consensus nullifications"
    );
}

fn run_payload_builder_test(
    share_sparse_trie_with_payload_builder: &[bool],
    target_height: u64,
) -> MetricDelta {
    let _ = tempo_eyre::install();
    let metrics_recorder = install_prometheus_recorder();
    let initial_finalization_count =
        prometheus_histogram_count(metrics_recorder, PAYLOAD_FINALIZATION_COUNT_METRIC);
    let initial_state_root_count =
        prometheus_histogram_count(metrics_recorder, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);

    let nullification_count =
        Runner::from(Config::default().with_seed(0)).start(|mut context| async move {
            let setup = Setup::new()
                .how_many_signers(share_sparse_trie_with_payload_builder.len() as u32)
                .epoch_length(100);
            let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

            for (node, share_sparse_trie) in nodes
                .iter_mut()
                .zip(share_sparse_trie_with_payload_builder.iter().copied())
            {
                node.execution_config.share_sparse_trie_with_payload_builder = share_sparse_trie;
            }

            join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
            if nodes.len() > 1 {
                connect_execution_peers(&nodes).await;
            }

            wait_for_height(
                &context,
                share_sparse_trie_with_payload_builder.len() as u32,
                target_height,
            )
            .await;

            consensus_metric_sum(&context, NULLIFICATIONS_PER_LEADER_METRIC_SUFFIX)
        });

    let final_finalization_count =
        prometheus_histogram_count(metrics_recorder, PAYLOAD_FINALIZATION_COUNT_METRIC);
    let final_state_root_count =
        prometheus_histogram_count(metrics_recorder, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);

    MetricDelta {
        finalization_count: final_finalization_count - initial_finalization_count,
        state_root_count: final_state_root_count - initial_state_root_count,
        nullification_count,
    }
}

struct MetricDelta {
    finalization_count: u64,
    state_root_count: u64,
    nullification_count: u64,
}

async fn wait_for_height(context: &Context, expected_validators: u32, target_height: u64) {
    loop {
        let validators_at_height = context
            .encode()
            .lines()
            .filter(|line| line.starts_with(CONSENSUS_NODE_PREFIX))
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let metric = parts.next()?;
                let value = parts.next()?;
                metric
                    .ends_with("_marshal_processed_height")
                    .then(|| value.parse::<u64>().ok())?
            })
            .filter(|height| *height >= target_height)
            .count() as u32;

        if validators_at_height == expected_validators {
            break;
        }

        context.sleep(Duration::from_secs(1)).await;
    }
}

fn consensus_metric_sum(context: &Context, metric_suffix: &str) -> u64 {
    context
        .encode()
        .lines()
        .filter(|line| line.starts_with(CONSENSUS_NODE_PREFIX))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let metric = parts.next()?;
            let value = parts.next()?;
            metric
                .ends_with(metric_suffix)
                .then(|| value.parse::<u64>().ok())?
        })
        .sum()
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
