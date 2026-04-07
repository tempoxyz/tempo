use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Context, Runner},
};
use futures::future::join_all;
use reth_node_metrics::recorder::{PrometheusRecorder, install_prometheus_recorder};
use tempo_e2e::{CONSENSUS_NODE_PREFIX, Setup, connect_execution_peers, setup_validators};

const PAYLOAD_FINALIZATION_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_payload_finalization_duration_seconds_count";
const STATE_ROOT_WITH_UPDATES_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_state_root_with_updates_duration_seconds_count";

#[test_traced]
fn mixed_validators_build_blocks_with_shared_sparse_trie_payload_builder() {
    let _ = tempo_eyre::install();
    let metrics_recorder = install_prometheus_recorder();
    let initial_finalization_count =
        prometheus_histogram_count(metrics_recorder, PAYLOAD_FINALIZATION_COUNT_METRIC);
    let initial_state_root_count =
        prometheus_histogram_count(metrics_recorder, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);

    Runner::from(Config::default().with_seed(0)).start(|mut context| async move {
        let setup = Setup::new().how_many_signers(2).epoch_length(100);
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        nodes[0]
            .execution_config
            .share_sparse_trie_with_payload_builder = true;
        nodes[1]
            .execution_config
            .share_sparse_trie_with_payload_builder = false;

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&nodes).await;

        wait_for_height(&context, 2, 10).await;
    });

    let final_finalization_count =
        prometheus_histogram_count(metrics_recorder, PAYLOAD_FINALIZATION_COUNT_METRIC);
    let final_state_root_count =
        prometheus_histogram_count(metrics_recorder, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);
    let finalization_delta = final_finalization_count - initial_finalization_count;
    let state_root_delta = final_state_root_count - initial_state_root_count;

    assert!(
        finalization_delta > 0,
        "expected payload builder finalization metrics to increase"
    );
    assert!(
        state_root_delta > 0,
        "expected the non-shared validator to keep using state_root_with_updates()"
    );
    assert!(
        state_root_delta < finalization_delta,
        "expected shared sparse trie finalizations to bypass state_root_with_updates()"
    );
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
