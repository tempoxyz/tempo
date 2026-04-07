use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use reth_ethereum::provider::BlockNumReader as _;
use reth_node_metrics::recorder::{PrometheusRecorder, install_prometheus_recorder};
use tempo_e2e::{Setup, setup_validators};

const PAYLOAD_FINALIZATION_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_payload_finalization_duration_seconds_count";
const STATE_ROOT_WITH_UPDATES_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_state_root_with_updates_duration_seconds_count";

#[test_traced]
fn single_node_builds_blocks_with_shared_sparse_trie_payload_builder() {
    let _ = tempo_eyre::install();
    let metrics_recorder = install_prometheus_recorder();
    let initial_finalization_count =
        prometheus_histogram_count(metrics_recorder, PAYLOAD_FINALIZATION_COUNT_METRIC);
    let initial_state_root_count =
        prometheus_histogram_count(metrics_recorder, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);

    Runner::from(Config::default().with_seed(0)).start(|mut context| async move {
        let setup = Setup::new().how_many_signers(1).epoch_length(100);
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        nodes[0]
            .execution_config
            .share_sparse_trie_with_payload_builder = true;
        nodes[0].start(&context).await;

        while nodes[0].execution_provider().last_block_number().unwrap() < 10 {
            context.sleep(Duration::from_secs(1)).await;
        }
    });

    let final_finalization_count =
        prometheus_histogram_count(metrics_recorder, PAYLOAD_FINALIZATION_COUNT_METRIC);
    let final_state_root_count =
        prometheus_histogram_count(metrics_recorder, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);

    assert!(
        final_finalization_count > initial_finalization_count,
        "expected payload builder finalization metrics to increase"
    );
    assert_eq!(
        final_state_root_count, initial_state_root_count,
        "shared sparse trie should bypass payload builder state_root_with_updates()"
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
