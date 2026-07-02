use commonware_runtime::{Metrics as _, deterministic};
use reth_db::DatabaseEnv;
use reth_ethereum::provider::providers::BlockchainProvider;
use reth_node_builder::NodeTypesWithDBAdapter;
use tempo_node::node::TempoNode;

use crate::TestingNode;

pub async fn write_consensus_snapshot(
    context: &deterministic::Context,
    source: &TestingNode<deterministic::Context>,
    execution_provider: BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>,
    target_partition_prefix: &str,
) {
    let source_partition_prefix = source.consensus_config.partition_prefix.clone();
    let (archive_entries_tx, archive_entries_rx) = tokio::sync::mpsc::channel(64);

    let state = tempo_consensus::storage::snapshot::prepare_with_partition_prefix(
        &context.with_label("snapshot_prepare"),
        &source_partition_prefix,
        execution_provider,
        archive_entries_tx,
    )
    .await
    .expect("snapshot must prepare");

    tempo_consensus::storage::snapshot::write_archive_with_partition_prefix(
        &context.with_label("snapshot_write"),
        target_partition_prefix,
        archive_entries_rx,
    )
    .await
    .expect("snapshot must write");

    assert!(state.anchor_finalization_height > 0);
    assert!(state.tip_finalization_height >= state.anchor_finalization_height);
}
