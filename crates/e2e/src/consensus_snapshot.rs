use commonware_consensus::types::FixedEpocher;
use commonware_runtime::{Supervisor as _, deterministic};
use reth_db::DatabaseEnv;
use reth_ethereum::provider::{ChainSpecProvider as _, providers::BlockchainProvider};
use reth_node_builder::NodeTypesWithDBAdapter;
use tempo_node::node::TempoNode;

use crate::TestingNode;

pub async fn write_consensus_snapshot(
    context: &deterministic::Context,
    source: &TestingNode<deterministic::Context>,
    execution_provider: BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>,
    target_partition_prefix: &str,
) -> tempo_consensus::storage::snapshot::State {
    let source_partition_prefix = source.partition_prefix.clone();
    let epoch_strategy = FixedEpocher::new(
        execution_provider
            .chain_spec()
            .info
            .epoch_length()
            .expect("test chainspec must contain epochLength"),
    );
    let (archive_entries_tx, archive_entries_rx) = tokio::sync::mpsc::channel(64);

    let state = tempo_consensus::storage::snapshot::prepare(
        &context.child("snapshot_prepare"),
        &source_partition_prefix,
        execution_provider,
        archive_entries_tx,
        &epoch_strategy,
    )
    .await
    .expect("snapshot must prepare");

    tempo_consensus::storage::snapshot::write_archive(
        &context.child("snapshot_write"),
        target_partition_prefix,
        archive_entries_rx,
        &epoch_strategy,
    )
    .await
    .expect("snapshot must write");

    assert!(state.anchor_finalization_height > 0);
    assert!(state.tip_finalization_height >= state.anchor_finalization_height);

    state
}
