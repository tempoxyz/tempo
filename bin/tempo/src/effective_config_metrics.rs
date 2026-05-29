use crate::TempoArgs;
use reth_ethereum::node::core::args::{EngineArgs, PayloadBuilderArgs};
use tempo_node::{TempoFullNode, TempoNodeArgs};

#[derive(Debug, Clone, Copy, PartialEq)]
struct Snapshot {
    payload_builder_prewarming_enabled: bool,
    payload_builder_state_provider_metrics_enabled: bool,
    payload_builder_build_time_multiplier: f64,
    payload_builder_max_tasks: usize,
    txpool_aa_valid_after_max_secs: u64,
    txpool_max_tempo_authorizations: usize,
    engine_state_cache_enabled: bool,
    engine_prewarming_enabled: bool,
    engine_state_provider_metrics_enabled: bool,
    engine_cache_metrics_enabled: bool,
    engine_cross_block_cache_size_bytes: usize,
    engine_share_execution_cache_with_payload_builder_enabled: bool,
    engine_share_sparse_trie_with_payload_builder_enabled: bool,
    engine_sparse_trie_cache_pruning_enabled: bool,
    engine_sparse_trie_max_hot_slots: usize,
    engine_sparse_trie_max_hot_accounts: usize,
}

impl Snapshot {
    fn from_node(args: &TempoArgs, node: &TempoFullNode) -> Self {
        Self::from_parts(&args.node_args, &node.config.builder, &node.config.engine)
    }

    fn from_parts(
        node_args: &TempoNodeArgs,
        builder: &PayloadBuilderArgs,
        engine: &EngineArgs,
    ) -> Self {
        Self {
            payload_builder_prewarming_enabled: node_args.builder_enable_prewarming,
            payload_builder_state_provider_metrics_enabled: node_args
                .builder_state_provider_metrics,
            payload_builder_build_time_multiplier: node_args.builder_build_time_multiplier,
            payload_builder_max_tasks: builder.max_payload_tasks,
            txpool_aa_valid_after_max_secs: node_args.aa_valid_after_max_secs,
            txpool_max_tempo_authorizations: node_args.max_tempo_authorizations,
            engine_state_cache_enabled: !engine.state_cache_disabled,
            engine_prewarming_enabled: !engine.prewarming_disabled,
            engine_state_provider_metrics_enabled: engine.state_provider_metrics,
            engine_cache_metrics_enabled: !engine.cache_metrics_disabled,
            engine_cross_block_cache_size_bytes: engine
                .cross_block_cache_size
                .saturating_mul(1024 * 1024),
            engine_share_execution_cache_with_payload_builder_enabled: engine
                .share_execution_cache_with_payload_builder,
            engine_share_sparse_trie_with_payload_builder_enabled: engine
                .share_sparse_trie_with_payload_builder,
            engine_sparse_trie_cache_pruning_enabled: !engine.disable_sparse_trie_cache_pruning,
            engine_sparse_trie_max_hot_slots: engine.sparse_trie_max_hot_slots,
            engine_sparse_trie_max_hot_accounts: engine.sparse_trie_max_hot_accounts,
        }
    }

    fn record(self) {
        describe();

        metrics::gauge!("tempo_payload_builder_prewarming_enabled")
            .set(bool_gauge(self.payload_builder_prewarming_enabled));
        metrics::gauge!("tempo_payload_builder_state_provider_metrics_enabled").set(bool_gauge(
            self.payload_builder_state_provider_metrics_enabled,
        ));
        metrics::gauge!("tempo_payload_builder_build_time_multiplier")
            .set(self.payload_builder_build_time_multiplier);
        metrics::gauge!("tempo_payload_builder_max_tasks")
            .set(self.payload_builder_max_tasks as f64);
        metrics::gauge!("tempo_txpool_aa_valid_after_max_secs")
            .set(self.txpool_aa_valid_after_max_secs as f64);
        metrics::gauge!("tempo_txpool_max_tempo_authorizations")
            .set(self.txpool_max_tempo_authorizations as f64);
        metrics::gauge!("tempo_engine_state_cache_enabled")
            .set(bool_gauge(self.engine_state_cache_enabled));
        metrics::gauge!("tempo_engine_prewarming_enabled")
            .set(bool_gauge(self.engine_prewarming_enabled));
        metrics::gauge!("tempo_engine_state_provider_metrics_enabled")
            .set(bool_gauge(self.engine_state_provider_metrics_enabled));
        metrics::gauge!("tempo_engine_cache_metrics_enabled")
            .set(bool_gauge(self.engine_cache_metrics_enabled));
        metrics::gauge!("tempo_engine_cross_block_cache_size_bytes")
            .set(self.engine_cross_block_cache_size_bytes as f64);
        metrics::gauge!("tempo_engine_share_execution_cache_with_payload_builder_enabled").set(
            bool_gauge(self.engine_share_execution_cache_with_payload_builder_enabled),
        );
        metrics::gauge!("tempo_engine_share_sparse_trie_with_payload_builder_enabled").set(
            bool_gauge(self.engine_share_sparse_trie_with_payload_builder_enabled),
        );
        metrics::gauge!("tempo_engine_sparse_trie_cache_pruning_enabled")
            .set(bool_gauge(self.engine_sparse_trie_cache_pruning_enabled));
        metrics::gauge!("tempo_engine_sparse_trie_max_hot_slots")
            .set(self.engine_sparse_trie_max_hot_slots as f64);
        metrics::gauge!("tempo_engine_sparse_trie_max_hot_accounts")
            .set(self.engine_sparse_trie_max_hot_accounts as f64);
    }
}

pub(crate) fn record(args: &TempoArgs, node: &TempoFullNode) {
    Snapshot::from_node(args, node).record();
}

const fn bool_gauge(value: bool) -> f64 {
    if value { 1.0 } else { 0.0 }
}

fn describe() {
    metrics::describe_gauge!(
        "tempo_payload_builder_prewarming_enabled",
        "Whether Tempo payload-builder transaction prewarming is enabled."
    );
    metrics::describe_gauge!(
        "tempo_payload_builder_state_provider_metrics_enabled",
        "Whether Tempo payload-builder state provider latency metrics are enabled."
    );
    metrics::describe_gauge!(
        "tempo_payload_builder_build_time_multiplier",
        "Initial Tempo payload-builder replayable work multiplier."
    );
    metrics::describe_gauge!(
        "tempo_payload_builder_max_tasks",
        "Maximum number of concurrent payload builder tasks."
    );
    metrics::describe_gauge!(
        "tempo_txpool_aa_valid_after_max_secs",
        "Maximum allowed valid_after offset for AA transactions."
    );
    metrics::describe_gauge!(
        "tempo_txpool_max_tempo_authorizations",
        "Maximum number of Tempo authorizations allowed in an AA transaction."
    );
    metrics::describe_gauge!(
        "tempo_engine_state_cache_enabled",
        "Whether the Reth engine state cache is enabled."
    );
    metrics::describe_gauge!(
        "tempo_engine_prewarming_enabled",
        "Whether Reth engine parallel prewarming is enabled."
    );
    metrics::describe_gauge!(
        "tempo_engine_state_provider_metrics_enabled",
        "Whether Reth engine state provider latency metrics are enabled."
    );
    metrics::describe_gauge!(
        "tempo_engine_cache_metrics_enabled",
        "Whether Reth engine cache metrics recording is enabled."
    );
    metrics::describe_gauge!(
        "tempo_engine_cross_block_cache_size_bytes",
        metrics::Unit::Bytes,
        "Configured Reth engine cross-block cache size."
    );
    metrics::describe_gauge!(
        "tempo_engine_share_execution_cache_with_payload_builder_enabled",
        "Whether payload builder jobs receive the engine cross-block execution cache."
    );
    metrics::describe_gauge!(
        "tempo_engine_share_sparse_trie_with_payload_builder_enabled",
        "Whether payload builder jobs share the Reth engine sparse trie."
    );
    metrics::describe_gauge!(
        "tempo_engine_sparse_trie_cache_pruning_enabled",
        "Whether Reth sparse trie cache pruning is enabled."
    );
    metrics::describe_gauge!(
        "tempo_engine_sparse_trie_max_hot_slots",
        "Maximum storage slots retained across sparse trie prune cycles."
    );
    metrics::describe_gauge!(
        "tempo_engine_sparse_trie_max_hot_accounts",
        "Maximum account addresses retained across sparse trie prune cycles."
    );
}

#[cfg(test)]
mod tests {
    use super::Snapshot;
    use crate::{Commands, TempoCli, init_defaults_once};
    use clap::Parser;

    #[test]
    fn snapshot_reflects_effective_args() {
        init_defaults_once();

        let cli = TempoCli::try_parse_from([
            "tempo",
            "node",
            "--dev",
            "--builder.enable-prewarming",
            "--builder.state-provider-metrics",
            "--builder.build-time-multiplier",
            "2.5",
            "--builder.max-tasks",
            "1",
            "--txpool.aa-valid-after-max-secs",
            "42",
            "--txpool.max-tempo-authorizations",
            "7",
            "--engine.disable-state-cache",
            "--engine.disable-prewarming",
            "--engine.state-provider-metrics",
            "--engine.disable-cache-metrics",
            "--engine.cross-block-cache-size",
            "789",
            "--engine.share-execution-cache-with-payload-builder",
            "--engine.share-sparse-trie-with-payload-builder",
            "--engine.disable-sparse-trie-cache-pruning",
            "--engine.sparse-trie-max-hot-slots",
            "123",
            "--engine.sparse-trie-max-hot-accounts",
            "456",
        ])
        .unwrap();
        let Commands::Node(node_cmd) = cli.command else {
            panic!("expected node command");
        };

        let snapshot =
            Snapshot::from_parts(&node_cmd.ext.node_args, &node_cmd.builder, &node_cmd.engine);

        assert_eq!(
            snapshot,
            Snapshot {
                payload_builder_prewarming_enabled: true,
                payload_builder_state_provider_metrics_enabled: true,
                payload_builder_build_time_multiplier: 2.5,
                payload_builder_max_tasks: 1,
                txpool_aa_valid_after_max_secs: 42,
                txpool_max_tempo_authorizations: 7,
                engine_state_cache_enabled: false,
                engine_prewarming_enabled: false,
                engine_state_provider_metrics_enabled: true,
                engine_cache_metrics_enabled: false,
                engine_cross_block_cache_size_bytes: 789 * 1024 * 1024,
                engine_share_execution_cache_with_payload_builder_enabled: true,
                engine_share_sparse_trie_with_payload_builder_enabled: true,
                engine_sparse_trie_cache_pruning_enabled: false,
                engine_sparse_trie_max_hot_slots: 123,
                engine_sparse_trie_max_hot_accounts: 456,
            }
        );
    }
}
