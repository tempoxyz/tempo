use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadAttributes};
use reth_e2e_test_utils::{NodeHelperType, node::NodeTestContext};
use reth_ethereum::tasks::Runtime;
use reth_node_api::{BuiltPayload, TreeConfig};
use reth_node_builder::{EngineNodeLauncher, Node as _, NodeBuilder, NodeHandle};
use reth_node_core::args::{DiscoveryArgs, NetworkArgs, RpcServerArgs};
use reth_node_metrics::recorder::{PrometheusRecorder, install_prometheus_recorder};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{BlockNumReader, HeaderProvider, providers::BlockchainProvider};
use reth_qmdb::{QmdbConfig, QmdbState};
use reth_rpc_builder::RpcModuleSelection;
use std::{sync::Arc, time::Duration};
use tempo_chainspec::spec::{TempoChainSpec, TempoStateRootScheme};
use tempo_node::{
    node::{QmdbArgs, StateRootBackend, TempoNode, TempoNodeArgs},
    qmdb::qmdb_engine_tree_config,
};
use tempo_payload_types::TempoPayloadAttributes;

const QMDB_SHARED_ROOT_WAIT_COUNT_METRIC: &str =
    "reth_tempo_qmdb_shared_root_wait_duration_seconds_count";
const STATE_ROOT_WITH_UPDATES_COUNT_METRIC: &str =
    "reth_tempo_payload_builder_state_root_with_updates_duration_seconds_count";

fn test_payload_attributes(timestamp: u64) -> TempoPayloadAttributes {
    PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
        slot_number: None,
    }
    .into()
}

fn test_qmdb_chain_spec() -> eyre::Result<TempoChainSpec> {
    let genesis = serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    Ok(TempoChainSpec::from_genesis(genesis).with_state_root_scheme(TempoStateRootScheme::Qmdb))
}

async fn launch_qmdb_node_with(
    tree_config: TreeConfig,
    qmdb_args: QmdbArgs,
) -> eyre::Result<(NodeHelperType<TempoNode>, Runtime, QmdbConfig)> {
    reth_tracing::init_test_tracing();

    let runtime = Runtime::test();
    let chain_spec = Arc::new(test_qmdb_chain_spec()?);
    let network = NetworkArgs {
        discovery: DiscoveryArgs {
            disable_discovery: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let rpc = RpcServerArgs::default()
        .with_unused_ports()
        .with_http()
        .with_http_api(RpcModuleSelection::All);
    let mut config = reth_node_builder::NodeConfig::new(chain_spec)
        .with_network(network)
        .with_unused_ports()
        .with_rpc(rpc)
        .set_dev(true);
    config.txpool.max_account_slots = usize::MAX;

    let node_args = TempoNodeArgs {
        state_root_backend: Some(StateRootBackend::Qmdb),
        qmdb: qmdb_args.clone(),
        ..Default::default()
    };
    let tempo_node = TempoNode::new(&node_args, None);

    let NodeHandle {
        node,
        node_exit_future: _node_exit_future,
    } = NodeBuilder::new(config)
        .testing_node(runtime.clone())
        .with_types_and_provider::<TempoNode, BlockchainProvider<_>>()
        .with_components(tempo_node.components_builder())
        .with_add_ons(tempo_node.add_ons())
        .launch_with_fn(|builder| {
            let launcher = EngineNodeLauncher::new(
                builder.task_executor().clone(),
                builder.config().datadir(),
                qmdb_engine_tree_config(tree_config),
            );
            builder.launch_with(launcher)
        })
        .await?;

    let node = NodeTestContext::new(node, test_payload_attributes).await?;
    let genesis = node.block_hash(0);
    node.update_forkchoice(genesis, genesis).await?;
    let qmdb_config = QmdbConfig::new(node.inner.config.datadir().data_dir().join("qmdb"))
        .with_partition_prefix(qmdb_args.partition_prefix)
        .with_worker_threads(qmdb_args.qmdb_worker_threads);

    Ok((node, runtime, qmdb_config))
}

async fn launch_qmdb_node() -> eyre::Result<(NodeHelperType<TempoNode>, Runtime, QmdbConfig)> {
    launch_qmdb_node_with(
        TreeConfig::default()
            .with_persistence_threshold(0)
            .with_memory_block_buffer_target(0),
        QmdbArgs {
            batch_blocks: 1,
            qmdb_worker_threads: 2,
            partition_prefix: "state".to_string(),
        },
    )
    .await
}

async fn wait_for_head(
    node: &NodeHelperType<TempoNode>,
    number: u64,
    hash: B256,
) -> eyre::Result<()> {
    for _ in 0..500 {
        if node.inner.provider.last_block_number()? == number && node.block_hash(number) == hash {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    eyre::bail!("timed out waiting for canonical head {number} {hash}")
}

async fn wait_for_qmdb_head(config: &QmdbConfig, number: u64, hash: B256) -> eyre::Result<()> {
    for _ in 0..500 {
        let state = QmdbState::open(config.clone())?;
        if let Some(head) = state.head()?
            && head.number == number
            && head.hash == hash
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    eyre::bail!("timed out waiting for QMDB head {number} {hash}")
}

async fn shutdown_engine(node: &NodeHelperType<TempoNode>) -> eyre::Result<()> {
    let shutdown = node
        .inner
        .add_ons_handle
        .engine_shutdown
        .shutdown()
        .expect("engine shutdown should be available");
    shutdown.await?;
    Ok(())
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

#[tokio::test(flavor = "multi_thread")]
async fn qmdb_dev_node_default_tree_config_persists_each_payload() -> eyre::Result<()> {
    let (mut node, _runtime, qmdb_config) = launch_qmdb_node_with(
        TreeConfig::default(),
        QmdbArgs {
            batch_blocks: 1_000,
            qmdb_worker_threads: 2,
            partition_prefix: "state".to_string(),
        },
    )
    .await?;

    for _ in 0..6 {
        let payload = node.advance_block().await?;
        let block = payload.block();
        wait_for_head(&node, block.number(), block.hash()).await?;
        wait_for_qmdb_head(&qmdb_config, block.number(), block.hash()).await?;
    }

    shutdown_engine(&node).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn qmdb_dev_node_persists_empty_payload_root() -> eyre::Result<()> {
    let (mut node, _runtime, qmdb_config) = launch_qmdb_node().await?;

    let payload = node.advance_block().await?;
    let block = payload.block();
    wait_for_head(&node, block.number(), block.hash()).await?;

    shutdown_engine(&node).await?;

    let state = QmdbState::open(qmdb_config.clone())?;
    let head = state.head()?.expect("QMDB head should exist");
    let header = node
        .inner
        .provider
        .header_by_number(block.number())?
        .expect("canonical header should exist");

    assert_eq!(head.number, block.number());
    assert_eq!(head.hash, block.hash());
    assert_eq!(head.root, header.state_root());
    drop(state);

    let reopened = QmdbState::open(qmdb_config)?;
    assert_eq!(reopened.head()?, Some(head));
    assert_eq!(reopened.root()?, head.root);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn qmdb_shared_root_bypasses_sync_state_root_metric() -> eyre::Result<()> {
    let metrics = install_prometheus_recorder();
    let initial_qmdb_wait =
        prometheus_histogram_count(&metrics, QMDB_SHARED_ROOT_WAIT_COUNT_METRIC);
    let initial_sync_state_root =
        prometheus_histogram_count(&metrics, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);
    let (mut node, _runtime, _qmdb_config) = launch_qmdb_node().await?;

    for _ in 0..3 {
        let payload = node.advance_block().await?;
        let block = payload.block();
        wait_for_head(&node, block.number(), block.hash()).await?;
    }

    shutdown_engine(&node).await?;

    let final_qmdb_wait = prometheus_histogram_count(&metrics, QMDB_SHARED_ROOT_WAIT_COUNT_METRIC);
    let final_sync_state_root =
        prometheus_histogram_count(&metrics, STATE_ROOT_WITH_UPDATES_COUNT_METRIC);

    assert!(
        final_qmdb_wait > initial_qmdb_wait,
        "expected QMDB shared-root wait metric to increase"
    );
    assert_eq!(
        final_sync_state_root - initial_sync_state_root,
        0,
        "expected QMDB shared-root mode to bypass sync state_root_with_updates"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn qmdb_dev_node_rewinds_on_reorg() -> eyre::Result<()> {
    let (mut node, _runtime, qmdb_config) = launch_qmdb_node().await?;

    let parent = node.block_hash(0);
    let payload_a = node.build_and_submit_payload().await?;
    let hash_a = payload_a.block().hash();
    let payload_b = node.build_and_submit_payload().await?;
    let hash_b = payload_b.block().hash();

    node.update_forkchoice(parent, hash_a).await?;
    wait_for_head(&node, 1, hash_a).await?;
    node.inner
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(
            ForkchoiceState {
                head_block_hash: hash_b,
                safe_block_hash: parent,
                finalized_block_hash: parent,
            },
            None,
        )
        .await?;
    wait_for_head(&node, 1, hash_b).await?;
    wait_for_qmdb_head(&qmdb_config, 1, hash_b).await?;

    shutdown_engine(&node).await?;

    let state = QmdbState::open(qmdb_config)?;
    let head = state.head()?.expect("QMDB head should exist");
    let header = node
        .inner
        .provider
        .header_by_number(1)?
        .expect("canonical header should exist");

    assert_eq!(head.number, 1);
    assert_eq!(head.hash, hash_b);
    assert_eq!(head.root, header.state_root());

    Ok(())
}
