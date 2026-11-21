//! Tests of how the engine validates the blocks it receives.

use crate::utils::{TestNodeBuilder, t1_account};
use alloy::{primitives::Address, providers::Provider};
use alloy_rpc_types_engine::PayloadStatusEnum;
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_api::BuiltPayload;
use reth_node_metrics::recorder::{PrometheusRecorder, install_prometheus_recorder};
use reth_primitives_traits::SealedBlock;
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::TempoHeader;
use test_case::test_case;

/// The engine reports a block whose header is invalid as `INVALID` without executing it.
///
/// Each case takes a valid block with one transaction and makes one field of its header invalid.
///
/// One node builds the blocks and another node receives them, because an engine does not execute
/// the blocks that its own payload builder executed.
#[test_case(
    |header, _| header.general_gas_limit += 1,
    "general gas limit 30000001 does not match expected 30000000" ;
    "general gas limit"
)]
#[test_case(
    |header, _| header.shared_gas_limit += 1,
    "shared gas limit 1 does not match expected 0" ;
    "shared gas limit"
)]
#[test_case(
    |header, parent| header.inner.timestamp = parent.inner.timestamp - 1,
    "block timestamp 1710338135000 is in the past compared to the parent timestamp 1710338136000" ;
    "timestamp before the parent"
)]
#[tokio::test(flavor = "multi_thread")]
async fn rejects_invalid_header_without_execution(
    invalidate: fn(&mut TempoHeader, &TempoHeader),
    validation_error: &str,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_node_count(2)
        .build_multi_node()
        .await?;
    let metrics = install_prometheus_recorder();
    let mut builder = setup.nodes.remove(0);
    let receiver = setup.nodes.remove(0);
    let engine = receiver.inner.add_ons_handle.beacon_engine_handle.clone();

    // The parent is not the genesis block, so its timestamp is above zero.
    let parent = builder.advance_block().await?.block().clone();
    let status = engine
        .new_payload(TempoExecutionData {
            block: parent.clone().into(),
        })
        .await?;
    assert_eq!(status.status, PayloadStatusEnum::Valid);

    let chain_id = builder.rpc_provider().get_chain_id().await?;
    let raw_tx = t1_account(&Wallet::default().with_chain_id(chain_id), 0)
        .tx()
        .to(Address::ZERO)
        .await;
    builder.inject_tx(raw_tx).await?;
    let valid = builder.new_payload().await?.block().clone();
    assert_eq!(valid.body().transactions.len(), 1);

    let mut invalid = valid.clone_block();
    invalidate(&mut invalid.header, parent.header());
    let invalid = SealedBlock::seal_slow(invalid);

    let executed_before = executed_gas(metrics);
    let status = engine
        .new_payload(TempoExecutionData {
            block: invalid.into(),
        })
        .await?;
    assert_eq!(
        status.status,
        PayloadStatusEnum::Invalid {
            validation_error: validation_error.to_string()
        }
    );
    assert_eq!(executed_gas(metrics), executed_before);

    // The engine executes the block that the invalid block was made from.
    let status = engine
        .new_payload(TempoExecutionData {
            block: valid.into(),
        })
        .await?;
    assert_eq!(status.status, PayloadStatusEnum::Valid);
    assert!(executed_gas(metrics) > executed_before);

    Ok(())
}

/// Returns the gas of the blocks that the engines of this process have executed.
fn executed_gas(recorder: &PrometheusRecorder) -> u64 {
    recorder
        .handle()
        .render()
        .lines()
        .find(|line| line.starts_with("reth_sync_execution_gas_processed_total"))
        .and_then(|line| line.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0)
}
