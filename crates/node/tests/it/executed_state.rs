use crate::utils::with_t1_fees;
use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::TransactionRequest;
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::{chainspec::EthChainSpec as _, tasks::Runtime};
use reth_node_api::BuiltPayload;
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_storage_api::{AccountReader as _, StateProviderFactory as _};
use tempo_node::node::TempoNode;

/// One node builds two blocks. A second node only executes them with
/// `newPayload` and never receives a forkchoice update, so its head stays at
/// genesis. The first block becomes the engine's pending block. The second
/// block is neither canonical nor pending, so the provider has no state for
/// it, but [`tempo_node::ExecutedState`] reads it from the engine.
#[tokio::test(flavor = "multi_thread")]
async fn executed_state_reads_blocks_that_are_not_canonical() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut producer = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?
        .node;
    let chain_spec = producer.inner.chain_spec();
    let chain_id = chain_spec.chain().id();

    let mut account = Wallet::default().with_chain_id(chain_id).account(0);
    let sender = account.address();
    let tx = TransactionRequest::default()
        .to(Address::ZERO)
        .gas_limit(300_000);
    let (_, first) = producer
        .inject_and_advance(account.sign_tx_bytes(with_t1_fees(tx)).await)
        .await?;
    let second = producer.advance_block().await?;
    let second_hash = second.block().hash();

    let expected = producer
        .inner
        .provider
        .state_by_block_hash(second_hash)?
        .basic_account(&sender)?;
    assert_eq!(
        expected.map(|account| account.nonce),
        Some(1),
        "the transfer must be part of the first block",
    );

    let tempo_node = TempoNode::default();
    let executed_state = tempo_node.executed_state();
    let runtime = Runtime::test();
    let mut config = NodeConfig::new(chain_spec).with_unused_ports();
    config.network.discovery.disable_discovery = true;
    let observer_handle = NodeBuilder::new(config)
        .testing_node(runtime.clone())
        .node(tempo_node)
        .launch()
        .await?;
    let observer = &observer_handle.node;

    for payload in [first, second] {
        let status = observer
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(payload.into())
            .await?;
        assert!(status.is_valid(), "unexpected payload status: {status:?}");
    }

    assert!(
        observer.provider.state_by_block_hash(second_hash).is_err(),
        "the provider must not serve state for a block that is neither canonical nor pending",
    );
    let state = executed_state.state_by_block_hash(observer.provider.clone(), second_hash)?;
    assert_eq!(state.basic_account(&sender)?, expected);

    assert!(
        executed_state
            .state_by_block_hash(observer.provider.clone(), B256::repeat_byte(0xab))
            .is_err(),
        "a block that the engine has not executed must not resolve",
    );

    Ok(())
}
