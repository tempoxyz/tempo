use crate::utils::{t1_account, tempo_test_setup};
use alloy_primitives::{Address, B256};
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_node_api::BuiltPayload;
use reth_storage_api::{AccountReader as _, StateProviderFactory as _};
use tempo_node::node::TempoNode;

/// One node builds two blocks. A second node only executes them with
/// `newPayload` and receives no forkchoice update for them, so its head stays
/// at genesis. The first block becomes the engine's pending block. The second
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
    let chain_id = chain_spec.chain_id();

    let mut account = t1_account(&Wallet::default().with_chain_id(chain_id), 0);
    let sender = account.address();
    let tx = account.tx().to(Address::ZERO).gas_limit(300_000).await;
    let (_, first) = producer.inject_and_advance(tx).await?;
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
    let (observer, _) = tempo_test_setup(1, chain_spec)
        .with_node(move |_| tempo_node.clone())
        .build_single()
        .await?;
    let provider = &observer.inner.provider;

    for payload in [first, second] {
        let status = observer.submit_payload_with_status(payload).await?;
        assert!(status.is_valid(), "unexpected payload status: {status:?}");
    }

    assert!(
        provider.state_by_block_hash(second_hash).is_err(),
        "the provider must not serve state for a block that is neither canonical nor pending",
    );
    let state = executed_state.state_by_block_hash(provider.clone(), second_hash)?;
    assert_eq!(state.basic_account(&sender)?, expected);

    assert!(
        executed_state
            .state_by_block_hash(provider.clone(), B256::repeat_byte(0xab))
            .is_err(),
        "a block that the engine has not executed must not resolve",
    );

    Ok(())
}
