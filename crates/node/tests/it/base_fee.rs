use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use alloy_eips::BlockNumberOrTag;
use futures::{StreamExt, future::join_all, stream};
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::{TEMPO_BASE_FEE, TempoNode};

use crate::utils::setup_test_token;

#[tokio::test(flavor = "multi_thread")]
async fn test_base_fee() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();

    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/base-fee-test.json"
    ))?);
    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Get initial block to check base fee
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    let base_fee = block
        .header
        .base_fee_per_gas
        .expect("Could not get basefee");
    assert_eq!(base_fee, 0);

    // Deploy test token and mint initial supply
    let token = setup_test_token(provider.clone(), caller).await?;
    token
        .mint(caller, U256::from(u64::MAX))
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Gas limit is set to 200k in test-genesis.json, send 500 txs to exceed limit over multiple
    // blocks
    let mut pending_txs = vec![];
    for _ in 0..500 {
        let pending_tx = token
            .transfer(Address::random(), U256::ONE)
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await?;
        pending_txs.push(pending_tx);
    }

    // Wait for all receipts, get block number of last receipt
    let receipts = join_all(pending_txs.into_iter().map(|tx| tx.get_receipt()))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let final_block = receipts
        .iter()
        .filter_map(|r| r.block_number)
        .max()
        .unwrap();

    // Assert that all blocks have base_fee = 0
    stream::iter(0..=final_block)
        .for_each(|block_num| {
            let provider = provider.clone();
            async move {
                let block = provider
                    .get_block_by_number(BlockNumberOrTag::Number(block_num))
                    .await
                    .unwrap()
                    .expect("Could not get block");

                // Assert that base fee is 0
                let base_fee = block
                    .header
                    .base_fee_per_gas
                    .expect("Could not get basefee");
                assert_eq!(base_fee, 0, "Base fee should be 0");
            }
        })
        .await;

    // Check fee history and ensure fee stays at 0
    let fee_history = provider
        .get_fee_history(final_block, BlockNumberOrTag::Number(final_block), &[])
        .await?;

    for (base_fee, gas_used_ratio) in fee_history
        .base_fee_per_gas
        .iter()
        .zip(fee_history.gas_used_ratio)
    {
        assert_eq!(*base_fee, 0, "Base fee should remain 0");
        println!("Gas used ratio: {gas_used_ratio}");
    }

    Ok(())
}
