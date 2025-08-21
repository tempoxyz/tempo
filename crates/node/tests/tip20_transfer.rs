use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::{
        local::{MnemonicBuilder, coins_bip39::English},
        utils::secret_key_to_address,
    },
    sol_types::{SolCall, SolType},
};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use reth_chainspec::ChainSpec;
use reth_ethereum::{provider::db, tasks::TaskManager};
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::{DevArgs, RpcServerArgs};
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, TipFeeManager},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();

    let chain_spec = ChainSpec::from_genesis(serde_json::from_str(include_str!(
        "./assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::test()
        .with_chain(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch()
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
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider);
    let user_fee_token = fee_manager.userTokens(caller).call().await?;
    dbg!(user_fee_token);

    // TODO: get balance of fee token before

    let tx = TransactionRequest::default().from(caller).to(caller);
    let tx_hash = fee_manager.provider().send_transaction(tx).await?;

    dbg!(tx_hash);
    // TODO: assert state changes, gas spent in fee token

    Ok(())
}
