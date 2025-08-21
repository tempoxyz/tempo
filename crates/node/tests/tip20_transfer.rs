use std::sync::Arc;

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::{
        local::{MnemonicBuilder, coins_bip39::English},
        utils::secret_key_to_address,
    },
    sol_types::{SolCall, SolType},
};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use reth_chainspec::ChainSpec;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
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

    let wallet = MnemonicBuilder::<English>::default().build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider);

    // dbg!(user_token);
    // // TODO: craft tip20 tx
    // let tx = TransactionRequest::default();

    // provider.send_transaction(tx);
    //
    //     // <cast send 0x20c0000000000000000000000000000000000000 'transfer(address,uint256)' 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC 100000000 --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d --gas-limit 2000000 --gas-price 4000000000>
    //     let raw = hex!(
    //         "0x02f8ae820539800184ee6b2800831e84809420c000000000000000000000000000000000000080b844a9059cbb0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000000000000000000000000000000000000005f5e100c001a07c453d4ffe1b391089656e70658aa839435e18a5edab6113076166035c7d7afca06f454ef1b016bbf55cc147f4b20cda2719c5be22169b9c5c31366bde0c546d67"
    //     );
    //
    //     let tx = TransactionSigned::decode_2718_exact(&raw[..])?.try_into_recovered()?;
    //     let signer = tx.signer();
    //     let slot = slots::mapping_slot(signer, tip_fee_manager::slots::USER_TOKENS);
    //     println!("Submitting tx from {signer} with fee manager token slot 0x{slot:x}");
    //
    //     let res = node
    //         .pool
    //         .add_consensus_transaction(tx, TransactionOrigin::Local)
    //         .await
    //         .unwrap();
    //     assert!(matches!(res.state, AddedTransactionState::Pending));
    //     let pooled_tx = node.pool.get_transactions_by_sender(signer);
    //     assert_eq!(pooled_tx.len(), 1);
    //
    //     let best = node.pool.best_transactions().next().unwrap();
    //     assert_eq!(res.hash, *best.hash());
    //
    //
    //
    // TODO: assert state changes
    Ok(())
}
