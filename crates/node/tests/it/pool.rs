use alloy_eips::Decodable2718;
use reth_ethereum::{
    evm::revm::primitives::hex,
    node::builder::{NodeBuilder, NodeHandle},
    pool::TransactionPool,
    primitives::SignerRecoverable,
    tasks::TaskManager,
};
use reth_ethereum_primitives::TransactionSigned;
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_transaction_pool::{TransactionOrigin, pool::AddedTransactionState};
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::{args::TempoArgs, node::TempoNode};
use tempo_precompiles::contracts::{storage::slots, tip_fee_manager};

#[tokio::test(flavor = "multi_thread")]
async fn submit_pending_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
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
        .node(TempoNode::new(TempoArgs::default()))
        .launch()
        .await?;

    // <cast send 0x20c0000000000000000000000000000000000000 'transfer(address,uint256)' 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC 100000000 --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d --gas-limit 2000000 --gas-price 4000000000>
    let raw = hex!(
        "0x02f8ae820539800184ee6b2800831e84809420c000000000000000000000000000000000000080b844a9059cbb0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000000000000000000000000000000000000005f5e100c001a07c453d4ffe1b391089656e70658aa839435e18a5edab6113076166035c7d7afca06f454ef1b016bbf55cc147f4b20cda2719c5be22169b9c5c31366bde0c546d67"
    );

    let tx = TransactionSigned::decode_2718_exact(&raw[..])?.try_into_recovered()?;
    let signer = tx.signer();
    let slot = slots::mapping_slot(signer, tip_fee_manager::slots::USER_TOKENS);
    println!("Submitting tx from {signer} with fee manager token slot 0x{slot:x}");

    let res = node
        .pool
        .add_consensus_transaction(tx, TransactionOrigin::Local)
        .await
        .unwrap();
    assert!(matches!(res.state, AddedTransactionState::Pending));
    let pooled_tx = node.pool.get_transactions_by_sender(signer);
    assert_eq!(pooled_tx.len(), 1);

    let best = node.pool.best_transactions().next().unwrap();
    assert_eq!(res.hash, *best.hash());

    Ok(())
}
