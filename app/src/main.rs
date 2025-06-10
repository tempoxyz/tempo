use std::sync::Arc;

use reth_chainspec::ChainSpec;
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{DevArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_node_ethereum::EthereumNode;
use reth_node_ethereum::node::EthereumAddOns;
use reth_tasks::TaskManager;

use library::consensus::MalachiteConsensusBuilder;

use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let task_manager = TaskManager::current();

    let node_config = NodeConfig::test()
        .dev()
        .with_dev(DevArgs {
            dev: true,
            block_max_transactions: None,
            block_time: Some(std::time::Duration::from_secs(1)),
        })
        .with_rpc(RpcServerArgs::default().with_http())
        .with_chain(custom_chain());

    let NodeHandle {
        node: _,
        node_exit_future: _,
    } = NodeBuilder::new(node_config)
        .testing_node(task_manager.executor())
        .with_types::<EthereumNode>()
        .with_components(EthereumNode::components().consensus(MalachiteConsensusBuilder::new()))
        .with_add_ons(EthereumAddOns::default())
        .launch()
        .await?;

    Ok(())
}

fn custom_chain() -> Arc<ChainSpec> {
    todo!();

    let custom_genesis = r#"
{
    "nonce": "0x42",
    "timestamp": "0x0",
    "extraData": "0x5343",
    "gasLimit": "0xa388",
    "difficulty": "0x400000000",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
        "0x6Be02d1d3665660d22FF9624b7BE0551ee1Ac91b": {
            "balance": "0x4a47e3c12448f4ad000000"
        }
    },
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "config": {
        "ethash": {},
        "chainId": 2600,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": true,
        "shanghaiTime": 0
    }
}
"#;
    // let genesis: Genesis = serde_json::from_str(custom_genesis).unwrap();
    // Arc::new(genesis.into())
}
