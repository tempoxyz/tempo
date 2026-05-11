//! Example: Running a Tempo dev node with a custom state root strategy.
//!
//! This demonstrates how to use the [`CustomStateRoot`] hook added in
//! [paradigmxyz/reth#24130](https://github.com/paradigmxyz/reth/pull/24130)
//! to override state root computation. The example sets the state root to
//! `B256::ZERO` for every block.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example custom_state_root
//! ```

use std::sync::Arc;

use alloy_primitives::B256;
use reth_ethereum::tasks::Runtime;
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_trie::updates::TrieUpdates;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::{CustomStateRoot, TempoNodeArgs, node::TempoNode, primitives::TempoPrimitives};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // A custom state root handler that always returns B256::ZERO.
    let zero_state_root: CustomStateRoot<TempoPrimitives> =
        Arc::new(|_input| Ok((B256::ZERO, TrieUpdates::default())));

    let node = TempoNode::new(&TempoNodeArgs::default(), None)
        .with_custom_state_root(zero_state_root);

    // Build a minimal Tempo chain spec for dev mode.
    let genesis: alloy_genesis::Genesis = serde_json::from_value(serde_json::json!({
        "config": {
            "chainId": 1,
            "homesteadBlock": 0,
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
            "shanghaiTime": 0,
            "cancunTime": 0,
            "pragueTime": 0
        },
        "nonce": "0x0",
        "timestamp": "0x0",
        "gasLimit": "0x1c9c380",
        "difficulty": "0x0",
        "alloc": {
            "0x6Be02d1d3665660d22FF9624b7BE0551ee1Ac91b": {
                "balance": "0x4a47e3c12448f4ad000000"
            }
        }
    }))?;
    let chain_spec: TempoChainSpec = reth_chainspec::ChainSpec::from(genesis).into();

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_http());

    let runtime = Runtime::test();

    let NodeHandle {
        node: _node,
        node_exit_future,
    } = NodeBuilder::new(node_config)
        .testing_node(runtime)
        .node(node)
        .launch_with_debug_capabilities()
        .await?;

    println!("Tempo node running with custom zero state root — press Ctrl+C to exit");

    node_exit_future.await
}
