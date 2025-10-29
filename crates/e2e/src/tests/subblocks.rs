use std::time::Duration;

use alloy_network::TxSignerSync;
use alloy_primitives::{Address, B256, b256};
use alloy_signer_local::PrivateKeySigner;
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;
use reth_ethereum::{
    chainspec::{ChainSpecProvider, EthChainSpec},
    provider::{StateProviderFactory, TransactionsProvider},
};
use reth_node_core::primitives::transaction::TxHashRef;
use tempo_node::primitives::{TempoTxEnvelope, TxAA, transaction::Call};

use crate::{ExecutionRuntime, Setup, ValidatorNode, setup_validators};

#[test_traced]
fn subblocks_are_included() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        let num_nodes = 5;

        let setup = Setup {
            how_many: num_nodes,
            seed: 0,
            linkage: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            epoch_length: 100,
        };

        // Setup and start all nodes.
        let execution_runtime = ExecutionRuntime::new();
        let (mut nodes, _network_handle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start())).await;

        let tx = build_subblock_transaction(&nodes[0]);
        nodes[0].subblocks.add_transaction(tx.clone());

        context.sleep(Duration::from_secs(2)).await;

        let tx = nodes[0]
            .node
            .node
            .provider
            .transaction_by_hash(*tx.tx_hash())
            .unwrap()
            .unwrap();
    });
}

fn build_subblock_transaction(node: &ValidatorNode) -> TempoTxEnvelope {
    let wallet = PrivateKeySigner::from_bytes(&b256!(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ))
    .unwrap();

    let nonce = node
        .node
        .node
        .provider
        .latest()
        .unwrap()
        .account_nonce(&wallet.address())
        .unwrap()
        .unwrap_or_default();

    let mut tx = TxAA {
        chain_id: node.node.node.provider.chain_spec().chain_id(),
        proposer: Some(B256::from_slice(node.public_key.as_ref())),
        calls: vec![Call {
            to: Address::ZERO.into(),
            input: Default::default(),
            value: Default::default(),
        }],
        nonce,
        gas_limit: 100000,
        ..Default::default()
    };
    let signature = wallet.sign_transaction_sync(&mut tx).unwrap();

    TempoTxEnvelope::AA(tx.into_signed(signature.into()))
}
