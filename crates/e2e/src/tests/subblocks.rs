use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy_network::{TxSignerSync, eip2718::Encodable2718};
use alloy_primitives::{Address, TxHash, U256};
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::{StreamExt, future::join_all};
use reth_ethereum::{
    chainspec::{ChainSpecProvider, EthChainSpec},
    primitives::AlloyBlockHeader,
    provider::{CanonStateNotification, CanonStateSubscriptions},
    rpc::eth::EthApiServer,
};
use reth_node_core::primitives::transaction::TxHashRef;
use tempo_node::primitives::{
    TempoTxEnvelope, TxAA, subblock::TEMPO_SUBBLOCK_NONCE_KEY_PREFIX, transaction::Call,
};

use crate::{ExecutionRuntime, RunningNode, Setup, link_validators, setup_validators};

#[test_traced]
fn subblocks_are_included() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        let how_many_signers = 5;

        let linkage = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        let setup = Setup {
            how_many_signers,
            seed: 0,
            linkage: linkage.clone(),
            epoch_length: 10,
            connect_execution_layer_nodes: false,
        };

        // Setup and start all nodes.
        let execution_runtime = ExecutionRuntime::new();
        let (nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;

        let running = join_all(
            nodes
                .into_iter()
                .map(|mut node| {
                    node.consensus_config.new_payload_wait_time = Duration::from_millis(500);
                    node.start()
                })
                .collect::<Vec<_>>(),
        )
        .await;

        link_validators(&mut oracle, &running, linkage.clone(), None).await;

        let mut stream = running[0]
            .execution_node
            .node
            .provider
            .canonical_state_stream();

        let mut expected_transactions: Vec<TxHash> = Vec::new();
        while let Some(update) = stream.next().await {
            let CanonStateNotification::Commit { new } = update else {
                unreachable!("unexpected reorg");
            };

            // Assert that all expected transactions are included in the block.
            for tx in expected_transactions.drain(..) {
                if !new.blocks().iter().any(|(_, block)| {
                    block
                        .sealed_block()
                        .body()
                        .transactions
                        .iter()
                        .any(|t| *t.tx_hash() == *tx)
                }) {
                    panic!("transaction {tx} was not included");
                }
            }

            // Exit once we reach height 20.
            if new.tip().number() == 20 {
                break;
            }

            // Send subblock transactions to all nodes.
            for node in running.iter() {
                for _ in 0..5 {
                    expected_transactions.push(submit_subblock_tx(node).await);
                }
            }
        }
    });
}

async fn submit_subblock_tx(node: &RunningNode) -> TxHash {
    let wallet = PrivateKeySigner::random();

    let mut nonce_bytes = [0; 32];
    nonce_bytes[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;
    nonce_bytes[1..16].copy_from_slice(&node.public_key.as_ref()[..15]);

    let mut tx = TxAA {
        chain_id: node.execution_node.node.provider.chain_spec().chain_id(),
        calls: vec![Call {
            to: Address::ZERO.into(),
            input: Default::default(),
            value: Default::default(),
        }],
        gas_limit: 100000,
        nonce_key: U256::from_be_bytes(nonce_bytes),
        ..Default::default()
    };
    assert!(tx.subblock_proposer().unwrap().matches(&node.public_key));
    let signature = wallet.sign_transaction_sync(&mut tx).unwrap();

    let tx = TempoTxEnvelope::AA(tx.into_signed(signature.into()));
    let tx_hash = *tx.tx_hash();
    node.execution_node
        .node
        .eth_api()
        .send_raw_transaction(tx.encoded_2718().into())
        .await
        .unwrap();

    tx_hash
}
