//! Real Tempo block production and a same-machine backend comparison.

use std::{sync::Arc, time::Instant};

use alloy_primitives::Address;
use alloy_rpc_types_eth::TransactionRequest;
use reth_e2e_test_utils::wallet::Wallet;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_node_api::BuiltPayload;
use reth_storage_api::{AccountReader as _, StateProviderFactory as _};
use tempo_chainspec::TempoChainSpec;
use tempo_node::{TempoNode, node::TempoNodeArgs, qmdb::StateRootBackend};

use crate::utils::with_t1_fees;

async fn node(backend: StateRootBackend) -> eyre::Result<crate::utils::LocalTestNode> {
    let genesis = serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    let chain = Arc::new(TempoChainSpec::from_genesis(genesis));
    let (node, _) = TempoNode::test_setup(1, chain)
        .with_dev_mode(true)
        .with_node(move |_| {
            TempoNode::new(
                &TempoNodeArgs {
                    state_root_backend: backend,
                    ..Default::default()
                },
                None,
            )
        })
        .with_tree_config_modifier(|config| {
            config
                .with_persistence_threshold(0)
                .with_memory_block_buffer_target(0)
                .with_share_sparse_trie_with_payload_builder(true)
        })
        .with_restartable_nodes()
        .build_single()
        .await?;
    Ok(node)
}

#[tokio::test(flavor = "multi_thread")]
async fn qmdb_builds_validates_persists_and_restarts() -> eyre::Result<()> {
    let mut node = node(StateRootBackend::Qmdb).await?;
    let chain_id = node.inner.chain_spec().chain_id();
    let mut sender = Wallet::default().with_chain_id(chain_id).account(0);
    let address = sender.address();
    for nonce in 0..3 {
        let transaction = with_t1_fees(
            TransactionRequest::default()
                .to(Address::ZERO)
                .gas_limit(300_000),
        );
        let (_, payload) = node
            .inject_and_advance(sender.sign_tx_bytes(transaction).await)
            .await?;
        assert_eq!(payload.block().body().transactions.len(), 1);
        assert_eq!(
            node.inner
                .provider
                .latest()?
                .basic_account(&address)?
                .unwrap()
                .nonce,
            nonce + 1
        );
    }
    node.wait_for_persisted_block(3).await?;
    let mut node = node.restart().await?;
    assert_eq!(
        node.inner
            .provider
            .latest()?
            .basic_account(&address)?
            .unwrap()
            .nonce,
        3
    );
    node.advance_block().await?;
    node.wait_for_persisted_block(4).await?;
    Ok(())
}

/// Includes transaction submission, payload construction, execution validation, and durable save.
/// This deliberately is not a production TPS or root-only microbenchmark.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "same-machine full-node backend benchmark; run with --ignored --nocapture"]
async fn bench_mpt_vs_qmdb() -> eyre::Result<()> {
    let blocks = std::env::var("QMDB_BENCH_BLOCKS")
        .unwrap_or_else(|_| "100".into())
        .parse::<u64>()?;
    for backend in [StateRootBackend::Mpt, StateRootBackend::Qmdb] {
        let mut node = node(backend).await?;
        let chain_id = node.inner.chain_spec().chain_id();
        let mut sender = Wallet::default().with_chain_id(chain_id).account(0);
        let mut samples = Vec::new();
        for index in 0..blocks + 10 {
            let transaction = with_t1_fees(
                TransactionRequest::default()
                    .to(Address::ZERO)
                    .gas_limit(300_000),
            );
            let signed = sender.sign_tx_bytes(transaction).await;
            let start = Instant::now();
            let (_, payload) = node.inject_and_advance(signed).await?;
            assert_eq!(payload.block().body().transactions.len(), 1);
            node.wait_for_persisted_block(index + 1).await?;
            if index >= 10 {
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        let total = samples.iter().sum::<f64>();
        samples.sort_by(f64::total_cmp);
        println!(
            "QMDB_BENCH {}",
            serde_json::json!({
                "backend": format!("{backend:?}"), "blocks": blocks, "transactions_per_block": 1,
                "warmup_blocks": 10, "mean_ms": total / blocks as f64,
                "p50_ms": samples[samples.len() / 2],
                "p95_ms": samples[(samples.len() * 95 / 100).min(samples.len() - 1)],
                "transactions_per_second": blocks as f64 * 1000.0 / total,
            })
        );
        node.stop().await?;
    }
    Ok(())
}
