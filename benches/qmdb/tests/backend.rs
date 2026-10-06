//! Real Tempo block production and a same-machine backend comparison.

use std::{sync::Arc, time::Instant};

use alloy::{
    consensus::{Transaction as _, TxReceipt as _},
    providers::Provider as _,
    sol_types::SolCall as _,
};
use alloy_primitives::{Address, U256, address};
use alloy_rpc_types_eth::TransactionRequest;
use reth_e2e_test_utils::{E2ETestSetupExt, wallet::Wallet};
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_node_api::BuiltPayload;
use reth_storage_api::{AccountReader as _, ReceiptProvider as _, StateProviderFactory as _};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::ITIP20;
use tempo_node::{TempoNode, node::TempoNodeArgs, qmdb::StateRootBackend};
use tempo_precompiles::PATH_USD_ADDRESS;

// AlphaUSD is funded for the development wallets in test-genesis.json.
const BENCHMARK_TOKEN: Address = address!("0x20c0000000000000000000000000000000000001");

fn with_t1_fees(tx: TransactionRequest) -> TransactionRequest {
    let fee = u128::from(tempo_chainspec::spec::TEMPO_T1_BASE_FEE);
    tx.max_fee_per_gas(fee).max_priority_fee_per_gas(fee)
}

async fn node(
    backend: StateRootBackend,
) -> eyre::Result<reth_e2e_test_utils::NodeHelperType<TempoNode>> {
    let genesis = serde_json::from_str(include_str!(
        "../../../crates/node/tests/assets/test-genesis.json"
    ))?;
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
    let observer = self::node(StateRootBackend::Qmdb).await?;
    let proof_error = node
        .rpc_provider()
        .get_proof(Address::ZERO, vec![])
        .await
        .unwrap_err();
    assert_eq!(proof_error.as_error_resp().unwrap().code, -32601);
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
        // This node has no producer execution cache and independently validates each root.
        observer.submit_payload(payload.clone()).await?;
        assert_eq!(
            payload
                .block()
                .body()
                .transactions
                .iter()
                .filter(|&tx| tx.gas_limit() > 0)
                .count(),
            1
        );
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
    assert_eq!(
        observer
            .inner
            .provider
            .latest()?
            .basic_account(&address)?
            .map_or(0, |account| account.nonce),
        0
    );
    observer.stop().await?;
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
    let transactions = std::env::var("QMDB_BENCH_TXS")
        .unwrap_or_else(|_| "16".into())
        .parse::<u64>()?;
    eyre::ensure!(blocks > 0 && (1..=16).contains(&transactions));
    let rounds = std::env::var("QMDB_BENCH_ROUNDS")
        .unwrap_or_else(|_| "3".into())
        .parse::<u64>()?;
    eyre::ensure!(rounds > 0);
    for round in 0..rounds {
        let backends = if round % 2 == 0 {
            [StateRootBackend::Mpt, StateRootBackend::Qmdb]
        } else {
            [StateRootBackend::Qmdb, StateRootBackend::Mpt]
        };
        for backend in backends {
            let mut node = node(backend).await?;
            let chain_id = node.inner.chain_spec().chain_id();
            let mut sender = Wallet::default().with_chain_id(chain_id).account(0);
            for token in [PATH_USD_ADDRESS, BENCHMARK_TOKEN] {
                let data = ITIP20::balanceOfCall {
                    account: sender.address(),
                }
                .abi_encode();
                let balance = node
                    .rpc_provider()
                    .call(TransactionRequest::default().to(token).input(data.into()))
                    .await?;
                println!(
                    "QMDB_BENCH_BALANCE {}",
                    serde_json::json!({
                        "backend": format!("{backend:?}"), "token": format!("{token}"),
                        "balance": U256::from_be_slice(&balance).to_string(),
                    })
                );
                if token == BENCHMARK_TOKEN {
                    eyre::ensure!(
                        U256::from_be_slice(&balance) > U256::from((blocks + 10) * transactions),
                        "benchmark sender must have funded transfer tokens"
                    );
                }
            }
            let probe = ITIP20::transferCall {
                to: Address::from_word(U256::from(10_000).into()),
                amount: U256::from(1),
            }
            .abi_encode();
            for gas in [300_000, 1_000_000, 5_000_000] {
                let request = with_t1_fees(
                    TransactionRequest::default()
                        .from(sender.address())
                        .to(BENCHMARK_TOKEN)
                        .input(probe.clone().into())
                        .gas_limit(gas),
                );
                println!(
                    "QMDB_BENCH_TRANSFER_PROBE gas={gas} result={:?}",
                    node.rpc_provider().call(request).await
                );
            }
            let mut samples = Vec::new();
            let mut processing_samples = Vec::new();
            for index in 0..blocks + 10 {
                let mut signed = Vec::new();
                for transaction_index in 0..transactions {
                    let recipient = Address::from_word(
                        U256::from(10_000 + index * transactions + transaction_index).into(),
                    );
                    let data = ITIP20::transferCall {
                        to: recipient,
                        amount: U256::from(1),
                    }
                    .abi_encode();
                    let transaction = with_t1_fees(
                        TransactionRequest::default()
                            .to(BENCHMARK_TOKEN)
                            .input(data.into())
                            .gas_limit(5_000_000),
                    );
                    signed.push(sender.sign_tx_bytes(transaction).await);
                }
                let start = Instant::now();
                let mut hashes = Vec::new();
                for transaction in signed {
                    hashes.push(node.rpc.inject_tx(transaction).await?);
                }
                node.wait_for_pooled(hashes).await?;
                let payload = node.advance_block().await?;
                let processing_ms = start.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(
                    payload
                        .block()
                        .body()
                        .transactions
                        .iter()
                        .filter(|&tx| tx.gas_limit() > 0)
                        .count(),
                    transactions as usize
                );
                node.wait_for_persisted_block(index + 1).await?;
                if index >= 10 {
                    samples.push(start.elapsed().as_secs_f64() * 1000.0);
                    processing_samples.push(processing_ms);
                }
                let receipts = node
                    .inner
                    .provider
                    .receipts_by_block(payload.block().hash().into())?
                    .expect("persisted block receipts");
                assert!(
                    receipts.iter().all(|receipt| receipt.status()),
                    "all transfers must succeed; receipts: {receipts:?}"
                );
                node.wait_for_pool_head(payload.block().hash()).await?;
            }
            let total = samples.iter().sum::<f64>();
            samples.sort_by(f64::total_cmp);
            let processing_total = processing_samples.iter().sum::<f64>();
            processing_samples.sort_by(f64::total_cmp);
            println!(
                "QMDB_BENCH {}",
                serde_json::json!({
                    "backend": format!("{backend:?}"), "blocks": blocks, "transactions_per_block": transactions,
                    "round": round + 1, "debug_assertions": cfg!(debug_assertions),
                    "workload": "TIP20 transfers to fresh recipients", "token": format!("{BENCHMARK_TOKEN}"),
                    "warmup_blocks": 10, "mean_ms": total / blocks as f64,
                    "p50_ms": samples[samples.len() / 2],
                    "p95_ms": samples[(samples.len() * 95 / 100).min(samples.len() - 1)],
                    "transactions_per_second": (blocks * transactions) as f64 * 1000.0 / total,
                    "processing_mean_ms": processing_total / blocks as f64,
                    "processing_p50_ms": processing_samples[processing_samples.len() / 2],
                    "processing_p95_ms": processing_samples[(processing_samples.len() * 95 / 100).min(processing_samples.len() - 1)],
                    "processing_transactions_per_second": (blocks * transactions) as f64 * 1000.0 / processing_total,
                })
            );
            node.stop().await?;
        }
    }
    Ok(())
}
