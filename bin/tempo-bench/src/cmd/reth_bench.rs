//! Reth-compatible benchmarking mode using standard Ethereum network.
//!
//! This module provides a separate code path for benchmarking vanilla Ethereum nodes
//! like Reth, which don't have Tempo-specific RPC extensions.

use alloy::{
    consensus::TxEnvelope,
    eips::Encodable2718,
    network::{Ethereum, EthereumWallet, TxSignerSync},
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, Secp256k1Signer},
    sol,
    transports::http::reqwest::Url,
};
use eyre::Context;
use futures::{StreamExt, stream};
use governor::{Quota, RateLimiter, state::StreamRateLimitExt};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressIterator};
use rand::seq::IndexedRandom;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reth_tracing::tracing::info;
use serde::Serialize;
use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

sol! {
    #[sol(rpc)]
    #[allow(clippy::too_many_arguments)]
    MockERC20,
    "artifacts/MockERC20.json"
}

/// Run the benchmark in Reth-compatible mode
pub async fn run_reth_benchmark(
    target_urls: Vec<Url>,
    tps: u64,
    duration: u64,
    accounts: u64,
    mnemonic: String,
    from_mnemonic_index: u32,
    max_concurrent_requests: usize,
) -> eyre::Result<RethBenchmarkReport> {
    info!("Running Reth-compatible benchmark");

    // Create signers
    info!(accounts, "Creating signers");
    let signers: Vec<Secp256k1Signer> = (from_mnemonic_index..)
        .take(accounts as usize)
        .progress_count(accounts)
        .map(|i| MnemonicBuilder::from_phrase_nth(&mnemonic, i).into_secp256k1())
        .collect();

    // Create base provider with explicit Ethereum network
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .connect_http(target_urls[0].clone());

    // Get start block and chain info
    let start_block = provider.get_block_number().await?;
    let chain_id = provider.get_chain_id().await?;

    // Get gas price for transactions
    let gas_price = provider.get_gas_price().await?;
    info!(chain_id, gas_price, "Connected to chain");

    // Deploy ERC-20 token using first signer
    info!("Deploying ERC-20 token");
    let deployer_provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(EthereumWallet::from(signers[0].clone()))
        .connect_http(target_urls[0].clone());

    let token = MockERC20::deploy(
        &deployer_provider,
        "BenchToken".to_string(),
        "BENCH".to_string(),
        18,
    )
    .await
    .context("Failed to deploy ERC-20 token")?;
    let token_address = *token.address();
    info!(%token_address, "ERC-20 token deployed");

    // Mint tokens to all signers
    let mint_amount = U256::MAX / U256::from(signers.len());
    info!(%mint_amount, "Minting ERC-20 tokens to all accounts");

    for signer in signers.iter().progress() {
        let to = signer.address();
        token
            .mint(to, mint_amount)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Get initial nonces for all signers
    info!("Fetching initial nonces");
    let mut nonces: std::collections::HashMap<Address, u64> = std::collections::HashMap::new();
    for signer in &signers {
        let nonce = provider.get_transaction_count(signer.address()).await?;
        nonces.insert(signer.address(), nonce);
    }

    // Generate transaction data
    let total_txs = tps * duration;
    info!(total_txs, "Generating transaction data");

    let progress = ProgressBar::new(total_txs);
    let mut tx_data: Vec<(Secp256k1Signer, u64, Vec<u8>)> = Vec::with_capacity(total_txs as usize);

    for _ in (0..total_txs).progress_with(progress) {
        let signer = signers.choose(&mut rand::rng()).unwrap().clone();
        let from = signer.address();

        // Get and increment nonce
        let nonce = nonces.get(&from).copied().unwrap_or(0);
        nonces.insert(from, nonce + 1);

        // Create transfer calldata with random recipient
        let call = MockERC20::transferCall {
            to: Address::random(),
            amount: U256::from(1),
        };
        let calldata = alloy::sol_types::SolCall::abi_encode(&call);

        tx_data.push((signer, nonce, calldata));
    }

    // Sign transactions in parallel
    info!(transactions = tx_data.len(), "Signing transactions");

    let transactions: Vec<Vec<u8>> = tx_data
        .into_par_iter()
        .progress()
        .map(|(signer, nonce, calldata)| -> eyre::Result<Vec<u8>> {
            use alloy::consensus::{SignableTransaction, TxEip1559};

            let mut tx = TxEip1559 {
                chain_id,
                nonce,
                gas_limit: 100_000,
                max_fee_per_gas: gas_price + 1_000_000_000, // gas price + 1 gwei
                max_priority_fee_per_gas: 1_000_000_000,    // 1 gwei
                to: alloy::primitives::TxKind::Call(token_address),
                value: U256::ZERO,
                access_list: Default::default(),
                input: calldata.into(),
            };

            let sig = signer.sign_transaction_sync(&mut tx)?;
            let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));
            Ok(envelope.encoded_2718())
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    // Send transactions
    info!(
        transactions = transactions.len(),
        tps, "Sending transactions"
    );
    let rate_limiter = RateLimiter::direct(Quota::per_second(NonZeroU32::new(tps as u32).unwrap()));

    let deadline = tokio::time::sleep(Duration::from_secs(duration));
    tokio::pin!(deadline);

    let sent_count = Arc::new(AtomicUsize::new(0));
    let failed_count = Arc::new(AtomicUsize::new(0));

    stream::iter(transactions)
        .ratelimit_stream(&rate_limiter)
        .map(|bytes: Vec<u8>| {
            let provider = provider.clone();
            let sent = sent_count.clone();
            let failed = failed_count.clone();
            async move {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    provider.send_raw_transaction(&bytes),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        sent.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
        .buffer_unordered(max_concurrent_requests)
        .take_until(&mut deadline)
        .collect::<Vec<_>>()
        .await;

    let sent = sent_count.load(Ordering::Relaxed);
    let failed = failed_count.load(Ordering::Relaxed);
    info!(sent, failed, "Finished sending transactions");

    // Wait for transactions to be mined
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Get end block and generate report
    let end_block = provider.get_block_number().await?;
    info!(start_block, end_block, "Generating report");

    let mut blocks = Vec::new();
    let mut last_timestamp: Option<u64> = None;

    for number in start_block..=end_block {
        let block: Option<alloy::rpc::types::Block> = provider.get_block(number.into()).await?;
        if let Some(block) = block {
            let receipts: Vec<alloy::rpc::types::TransactionReceipt> = provider
                .get_block_receipts(number.into())
                .await?
                .unwrap_or_default();

            let timestamp = block.header.timestamp;
            let latency_ms = last_timestamp.map(|last| (timestamp - last) * 1000);

            // Count successful and failed transactions
            let tx_count = receipts.len();
            let ok_count = receipts.iter().filter(|r| r.status()).count();
            let err_count = tx_count - ok_count;

            blocks.push(RethBenchmarkedBlock {
                number,
                tx_count,
                ok_count,
                err_count,
                gas_used: block.header.gas_used,
                timestamp,
                latency_ms,
            });

            last_timestamp = Some(timestamp);
        }
    }

    let total_tx: usize = blocks.iter().map(|b| b.tx_count).sum();
    let total_ok: usize = blocks.iter().map(|b| b.ok_count).sum();
    let actual_tps = total_tx as f64 / duration as f64;

    info!(total_tx, total_ok, actual_tps, "Benchmark complete");

    Ok(RethBenchmarkReport {
        metadata: RethBenchmarkMetadata {
            target_tps: tps,
            run_duration_secs: duration,
            accounts,
            chain_id,
            start_block,
            end_block,
            mode: "reth".to_string(),
        },
        blocks,
        summary: RethBenchmarkSummary {
            total_tx,
            total_ok,
            actual_tps,
        },
    })
}

#[derive(Serialize)]
pub struct RethBenchmarkReport {
    pub metadata: RethBenchmarkMetadata,
    pub blocks: Vec<RethBenchmarkedBlock>,
    pub summary: RethBenchmarkSummary,
}

#[derive(Serialize)]
pub struct RethBenchmarkMetadata {
    pub target_tps: u64,
    pub run_duration_secs: u64,
    pub accounts: u64,
    pub chain_id: u64,
    pub start_block: u64,
    pub end_block: u64,
    pub mode: String,
}

#[derive(Serialize)]
pub struct RethBenchmarkedBlock {
    pub number: u64,
    pub tx_count: usize,
    pub ok_count: usize,
    pub err_count: usize,
    pub gas_used: u64,
    pub timestamp: u64,
    pub latency_ms: Option<u64>,
}

#[derive(Serialize)]
pub struct RethBenchmarkSummary {
    pub total_tx: usize,
    pub total_ok: usize,
    pub actual_tps: f64,
}
