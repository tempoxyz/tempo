use crate::crescendo::config;
use alloy::{
    primitives::{BlockNumber, TxHash},
    providers::{Provider, ProviderBuilder},
    signers::k256::pkcs8::der::asn1::UtcTime,
};
use eyre::{Context, eyre};
use futures::{StreamExt, stream};
use parking_lot::Mutex;
use reth::rpc::types::TransactionReceipt;
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

#[derive(Debug, Serialize)]
pub struct TxReport {
    sent_txs: usize,
    landed_txs: usize,
    successful_txs: usize,
    average_tx_latency: f64,
    average_gas_used: u64,
}

pub struct SentTransaction {
    sent_at: SystemTime,
    landed_at: Option<SystemTime>,
    successful: Option<bool>,
    gas_used: Option<u64>,
}

impl SentTransaction {
    pub fn new(sent_at: SystemTime) -> Self {
        Self {
            sent_at,
            landed_at: None,
            successful: None,
            gas_used: None,
        }
    }

    pub fn landed(self, landed_at: u64, success: bool, gas_used: u64) -> Self {
        Self {
            sent_at: self.sent_at,
            landed_at: Some(SystemTime::from(
                UtcTime::from_unix_duration(Duration::from_secs(landed_at)).unwrap(),
            )),
            successful: Some(success),
            gas_used: Some(gas_used),
        }
    }

    pub fn latency(&self) -> Option<f64> {
        Some(
            self.landed_at?
                .duration_since(self.sent_at)
                .ok()?
                .as_secs_f64(),
        )
    }
}

pub struct TxTracker {
    tracked_txs: Mutex<Vec<(Vec<TxHash>, SystemTime)>>,
}

pub static TX_TRACKER: std::sync::LazyLock<TxTracker> = std::sync::LazyLock::new(TxTracker::new);

impl TxTracker {
    pub fn new() -> Self {
        Self {
            tracked_txs: Mutex::new(Vec::new()),
        }
    }

    pub fn push_sent_txs(&self, tx_hashes: Vec<TxHash>, sent_at: SystemTime) {
        self.tracked_txs.lock().push((tx_hashes, sent_at));
    }

    pub async fn tally_sent_txs(&self, start_block_number: BlockNumber) -> eyre::Result<TxReport> {
        let network_config = &config::get().network_worker;
        let target_url = &network_config.target_urls[0];

        let provider = ProviderBuilder::new().connect_http(
            target_url
                .parse()
                .wrap_err_with(|| format!("invalid RPC URL: {}", target_url))?,
        );

        let end_block_number = provider.get_block_number().await?;

        // lock the transactions for the final report
        let mut sent_txs: HashMap<TxHash, SentTransaction> = self
            .tracked_txs
            .lock()
            .iter()
            .flat_map(|(hashes, timestamp)| {
                hashes
                    .iter()
                    .map(move |hash| (*hash, SentTransaction::new(*timestamp)))
            })
            .collect();

        let blocks = stream::iter(start_block_number..end_block_number)
            .map(|block_number| {
                let provider = provider.clone();
                async move { (block_number, provider.get_block(block_number.into()).await) }
            })
            .buffer_unordered(10)
            .collect::<Vec<_>>()
            .await;

        let block_timestamps: HashMap<BlockNumber, u64> = blocks
            .into_iter()
            .map(|(block_number, r)| {
                r?.ok_or_else(|| eyre!("failed to fetch block {}", block_number))
            })
            .collect::<eyre::Result<Vec<_>>>()?
            .into_iter()
            .map(|block| (block.header.number, block.header.timestamp))
            .collect();

        let receipts_by_block = stream::iter(start_block_number..end_block_number)
            .map(|block_number| {
                let provider = provider.clone();
                async move {
                    (
                        block_number,
                        provider.get_block_receipts(block_number.into()).await,
                    )
                }
            })
            .buffer_unordered(10)
            .collect::<Vec<_>>()
            .await;

        let transaction_receipts: HashMap<TxHash, TransactionReceipt> = receipts_by_block
            .into_iter()
            .map(|(block_number, result)| {
                result?.ok_or_else(|| {
                    eyre!(
                        "failed to fetch transaction receipts for block {}",
                        block_number
                    )
                })
            })
            .collect::<eyre::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|tx| (tx.transaction_hash, tx))
            .collect();

        sent_txs = sent_txs
            .into_iter()
            .map(|(tx_hash, mut sent_tx)| {
                if let Some(receipt) = transaction_receipts.get(&tx_hash) {
                    let block_time = block_timestamps
                        .get(
                            &receipt
                                .block_number
                                .expect("receipt should have block number"),
                        )
                        .expect("block should exist in cache");
                    sent_tx = sent_tx.landed(*block_time, receipt.status(), receipt.gas_used);
                }

                (tx_hash, sent_tx)
            })
            .collect();

        let tx_latencies = sent_txs
            .values()
            .filter_map(|tx| tx.latency())
            .collect::<Vec<_>>();
        let tx_gas_used = sent_txs
            .values()
            .filter_map(|tx| tx.gas_used)
            .collect::<Vec<_>>();

        Ok(TxReport {
            sent_txs: sent_txs.values().count(),
            landed_txs: sent_txs.values().filter_map(|tx| tx.landed_at).count(),
            successful_txs: sent_txs.values().filter_map(|tx| tx.successful).count(),
            average_tx_latency: tx_latencies.iter().sum::<f64>() / tx_latencies.len() as f64,
            average_gas_used: tx_gas_used.iter().sum::<u64>() / tx_gas_used.len() as u64,
        })
    }
}
