use std::sync::Arc;
use std::time::SystemTime;
use alloy::primitives::TxHash;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::client::ClientBuilder;
use alloy::transports::{RpcError, TransportErrorKind};
use eyre::Context;
use parking_lot::Mutex;
use thiserror::Error;
use crate::crescendo::config;


#[derive(Error, Debug)]
enum TxTrackError {
    #[error("rpc failed to return a proper response")]
    RpcError(#[from] RpcError<TransportErrorKind>),
}

pub struct TxReport {
    successful_txs: u128,
    average_latency: f64,
}

pub struct TxTracker {
    tracked_txs: Mutex<Vec<(Vec<TxHash>, SystemTime)>>
}

pub static TX_TRACKER: std::sync::LazyLock<TxTracker> = std::sync::LazyLock::new(TxTracker::new);

impl TxTracker {
    pub fn new() -> Self{
        Self{
            tracked_txs: Mutex::new(Vec::new()),
        }
    }

    pub fn push_sent_txs(&self, tx_hashes: Vec<TxHash>, sent_at: SystemTime) {
        self.tracked_txs.lock().push((tx_hashes, sent_at));
    }

    pub async fn tally_sent_txs(&self) -> eyre::Result<TxReport> {
        let network_config = &config::get().network_worker;
        let target_url = &network_config.target_urls[0];

        let provider = ProviderBuilder::new().connect_http(
            target_url
                .parse()
                .wrap_err_with(|| format!("invalid RPC URL: {}", target_url))?,
        );

        // lock the transactions for the final report
        let tracked_txs = self.tracked_txs.lock();

        for (tx_hash_batch, sent_at) in tracked_txs.iter() {
            let mut tx_receipt_futures = tx_hash_batch.iter()
                .map(|tx_hash| {
                    let provider = provider.clone();
                    async move {
                        let receipt = provider.get_transaction_receipt(*tx_hash).await;
                    }
                });
        }

        todo!()
    }
}