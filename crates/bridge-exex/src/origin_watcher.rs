//! Watches origin chains for deposit events.

use alloy::{
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use eyre::Result;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::ChainConfig;

sol! {
    /// Deposit event from StablecoinEscrow
    event Deposited(
        bytes32 indexed depositId,
        address indexed token,
        address indexed depositor,
        uint64 amount,
        address tempoRecipient,
        uint64 nonce
    );
}

/// A detected deposit from an origin chain
#[derive(Debug, Clone)]
pub struct DetectedDeposit {
    pub deposit_id: B256,
    pub origin_chain_id: u64,
    pub origin_token: Address,
    pub depositor: Address,
    pub amount: u64,
    pub tempo_recipient: Address,
    pub nonce: u64,
    pub tx_hash: B256,
    pub log_index: u32,
    pub block_number: u64,
}

/// Watches an origin chain for deposits
pub struct OriginWatcher {
    chain_name: String,
    config: ChainConfig,
    deposit_tx: mpsc::Sender<DetectedDeposit>,
}

impl OriginWatcher {
    pub fn new(
        chain_name: String,
        config: ChainConfig,
        deposit_tx: mpsc::Sender<DetectedDeposit>,
    ) -> Self {
        Self {
            chain_name,
            config,
            deposit_tx,
        }
    }

    /// Start watching for deposits
    pub async fn run(self) -> Result<()> {
        info!(
            chain = %self.chain_name,
            chain_id = %self.config.chain_id,
            escrow = %self.config.escrow_address,
            "Starting origin chain watcher"
        );

        let provider = ProviderBuilder::new()
            .connect(self.config.rpc_url.as_str())
            .await?;

        let mut last_block: u64 = if self.config.start_block > 0 {
            self.config.start_block
        } else {
            provider.get_block_number().await?
        };

        let deposit_event_sig = Deposited::SIGNATURE_HASH;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.poll_interval_secs,
            ))
            .await;

            let current_block: u64 = provider.get_block_number().await?;

            // Wait for confirmations
            let safe_block = current_block.saturating_sub(self.config.confirmations);

            if safe_block <= last_block {
                continue;
            }

            debug!(
                chain = %self.chain_name,
                from = %last_block,
                to = %safe_block,
                "Scanning blocks for deposits"
            );

            let filter = Filter::new()
                .address(self.config.escrow_address)
                .event_signature(deposit_event_sig)
                .from_block(last_block + 1)
                .to_block(safe_block);

            match provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in logs {
                        if let Some(deposit) = self.parse_deposit_log(&log) {
                            info!(
                                chain = %self.chain_name,
                                deposit_id = %deposit.deposit_id,
                                amount = %deposit.amount,
                                recipient = %deposit.tempo_recipient,
                                "Detected deposit"
                            );

                            if let Err(e) = self.deposit_tx.send(deposit).await {
                                error!("Failed to send deposit: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(chain = %self.chain_name, error = %e, "Failed to get logs");
                    continue;
                }
            }

            last_block = safe_block;
        }
    }

    fn parse_deposit_log(&self, log: &alloy::rpc::types::Log) -> Option<DetectedDeposit> {
        let decoded = Deposited::decode_log(log.as_ref()).ok()?;

        Some(DetectedDeposit {
            deposit_id: decoded.depositId,
            origin_chain_id: self.config.chain_id,
            origin_token: decoded.token,
            depositor: decoded.depositor,
            amount: decoded.amount,
            tempo_recipient: decoded.tempoRecipient,
            nonce: decoded.nonce,
            tx_hash: log.transaction_hash?,
            log_index: log.log_index? as u32,
            block_number: log.block_number?,
        })
    }
}
