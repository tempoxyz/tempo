//! Main ExEx implementation.

use alloy::{eips::BlockNumHash, primitives::Sealable};
use eyre::Result;
use futures::StreamExt;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::FullNodeComponents;
use reth_primitives_traits::AlloyBlockHeader;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::{
    config::BridgeConfig,
    origin_watcher::{DetectedDeposit, OriginWatcher},
    signer::BridgeSigner,
    tempo_watcher::{DetectedBurn, TempoWatcher},
};

/// Bridge ExEx
pub struct BridgeExEx<Node: FullNodeComponents> {
    ctx: ExExContext<Node>,
    config: BridgeConfig,
    signer: Option<BridgeSigner>,
}

impl<Node: FullNodeComponents> BridgeExEx<Node> {
    /// Create a new bridge ExEx
    pub fn new(ctx: ExExContext<Node>, config: BridgeConfig) -> Self {
        Self {
            ctx,
            config,
            signer: None,
        }
    }

    /// Set the signer
    pub fn with_signer(mut self, signer: BridgeSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Run the ExEx
    pub async fn run(mut self) -> Result<()> {
        info!("Starting Bridge ExEx");

        // Channels for detected events
        let (deposit_tx, mut deposit_rx) = mpsc::channel::<DetectedDeposit>(100);
        let (burn_tx, mut burn_rx) = mpsc::channel::<DetectedBurn>(100);

        // Spawn origin chain watchers
        for (chain_name, chain_config) in self.config.chains.clone() {
            let watcher = OriginWatcher::new(chain_name, chain_config, deposit_tx.clone());
            tokio::spawn(async move {
                if let Err(e) = watcher.run().await {
                    error!("Origin watcher error: {}", e);
                }
            });
        }

        // Create Tempo watcher
        let tempo_watcher = TempoWatcher::new(burn_tx);

        // Main event loop
        loop {
            tokio::select! {
                // Process ExEx notifications
                Some(notification) = self.ctx.notifications.next() => {
                    let notification = notification?;
                    if let Err(e) = tempo_watcher.process_notification(&notification).await {
                        error!("Failed to process notification: {}", e);
                    }

                    // Acknowledge the notification
                    if let Some(committed_chain) = notification.committed_chain() {
                        let tip = committed_chain.tip();
                        let tip_number = tip.header().number();
                        let tip_hash = tip.header().hash_slow();
                        self.ctx
                            .events
                            .send(ExExEvent::FinishedHeight(BlockNumHash::new(tip_number, tip_hash)))?;
                    }
                }

                // Process detected deposits
                Some(deposit) = deposit_rx.recv() => {
                    if let Err(e) = self.handle_deposit(deposit).await {
                        error!("Failed to handle deposit: {}", e);
                    }
                }

                // Process detected burns (for header relay)
                Some(burn) = burn_rx.recv() => {
                    if let Err(e) = self.handle_burn(burn).await {
                        error!("Failed to handle burn: {}", e);
                    }
                }
            }
        }
    }

    async fn handle_deposit(&self, deposit: DetectedDeposit) -> Result<()> {
        let Some(signer) = &self.signer else {
            info!("No signer configured, skipping deposit signing");
            return Ok(());
        };

        // Compute request ID
        let request_id = BridgeSigner::compute_deposit_id(
            deposit.origin_chain_id,
            deposit.origin_token,
            deposit.tx_hash,
            deposit.log_index,
            deposit.tempo_recipient,
            deposit.amount,
            deposit.block_number,
        );

        // Sign the request
        let signature = signer.sign_deposit(&request_id).await?;

        info!(
            request_id = %request_id,
            validator = %signer.address(),
            signature_len = %signature.len(),
            "Signed deposit, ready to submit to bridge precompile"
        );

        // TODO: Submit to bridge precompile via Tempo RPC
        // This would create a transaction calling submitDepositSignature

        Ok(())
    }

    async fn handle_burn(&self, burn: DetectedBurn) -> Result<()> {
        info!(
            burn_id = %burn.burn_id,
            origin_chain = %burn.origin_chain_id,
            "Detected burn, header relay needed"
        );

        // TODO: Relay Tempo header to origin chain light client
        // This would submit the header with validator signatures

        Ok(())
    }
}
