//! Watches Tempo chain for burn events.

use alloy::{
    consensus::TxReceipt,
    primitives::{Address, B256},
    sol_types::SolEvent,
};
use eyre::Result;
use reth_exex::ExExNotification;
use reth_primitives_traits::{AlloyBlockHeader as _, NodePrimitives};
use tokio::sync::mpsc;
use tracing::info;

use tempo_contracts::precompiles::IBridge;

/// A detected burn from Tempo
#[derive(Debug, Clone)]
pub struct DetectedBurn {
    pub burn_id: B256,
    pub origin_chain_id: u64,
    pub origin_token: Address,
    pub origin_recipient: Address,
    pub amount: u64,
    pub nonce: u64,
    pub tempo_block_number: u64,
}

/// Watches Tempo for burn events via ExEx notifications
pub struct TempoWatcher {
    burn_tx: mpsc::Sender<DetectedBurn>,
}

impl TempoWatcher {
    pub fn new(burn_tx: mpsc::Sender<DetectedBurn>) -> Self {
        Self { burn_tx }
    }

    /// Process an ExEx notification for burn events
    pub async fn process_notification<N: NodePrimitives>(
        &self,
        notification: &ExExNotification<N>,
    ) -> Result<()> {
        if let ExExNotification::ChainCommitted { new } = notification {
            let execution_outcome = new.execution_outcome();
            let receipts = execution_outcome.receipts();

            for (block_idx, block) in new.blocks_iter().enumerate() {
                let block_number = block.header().number();

                // Get receipts for this block
                if let Some(block_receipts) = receipts.get(block_idx) {
                    for receipt in block_receipts {
                        for log in receipt.logs() {
                            if let Some(burn) = self.parse_burn_log(log, block_number) {
                                info!(
                                    burn_id = %burn.burn_id,
                                    origin_chain = %burn.origin_chain_id,
                                    amount = %burn.amount,
                                    "Detected burn event"
                                );

                                self.burn_tx.send(burn).await?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_burn_log(
        &self,
        log: &alloy::primitives::Log,
        block_number: u64,
    ) -> Option<DetectedBurn> {
        // Check if this is a BurnInitiated event from the bridge precompile
        let burn_sig = IBridge::BurnInitiated::SIGNATURE_HASH;

        if log.topics().first() != Some(&burn_sig) {
            return None;
        }

        // Decode the event
        let decoded = IBridge::BurnInitiated::decode_log(log).ok()?;

        Some(DetectedBurn {
            burn_id: decoded.burnId,
            origin_chain_id: decoded.originChainId,
            origin_token: decoded.originToken,
            origin_recipient: decoded.originRecipient,
            amount: decoded.amount,
            nonce: decoded.nonce,
            tempo_block_number: block_number,
        })
    }
}
