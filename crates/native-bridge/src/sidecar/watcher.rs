//! Chain watcher - subscribes to MessageSent events via websocket.

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use alloy_primitives::B256;
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::{
    config::ChainConfig,
    error::{BridgeError, Result},
    message::Message,
};

sol! {
    #[derive(Debug)]
    event MessageSent(
        address indexed sender,
        bytes32 indexed messageHash,
        uint64 indexed destinationChainId
    );
}

/// Watches a chain for MessageSent events.
pub struct ChainWatcher {
    chain_id: u64,
    chain_name: String,
    ws_url: Option<String>,
    rpc_url: String,
    bridge_address: Address,
    finality_blocks: u64,
}

impl ChainWatcher {
    pub async fn new(config: ChainConfig) -> Result<Self> {
        let bridge_address = config
            .bridge_address
            .parse::<Address>()
            .map_err(|e| BridgeError::Config(format!("invalid bridge address: {e}")))?;

        Ok(Self {
            chain_id: config.chain_id,
            chain_name: config.name,
            ws_url: config.ws_url,
            rpc_url: config.rpc_url,
            bridge_address,
            finality_blocks: config.finality_blocks,
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Run the watcher, sending messages to the channel.
    pub async fn run(self, tx: mpsc::Sender<Message>) -> Result<()> {
        if let Some(ws_url) = &self.ws_url {
            self.run_websocket(ws_url, tx).await
        } else {
            self.run_polling(tx).await
        }
    }

    /// Subscribe to events via websocket.
    async fn run_websocket(&self, ws_url: &str, tx: mpsc::Sender<Message>) -> Result<()> {
        tracing::info!(
            chain = %self.chain_name,
            chain_id = self.chain_id,
            "connecting to websocket"
        );

        let provider = ProviderBuilder::new()
            .connect(ws_url)
            .await
            .map_err(|e| BridgeError::Rpc(format!("ws connect failed: {e}")))?;

        let filter = Filter::new()
            .address(self.bridge_address)
            .event_signature(MessageSent::SIGNATURE_HASH);

        let sub = provider
            .subscribe_logs(&filter)
            .await
            .map_err(|e| BridgeError::Rpc(format!("subscribe failed: {e}")))?;

        let mut stream = sub.into_stream();

        tracing::info!(
            chain = %self.chain_name,
            bridge = %self.bridge_address,
            "subscribed to MessageSent events"
        );

        while let Some(log) = stream.next().await {
            match self.parse_log(&log) {
                Ok(msg) => {
                    if tx.send(msg).await.is_err() {
                        tracing::warn!("receiver dropped");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to parse log: {e}");
                }
            }
        }

        Ok(())
    }

    /// Fallback polling mode.
    async fn run_polling(&self, tx: mpsc::Sender<Message>) -> Result<()> {
        tracing::info!(
            chain = %self.chain_name,
            chain_id = self.chain_id,
            "starting polling mode (no websocket configured)"
        );

        let provider = ProviderBuilder::new().connect_http(
            self.rpc_url
                .parse()
                .map_err(|e| BridgeError::Config(format!("invalid rpc url: {e}")))?,
        );

        let mut last_block = provider
            .get_block_number()
            .await
            .map_err(|e| BridgeError::Rpc(e.to_string()))?;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(12)).await;

            let current_block = provider
                .get_block_number()
                .await
                .map_err(|e| BridgeError::Rpc(e.to_string()))?;

            let safe_block = current_block.saturating_sub(self.finality_blocks);

            if safe_block <= last_block {
                continue;
            }

            let filter = Filter::new()
                .address(self.bridge_address)
                .event_signature(MessageSent::SIGNATURE_HASH)
                .from_block(last_block + 1)
                .to_block(safe_block);

            let logs = provider
                .get_logs(&filter)
                .await
                .map_err(|e| BridgeError::Rpc(e.to_string()))?;

            for log in logs {
                match self.parse_log(&log) {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("failed to parse log: {e}");
                    }
                }
            }

            last_block = safe_block;
        }
    }

    fn parse_log(&self, log: &alloy::rpc::types::Log) -> Result<Message> {
        let topics = log.topics();

        if topics.len() < 4 {
            return Err(BridgeError::ChainWatcher("not enough topics".into()));
        }

        let sender = Address::from_slice(&topics[1].as_slice()[12..]);
        let message_hash = B256::from(topics[2]);
        let dest_chain_id = u64::from_be_bytes(
            topics[3].as_slice()[24..]
                .try_into()
                .map_err(|_| BridgeError::ChainWatcher("invalid dest chain id".into()))?,
        );

        Ok(Message::new(
            sender,
            message_hash,
            self.chain_id,
            dest_chain_id,
        ))
    }
}
