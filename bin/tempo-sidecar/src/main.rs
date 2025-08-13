use alloy::{
    hex,
    primitives::B256,
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Block,
};
use alloy_rpc_types_engine::ForkchoiceState;
use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;
use std::{fs, path::PathBuf, time, time::Duration};
use alloy::eips::BlockId;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use tokio::time::sleep;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Producer node RPC URL")]
    producer_url: String,

    #[arg(long, help = "Follower node engine API URL")]
    follower_url: String,

    #[arg(
        long,
        default_value = "~/malachite/reth/jwt.hex",
        help = "Path to JWT secret file"
    )]
    jwt_secret_file: String,

    #[arg(long, default_value = "5", help = "Poll interval in seconds")]
    interval: u64,
}

struct BlockFollower {
    producer: RootProvider<alloy::network::Ethereum>,
    follower_url: String,
    jwt_token: String,
    client: Client,
    interval: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iat: u64
}

impl BlockFollower {
    async fn new(args: Args) -> Result<Self> {
        let jwt_secret_path = shellexpand::tilde(&args.jwt_secret_file);
        let jwt_secret_path = PathBuf::from(jwt_secret_path.as_ref());
        
        let jwt_secret = fs::read_to_string(&jwt_secret_path)
            .with_context(|| format!("Failed to read JWT secret from {jwt_secret_path:?}"))?;
        
        let jwt_secret = jwt_secret.trim();
        let jwt_secret_bytes = hex::decode(jwt_secret)
            .with_context(|| "Failed to decode JWT secret from hex")?;

        let claims = Claims {
            iat: time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH)?.as_secs(),
        };

        let jwt_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&jwt_secret_bytes),
        )?;

        let producer = ProviderBuilder::new()
            .connect_http(args.producer_url.parse()?);

        Ok(Self {
            producer: producer.root().clone(),
            follower_url: args.follower_url,
            jwt_token,
            client: reqwest::Client::new(),
            interval: Duration::from_secs(args.interval),
        })
    }

    async fn get_latest_block(&self) -> Result<Block> {
        let block = self
            .producer
            .get_block(BlockId::latest())
            .await?
            .ok_or_else(|| anyhow::anyhow!("Latest block not found"))?;

        Ok(block)
    }

    async fn send_forkchoice_updated(&self, block: &Block) -> Result<()> {
        let forkchoice_state = ForkchoiceState {
            head_block_hash: block.header.hash,
            safe_block_hash: block.header.hash,
            finalized_block_hash: block.header.parent_hash,
        };

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "engine_forkchoiceUpdatedV1",
            "params": [forkchoice_state, null],
            "id": 1
        });

        info!("Sending forkchoice update to {}: {}", self.follower_url, payload);
        let response = self
            .client
            .post(&self.follower_url)
            .header("Authorization", format!("Bearer {}", self.jwt_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Forkchoice update failed with status {} to URL {}: {}",
                status, self.follower_url, text
            ));
        }

        let result: Value = response.json().await
            .with_context(|| "Failed to parse forkchoice update response")?;

        if let Some(error) = result.get("error") {
            return Err(anyhow::anyhow!("Forkchoice update error: {}", error));
        }

        info!("Forkchoice update successful for block {}", block.header.hash);
        Ok(())
    }

    async fn run(&self) -> Result<()> {
        info!("Starting block follower loop");
        info!("Poll interval: {:?}", self.interval);

        let mut last_block_hash: Option<B256> = None;

        loop {
            match self.get_latest_block().await {
                Ok(block) => {
                    if Some(block.header.hash) != last_block_hash {
                        info!(
                            "New block {} (number: {})",
                            block.header.hash,
                            block.header.number
                        );

                        if let Err(e) = self.send_forkchoice_updated(&block).await {
                            error!("Failed to send forkchoice update: {}", e);
                        } else {
                            last_block_hash = Some(block.header.hash);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get latest block: {}", e);
                }
            }

            sleep(self.interval).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let follower = BlockFollower::new(args).await?;
    follower.run().await
}