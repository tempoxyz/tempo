//! Get the current block number from the Tempo network.
//!
//! Run with: `cargo run --example get_block_number`

use alloy::providers::{Provider, ProviderBuilder};
use tempo_alloy::TempoNetwork;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    println!("{}", provider.get_block_number().await?);

    Ok(())
}
