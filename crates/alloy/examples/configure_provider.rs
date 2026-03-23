//! Configure a Tempo provider to interact with the network.
//!
//! Run with: `cargo run --example configure_provider`

use alloy::providers::{Provider, ProviderBuilder};
use tempo_alloy::TempoNetwork;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    println!("Provider connected successfully");
    let chain_id = provider.get_chain_id().await?;
    println!("Chain ID: {chain_id}");

    Ok(())
}
