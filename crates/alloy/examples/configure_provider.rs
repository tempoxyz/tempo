//! Configure a Tempo provider to interact with the network.
//!
//! Run with: `cargo run --example configure_provider`

use alloy::providers::ProviderBuilder;
use tempo_alloy::TempoNetwork;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    println!("Provider connected successfully");
    println!("Chain ID: {provider:?}");

    Ok(())
}
