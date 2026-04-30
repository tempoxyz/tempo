//! Burn stablecoins from your own balance.
//!
//! Run with: `cargo run --example burn_tokens`

use alloy::{
    primitives::{U256, address, keccak256},
    providers::ProviderBuilder,
};
use tempo_alloy::{TempoNetwork, contracts::precompiles::ITIP20};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    let token = ITIP20::new(
        address!("0x20c0000000000000000000000000000000000004"),
        &provider,
    );

    // Burn 100 tokens from your own balance
    token
        .burn(U256::from(100_000_000))
        .send()
        .await?
        .get_receipt()
        .await?;

    // Burn with a memo for tracking
    token
        .burnWithMemo(U256::from(100_000_000), keccak256("REDEMPTION_Q1_2024"))
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Tokens burned successfully");

    Ok(())
}
