//! Mint stablecoins to a recipient address.
//!
//! Run with: `cargo run --example mint_tokens`

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

    let treasury_address = address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    // Mint 1,000 tokens to the treasury (USD has 6 decimals)
    token
        .mint(treasury_address, U256::from(1_000_000_000))
        .send()
        .await?
        .get_receipt()
        .await?;

    // Mint with a memo for tracking
    token
        .mintWithMemo(
            treasury_address,
            U256::from(1_000_000_000),
            keccak256("Q1_2024_TREASURY_ALLOCATION"),
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Tokens minted successfully");

    Ok(())
}
