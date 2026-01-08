//! Send a basic token transfer.
//!
//! Run with: `cargo run --example transfer`

use alloy::{
    primitives::{U256, address},
    providers::ProviderBuilder,
};
use tempo_alloy::{TempoNetwork, contracts::precompiles::ITIP20};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    let token = ITIP20::new(
        address!("0x20c0000000000000000000000000000000000001"), // AlphaUSD
        &provider,
    );

    let receipt = token
        .transfer(
            address!("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbb"),
            U256::from(100_000_000), // 100 tokens (6 decimals)
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Transfer successful: {:?}", receipt.transaction_hash);

    Ok(())
}
