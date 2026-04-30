//! Get the balance of a token for an address.
//!
//! Run with: `cargo run --example get_balance`

use alloy::{primitives::address, providers::ProviderBuilder};
use tempo_alloy::{TempoNetwork, contracts::precompiles::ITIP20};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    let balance = ITIP20::new(
        address!("0x20c0000000000000000000000000000000000001"), // Alpha USD
        &provider,
    )
    .balanceOf(address!("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbb"))
    .call()
    .await?;

    println!("Balance: {balance:?}");

    Ok(())
}
